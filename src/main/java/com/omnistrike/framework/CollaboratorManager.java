package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Manages OOB (Out-of-Band) interaction detection for all scanner modules.
 * Supports two mutually exclusive modes:
 * <ul>
 *   <li><b>BURP_COLLABORATOR</b> — Uses Burp's built-in Collaborator (requires Professional + internet)</li>
 *   <li><b>CUSTOM_OOB</b> — Self-hosted HTTP listener inside the extension (works on intranets)</li>
 * </ul>
 * All modules use the same API: {@code generatePayload()} + {@code Consumer<Interaction>} callbacks.
 */
public class CollaboratorManager {

    public enum OobMode {
        BURP_COLLABORATOR,
        CUSTOM_OOB
    }

    private final MontoyaApi api;
    private volatile OobMode mode = OobMode.BURP_COLLABORATOR;

    // --- Burp Collaborator mode ---
    private CollaboratorClient client;
    private ScheduledExecutorService poller;
    private volatile boolean available = false;
    private volatile int payloadTtlMinutes = 60;

    // --- Custom OOB mode ---
    private OobListener oobListener;
    private volatile String customAddress; // The IP address the target should call back to
    private volatile int customPort;       // HTTP port
    private volatile int customDnsPort;    // DNS port (UDP)
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Stale payload cleanup — shared by both modes
    private ScheduledExecutorService cleanupExecutor;

    // UI Activity Log callback: (module, message)
    private volatile java.util.function.BiConsumer<String, String> uiLogger;

    // Map payload ID -> callback to invoke when interaction is received
    private final ConcurrentHashMap<String, PendingPayload> pendingPayloads = new ConcurrentHashMap<>();

    public static class PendingPayload {
        public final String moduleId;
        public final String url;
        public final String parameter;
        public final String payloadDescription;
        public final Consumer<Interaction> callback;
        public final long createdAt;

        public PendingPayload(String moduleId, String url, String parameter,
                              String payloadDescription, Consumer<Interaction> callback) {
            this.moduleId = moduleId;
            this.url = url;
            this.parameter = parameter;
            this.payloadDescription = payloadDescription;
            this.callback = callback;
            this.createdAt = System.currentTimeMillis();
        }
    }

    public CollaboratorManager(MontoyaApi api) {
        this.api = api;
    }

    /** Set a callback to log events to the UI Activity Log. Args: (module, message) */
    public void setUiLogger(java.util.function.BiConsumer<String, String> logger) {
        this.uiLogger = logger;
    }

    private void uiLog(String message) {
        try {
            api.logging().logToOutput("[OOB] " + message);
        } catch (NullPointerException ignored) {}
        java.util.function.BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try { logger.accept("OOB", message); } catch (NullPointerException ignored) {}
        }
    }

    // ==================== MODE MANAGEMENT ====================

    public OobMode getMode() {
        return mode;
    }

    /**
     * Switch to Burp Collaborator mode. Stops custom OOB listener if running.
     */
    public void switchToBurpCollaborator() {
        stopCustomOob();
        mode = OobMode.BURP_COLLABORATOR;
        // Re-initialize Collaborator client if not already done
        if (client == null) {
            initialize();
        } else {
            available = (client != null);
        }
    }

    /**
     * Switch to Custom OOB mode. Stops Burp Collaborator polling.
     * The listener is NOT started automatically — call {@link #initializeCustomOob} to start it.
     */
    public void switchToCustomOob() {
        // Stop Collaborator polling (but keep pendingPayloads — they're shared)
        stopCollaboratorPolling();
        mode = OobMode.CUSTOM_OOB;
        // Available is false until initializeCustomOob() starts the listener
        available = (oobListener != null && oobListener.isRunning());
    }

    // ==================== BURP COLLABORATOR MODE ====================

    /**
     * Initialize the Collaborator client. Must be called during extension init.
     * Returns false if Collaborator is not available (Community edition).
     */
    public boolean initialize() {
        try {
            // Shutdown existing poller to prevent thread leak on re-initialization
            if (poller != null) {
                poller.shutdownNow();
                poller = null;
            }
            // Always create a fresh Collaborator client each session.
            client = api.collaborator().createClient();
            api.logging().logToOutput("Created new Collaborator client.");
            available = true;

            // Start polling for interactions every 5 seconds
            startPolling(5);
            startCleanupTask();

            return true;
        } catch (Exception e) {
            api.logging().logToError("Collaborator not available (Community edition?): " + e.getMessage());
            available = false;
            return false;
        }
    }

    // ==================== CUSTOM OOB MODE ====================

    /**
     * Initialize and start the custom OOB HTTP + DNS listeners.
     *
     * @param address The IP address to bind to and that the target can reach
     * @param httpPort The port for the HTTP listener
     * @param dnsPort  The port for the DNS listener (UDP)
     * @return true if both listeners started successfully
     */
    public boolean initializeCustomOob(String address, int httpPort, int dnsPort) {
        stopCustomOob();
        this.customAddress = address;
        this.customPort = httpPort;
        this.customDnsPort = dnsPort;

        try {
            oobListener = new OobListener(address, httpPort, dnsPort);
            oobListener.setInteractionHandler(this::handleCustomOobInteraction);
            uiLog("Starting HTTP listener on " + address + ":" + httpPort + "...");
            oobListener.startHttp();
            uiLog("HTTP listener started successfully on " + address + ":" + httpPort);

            try {
                uiLog("Starting DNS listener on " + address + ":" + dnsPort + " (UDP)...");
                oobListener.startDns();
                uiLog("DNS listener started successfully on " + address + ":" + dnsPort + " (UDP)");
            } catch (Exception dnsEx) {
                // DNS failure is non-fatal — HTTP still works
                uiLog("DNS FAILED on port " + dnsPort + ": " + dnsEx.getClass().getSimpleName()
                        + ": " + dnsEx.getMessage() + " (HTTP still active)");
            }

            available = true;
            startCleanupTask();
            return true;
        } catch (Exception e) {
            uiLog("FAILED to start HTTP on " + address + ":" + httpPort
                    + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            available = false;
            return false;
        }
    }

    /** Legacy overload — starts HTTP only with default DNS port 53. */
    public boolean initializeCustomOob(String address, int port) {
        return initializeCustomOob(address, port, 53);
    }

    /**
     * Stop the custom OOB listener.
     */
    public void stopCustomOob() {
        if (oobListener != null) {
            oobListener.stop();
            oobListener = null;
            if (mode == OobMode.CUSTOM_OOB) {
                available = false;
            }
            uiLog("Listener stopped.");
        }
    }

    /**
     * Called by OobListener when an HTTP/DNS request arrives. Matches the payload ID
     * against pending payloads and fires the module callback synchronously.
     */
    private void handleCustomOobInteraction(String payloadId, CustomOobInteraction interaction) {
        PendingPayload matched = pendingPayloads.remove(payloadId);
        if (matched != null) {
            try {
                matched.callback.accept(interaction);
            } catch (Exception e) {
                uiLog("Callback error for payload " + payloadId + ": " + e.getMessage());
            }
            uiLog("Received " + interaction.type().name()
                    + " from " + interaction.clientIp().getHostAddress()
                    + " — matched payload " + payloadId + " (" + matched.moduleId + ")");
        } else {
            uiLog("Received " + interaction.type().name() + " from "
                    + interaction.clientIp().getHostAddress()
                    + " payloadId=" + payloadId + " (no matching payload)");
        }
    }

    public boolean isCustomOobRunning() {
        return oobListener != null && oobListener.isRunning();
    }

    public String getCustomAddress() {
        return customAddress;
    }

    public int getCustomPort() {
        return customPort;
    }

    public int getCustomDnsPort() {
        return customDnsPort;
    }

    public boolean isCustomDnsRunning() {
        return oobListener != null && oobListener.isDnsRunning();
    }

    // ==================== PAYLOAD GENERATION (both modes) ====================

    /**
     * Generate an OOB payload and register a callback for when it receives an interaction.
     *
     * In BURP_COLLABORATOR mode: returns {@code "abc123.oastify.com"}
     * In CUSTOM_OOB mode: returns {@code "192.168.1.10:47832/abc123"} (used as: {@code http://<payload>/path})
     *
     * @return The payload string, or null if unavailable
     */
    public String generatePayload(String moduleId, String url, String parameter,
                                   String payloadDescription, Consumer<Interaction> callback) {
        if (!available) return null;

        if (mode == OobMode.CUSTOM_OOB) {
            return generateCustomPayload(moduleId, url, parameter, payloadDescription, callback);
        }

        // Burp Collaborator mode
        if (client == null) return null;
        try {
            CollaboratorPayload payload = client.generatePayload();
            String payloadStr = payload.toString();
            String payloadId = payload.id().toString();

            pendingPayloads.put(payloadId, new PendingPayload(
                    moduleId, url, parameter, payloadDescription, callback));

            return payloadStr;
        } catch (Exception e) {
            api.logging().logToError("Failed to generate Collaborator payload: " + e.getMessage());
            return null;
        }
    }

    /**
     * Generate a payload without server location (just the subdomain/ID part).
     *
     * In CUSTOM_OOB mode: returns just the hex ID (DNS won't work, but HTTP payloads using
     * this ID with a manually constructed URL will still match).
     */
    public String generatePayloadShort(String moduleId, String url, String parameter,
                                        String payloadDescription, Consumer<Interaction> callback) {
        if (!available) return null;

        if (mode == OobMode.CUSTOM_OOB) {
            String payloadId = generateHexId();
            pendingPayloads.put(payloadId, new PendingPayload(
                    moduleId, url, parameter, payloadDescription, callback));
            return payloadId;
        }

        // Burp Collaborator mode
        if (client == null) return null;
        try {
            CollaboratorPayload payload = client.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION);
            String payloadStr = payload.toString();
            String payloadId = payload.id().toString();

            pendingPayloads.put(payloadId, new PendingPayload(
                    moduleId, url, parameter, payloadDescription, callback));

            return payloadStr;
        } catch (Exception e) {
            api.logging().logToError("Failed to generate short Collaborator payload: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the OOB server address.
     * BURP_COLLABORATOR: {@code "oastify.com"}
     * CUSTOM_OOB: {@code "192.168.1.10:47832"}
     */
    public String getServerAddress() {
        if (mode == OobMode.CUSTOM_OOB) {
            if (customAddress != null && customPort > 0) {
                return customAddress + ":" + customPort;
            }
            return null;
        }
        // Burp Collaborator mode
        if (!available || client == null) return null;
        try {
            return client.server().address();
        } catch (Exception e) {
            return null;
        }
    }

    public boolean isAvailable() {
        return available;
    }

    // ==================== INTERNAL HELPERS ====================

    private String generateCustomPayload(String moduleId, String url, String parameter,
                                          String payloadDescription, Consumer<Interaction> callback) {
        String payloadId = generateHexId();
        pendingPayloads.put(payloadId, new PendingPayload(
                moduleId, url, parameter, payloadDescription, callback));
        // Return address:port/id — modules prepend "http://" and append "/path"
        return customAddress + ":" + customPort + "/" + payloadId;
    }

    /**
     * Generates a 24-character hex string using SecureRandom.
     */
    private String generateHexId() {
        byte[] bytes = new byte[12]; // 12 bytes = 24 hex chars
        SECURE_RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(24);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void stopCollaboratorPolling() {
        if (poller != null) {
            poller.shutdown();
            try {
                poller.awaitTermination(3, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                poller.shutdownNow();
                Thread.currentThread().interrupt();
            }
            poller = null;
        }
    }

    private void startPolling(int intervalSeconds) {
        poller = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "OmniStrike-CollabPoller");
            t.setDaemon(true);
            return t;
        });

        poller.scheduleAtFixedRate(() -> {
            try {
                if (client == null) return;

                List<Interaction> interactions = client.getAllInteractions();
                for (Interaction interaction : interactions) {
                    String interactionId = interaction.id().toString();
                    PendingPayload matched = pendingPayloads.get(interactionId);
                    String matchedKey = matched != null ? interactionId : null;

                    if (matched != null) {
                        pendingPayloads.remove(matchedKey);
                        try {
                            matched.callback.accept(interaction);
                        } catch (Exception e) {
                            api.logging().logToError("Collaborator callback error: " + e.getMessage());
                        }
                    } else {
                        api.logging().logToOutput("Collaborator interaction received (no matching payload): "
                                + interaction.type() + " from " + interaction.clientIp());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Collaborator polling error: " + e.getMessage());
            }
        }, 0, intervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Starts the cleanup task for stale pending payloads. Shared by both modes.
     */
    private void startCleanupTask() {
        if (cleanupExecutor != null) return; // Already running
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "OmniStrike-PayloadCleanup");
            t.setDaemon(true);
            return t;
        });
        cleanupExecutor.scheduleAtFixedRate(() -> {
            try {
                long cutoff = System.currentTimeMillis() - (payloadTtlMinutes * 60L * 1000L);
                int before = pendingPayloads.size();
                pendingPayloads.entrySet().removeIf(e -> e.getValue().createdAt < cutoff);
                int removed = before - pendingPayloads.size();
                if (removed > 0) {
                    api.logging().logToOutput("OOB cleanup: removed " + removed
                            + " stale payload(s), " + pendingPayloads.size() + " remaining");
                }
            } catch (Exception e) {
                api.logging().logToError("OOB cleanup error: " + e.getMessage());
            }
        }, 60, 60, TimeUnit.SECONDS);
    }

    // ==================== LIFECYCLE ====================

    public void shutdown() {
        stopCollaboratorPolling();
        stopCustomOob();
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
            try {
                cleanupExecutor.awaitTermination(3, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            cleanupExecutor = null;
        }
        pendingPayloads.clear();
    }

    public int getPendingCount() {
        return pendingPayloads.size();
    }

    public void setPayloadTtlMinutes(int minutes) {
        this.payloadTtlMinutes = Math.max(1, minutes);
    }

    public int getPayloadTtlMinutes() {
        return payloadTtlMinutes;
    }
}
