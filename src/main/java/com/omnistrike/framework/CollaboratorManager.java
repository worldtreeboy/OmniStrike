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
    private volatile CollaboratorClient client;
    private volatile ScheduledExecutorService poller;
    private volatile boolean available = false;
    private volatile int payloadTtlMinutes = 60;

    // --- Custom OOB mode ---
    private volatile OobListener oobListener;
    private volatile String customAddress; // The IP address the target should call back to
    private volatile int customPort;       // HTTP port
    private volatile int customDnsPort;    // DNS port (UDP)
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Stale payload cleanup — shared by both modes
    private volatile ScheduledExecutorService cleanupExecutor;

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
        } catch (Exception ignored) {}
        java.util.function.BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try { logger.accept("OOB", message); } catch (Exception ignored) {}
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
            available = true;
            // Restart polling — it was shut down by switchToCustomOob()
            if (poller == null) {
                startPolling(5);
            }
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
            uiLog("HTTP listener started on " + address + ":" + httpPort);

            // Self-test: verify the listener is actually accepting connections
            try {
                java.net.Socket testSocket = new java.net.Socket();
                testSocket.connect(new java.net.InetSocketAddress(
                        "127.0.0.1".equals(address) ? "127.0.0.1" : address, httpPort), 2000);
                testSocket.close();
                uiLog("HTTP listener VERIFIED — accepting connections on " + address + ":" + httpPort);
            } catch (Exception testEx) {
                uiLog("WARNING: HTTP listener started but self-test FAILED: " + testEx.getMessage()
                        + " — the listener may not be reachable from outside");
            }

            try {
                oobListener.startDns();
                uiLog("DNS listener started on " + address + ":" + dnsPort + " (UDP)");
            } catch (Throwable dnsEx) {
                uiLog("DNS FAILED on port " + dnsPort + ": " + dnsEx.getClass().getSimpleName()
                        + ": " + dnsEx.getMessage() + " (HTTP still active)");
            }

            available = true;
            startCleanupTask();
            return true;
        } catch (Throwable e) {
            uiLog("FAILED to start HTTP on " + address + ":" + httpPort
                    + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            api.logging().logToError("[OOB] Stack trace: " + java.util.Arrays.toString(e.getStackTrace()));
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

    /**
     * Resolve a payload template by replacing {@code COLLAB_PLACEHOLDER} with the appropriate
     * OOB payload. In Custom OOB mode, DNS-based commands (nslookup, dig, host, ping,
     * Resolve-DnsName) are rewritten to target the Custom DNS listener directly, since
     * {@code generatePayload()} returns {@code ip:port/hexid} which is not a valid domain name.
     *
     * <p>For HTTP commands (curl, wget), the placeholder is replaced with the raw HTTP payload
     * as-is (e.g. {@code 192.168.1.8:56742/hexid}), which already works.</p>
     *
     * <p>In Burp Collaborator mode, this is a simple {@code template.replace()}.</p>
     *
     * @param template     The payload template containing {@code COLLAB_PLACEHOLDER}
     * @param httpPayload  The payload from {@code generatePayload()} (e.g. {@code "192.168.1.8:56742/abc123"} or {@code "xyz.oastify.com"})
     * @return The resolved template with DNS commands rewritten for Custom OOB
     */
    public String resolveTemplate(String template, String httpPayload) {
        if (template == null || httpPayload == null) {
            return template;
        }

        // Burp Collaborator mode: simple replacement — payload is already a valid domain
        if (mode != OobMode.CUSTOM_OOB) {
            return template.replace("COLLAB_PLACEHOLDER", httpPayload);
        }

        // Custom OOB mode: rewrite DNS commands to target our listener
        // httpPayload format: "address:port/hexid"
        // Extract hex ID (everything after the last '/')
        String hexId = httpPayload;
        int lastSlash = httpPayload.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < httpPayload.length() - 1) {
            hexId = httpPayload.substring(lastSlash + 1);
        }

        String addr = customAddress;
        int dnsPort = customDnsPort;
        // DNS target domain: hexid.address (the DNS listener extracts first label as payload ID)
        String dnsDomain = hexId + "." + addr;

        // Check if this template contains a DNS command
        String resolved = template;
        boolean hasDns = containsDnsCommand(template);

        if (hasDns) {
            // Rewrite DNS commands to target our listener
            resolved = rewriteDnsCommand(resolved, dnsDomain, addr, dnsPort);
        }

        // Replace any remaining COLLAB_PLACEHOLDER with the HTTP payload (for non-DNS parts)
        resolved = resolved.replace("COLLAB_PLACEHOLDER", httpPayload);

        return resolved;
    }

    /**
     * Check if a template contains a DNS-based command.
     */
    private boolean containsDnsCommand(String template) {
        String lower = template.toLowerCase();
        return lower.contains("nslookup") || lower.contains("dig ")
                || lower.contains("dig\t") || lower.contains("host ")
                || lower.contains("ping ") || lower.contains("ping\t")
                || lower.contains("resolve-dnsname");
    }

    /**
     * Rewrite DNS commands in a template to target the Custom OOB DNS listener.
     *
     * Transforms patterns like:
     * <ul>
     *   <li>{@code nslookup COLLAB_PLACEHOLDER} → {@code nslookup hexid.addr addr} (port 53)</li>
     *   <li>{@code nslookup COLLAB_PLACEHOLDER} → {@code dig @addr -p port hexid.addr} (non-53)</li>
     *   <li>{@code dig COLLAB_PLACEHOLDER} → {@code dig @addr -p port hexid.addr}</li>
     *   <li>{@code host COLLAB_PLACEHOLDER} → {@code dig @addr -p port hexid.addr}</li>
     *   <li>{@code ping -c1 COLLAB_PLACEHOLDER} → {@code ping -c1 hexid.addr}</li>
     *   <li>{@code Resolve-DnsName COLLAB_PLACEHOLDER} → {@code Resolve-DnsName hexid.addr -Server addr}</li>
     * </ul>
     */
    private String rewriteDnsCommand(String template, String dnsDomain, String addr, int dnsPort) {
        // We need to find and rewrite DNS command patterns containing COLLAB_PLACEHOLDER
        // Strategy: use regex to find DNS commands and rewrite them

        String result = template;

        // nslookup COLLAB_PLACEHOLDER → nslookup domain server (port 53) or dig @server -p port domain (non-53)
        if (containsIgnoreCase(result, "nslookup")) {
            if (dnsPort == 53) {
                // nslookup domain server — sends query to our listener on port 53
                result = result.replaceAll(
                        "(?i)nslookup\\s+COLLAB_PLACEHOLDER",
                        "nslookup " + dnsDomain + " " + addr);
            } else {
                // nslookup can't specify non-53 ports; use dig instead
                result = result.replaceAll(
                        "(?i)nslookup\\s+COLLAB_PLACEHOLDER",
                        "dig @" + addr + " -p " + dnsPort + " " + dnsDomain);
            }
        }

        // dig ... COLLAB_PLACEHOLDER → dig @addr -p port domain
        if (containsIgnoreCase(result, "dig")) {
            // Replace "dig COLLAB_PLACEHOLDER" or "dig +short COLLAB_PLACEHOLDER" etc.
            result = result.replaceAll(
                    "(?i)dig\\s+(?:\\+\\S+\\s+)?COLLAB_PLACEHOLDER",
                    "dig @" + addr + " -p " + dnsPort + " " + dnsDomain);
        }

        // host COLLAB_PLACEHOLDER → dig @addr -p port domain (host can't set port)
        if (containsIgnoreCase(result, "host")) {
            if (dnsPort == 53) {
                result = result.replaceAll(
                        "(?i)host\\s+COLLAB_PLACEHOLDER",
                        "host " + dnsDomain + " " + addr);
            } else {
                result = result.replaceAll(
                        "(?i)host\\s+COLLAB_PLACEHOLDER",
                        "dig @" + addr + " -p " + dnsPort + " " + dnsDomain);
            }
        }

        // ping -c1 COLLAB_PLACEHOLDER → ping -c1 domain (best-effort; uses system DNS)
        if (containsIgnoreCase(result, "ping")) {
            result = result.replaceAll(
                    "(?i)(ping\\s+(?:-[cnw]\\s*\\d+\\s+)*)COLLAB_PLACEHOLDER",
                    "$1" + dnsDomain);
        }

        // Resolve-DnsName COLLAB_PLACEHOLDER → Resolve-DnsName domain -Server addr
        if (containsIgnoreCase(result, "resolve-dnsname")) {
            result = result.replaceAll(
                    "(?i)Resolve-DnsName\\s+COLLAB_PLACEHOLDER",
                    "Resolve-DnsName " + dnsDomain + " -Server " + addr);
        }

        return result;
    }

    private boolean containsIgnoreCase(String haystack, String needle) {
        return haystack.toLowerCase().contains(needle.toLowerCase());
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
    private synchronized void startCleanupTask() {
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
