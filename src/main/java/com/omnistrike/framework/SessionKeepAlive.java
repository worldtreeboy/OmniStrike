package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Session Keep-Alive: periodically replays a saved login request so Burp's
 * built-in CookieJar stays fresh with valid session cookies.
 *
 * <p>Entirely optional — does nothing unless the user explicitly enables it
 * AND sets a login request via the right-click context menu.
 *
 * <p>No custom cookie jar, no localhost ports. Relies 100% on Burp's
 * {@code api.http().sendRequest()} which auto-stores Set-Cookie responses
 * in Burp's CookieJar.
 */
public class SessionKeepAlive {

    private final MontoyaApi api;

    // The saved login request to replay
    private volatile HttpRequestResponse loginRequest;

    // Configuration
    private volatile boolean enabled = false;
    private volatile int intervalMinutes = 5;

    // State
    private volatile boolean errorState = false;
    private volatile String lastRefreshTime = "";
    private volatile String statusMessage = "Session: Not configured";

    // Scheduler
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> scheduledTask;
    private final Object schedulerLock = new Object();

    // Retry interval on failure (seconds)
    private static final int RETRY_INTERVAL_SECONDS = 30;

    // UI callback
    private volatile BiConsumer<String, String> uiLogger;
    private volatile Consumer<String> statusCallback;

    public SessionKeepAlive(MontoyaApi api) {
        this.api = api;
    }

    /** Set a callback to log events to the UI Activity Log. Args: (module, message) */
    public void setUiLogger(BiConsumer<String, String> logger) {
        this.uiLogger = logger;
    }

    /** Set a callback to update the session status label in the UI */
    public void setStatusCallback(Consumer<String> callback) {
        this.statusCallback = callback;
    }

    // ==================== LOGIN REQUEST MANAGEMENT ====================

    /**
     * Saves the login request for replay. Called from the context menu
     * "Set as Session Login Request".
     */
    public void setLoginRequest(HttpRequestResponse reqResp) {
        this.loginRequest = reqResp;
        this.errorState = false;
        updateStatus();
        log("SessionKeepAlive", "Login request saved: " + reqResp.request().url());

        // If already enabled, start/restart the scheduler immediately
        if (enabled) {
            startScheduler();
        }
    }

    /**
     * Clears the saved login request and stops the scheduler.
     */
    public void clearLoginRequest() {
        this.loginRequest = null;
        this.errorState = false;
        this.lastRefreshTime = "";
        stopScheduler();
        updateStatus();
        log("SessionKeepAlive", "Login request cleared.");
    }

    /**
     * Returns true if a login request has been saved.
     */
    public boolean hasLoginRequest() {
        return loginRequest != null;
    }

    /**
     * Returns a display-friendly URL of the saved login request, or null.
     */
    public String getLoginRequestUrl() {
        HttpRequestResponse req = loginRequest;
        return req != null ? req.request().url() : null;
    }

    // ==================== ENABLE / DISABLE ====================

    /**
     * Enable or disable the keep-alive. When enabled AND a login request
     * is set, the scheduler starts immediately. When disabled, the scheduler
     * stops but the saved login request is preserved.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        if (enabled && loginRequest != null) {
            startScheduler();
            log("SessionKeepAlive", "Enabled — refreshing every " + intervalMinutes + " min");
        } else if (!enabled) {
            stopScheduler();
            log("SessionKeepAlive", "Disabled.");
        }
        updateStatus();
    }

    public boolean isEnabled() {
        return enabled;
    }

    // ==================== INTERVAL ====================

    public void setIntervalMinutes(int minutes) {
        this.intervalMinutes = Math.max(1, minutes);
        // Restart scheduler if currently running to pick up new interval
        if (enabled && loginRequest != null && scheduler != null) {
            startScheduler();
        }
    }

    public int getIntervalMinutes() {
        return intervalMinutes;
    }

    // ==================== STATUS ====================

    public String getStatusMessage() {
        return statusMessage;
    }

    public boolean isErrorState() {
        return errorState;
    }

    private void updateStatus() {
        if (loginRequest == null) {
            statusMessage = "Session: Not configured";
        } else if (errorState) {
            statusMessage = "Session: ERROR";
        } else if (!enabled) {
            statusMessage = "Session: Disabled";
        } else if (lastRefreshTime.isEmpty()) {
            statusMessage = "Session: Active (pending first refresh)";
        } else {
            statusMessage = "Session: Active (last: " + lastRefreshTime + ")";
        }

        Consumer<String> cb = statusCallback;
        if (cb != null) {
            cb.accept(statusMessage);
        }
    }

    // ==================== SCHEDULER ====================

    private void startScheduler() {
        synchronized (schedulerLock) {
            stopSchedulerInternal();

            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "OmniStrike-SessionKeepAlive");
                t.setDaemon(true);
                return t;
            });

            // Run immediately on start, then at the configured interval
            scheduledTask = scheduler.scheduleAtFixedRate(
                    this::replayLoginRequestSafe,
                    0, intervalMinutes, TimeUnit.MINUTES);
        }
    }

    private void stopScheduler() {
        synchronized (schedulerLock) {
            stopSchedulerInternal();
        }
    }

    private void stopSchedulerInternal() {
        if (scheduledTask != null) {
            scheduledTask.cancel(false);
            scheduledTask = null;
        }
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            scheduler = null;
        }
    }

    /**
     * Called on extension unload. Stops everything permanently.
     */
    public void shutdown() {
        synchronized (schedulerLock) {
            enabled = false;
            stopSchedulerInternal();
        }
    }

    // ==================== REPLAY LOGIC ====================

    /**
     * Wrapper that catches all exceptions so the ScheduledExecutorService
     * doesn't silently kill the recurring task on an uncaught error.
     */
    private void replayLoginRequestSafe() {
        try {
            replayLoginRequest();
        } catch (Exception e) {
            log("SessionKeepAlive", "Unexpected error during replay: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * Core replay logic:
     * 1. Send the saved login request via api.http().sendRequest()
     *    (Burp auto-stores Set-Cookie in its CookieJar)
     * 2. Check for success (2xx/3xx status AND at least one Set-Cookie header)
     * 3. On failure: log warning, set error state, schedule a retry in 30s
     * 4. On success: update last refresh time, clear error state
     */
    private void replayLoginRequest() {
        HttpRequestResponse savedReq = this.loginRequest;
        if (savedReq == null || !enabled) return;

        HttpResponse response;
        try {
            // sendRequest() automatically applies cookies from Burp's jar on the
            // outgoing request AND stores Set-Cookie from the response back into the jar
            HttpRequestResponse result = api.http().sendRequest(savedReq.request());
            response = result.response();
        } catch (Exception e) {
            handleFailure("Request failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return;
        }

        int status = response.statusCode();
        boolean statusOk = (status >= 200 && status < 400);
        boolean hasCookies = response.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("Set-Cookie"));

        if (!statusOk) {
            handleFailure("HTTP " + status + " — expected 2xx/3xx");
            return;
        }

        if (!hasCookies) {
            // Non-fatal: some login endpoints return 200 without Set-Cookie on subsequent
            // replays if the session is still valid. Log as info, not error.
            log("SessionKeepAlive", "Refresh OK (HTTP " + status
                    + ") but no Set-Cookie headers — session may already be valid");
        } else {
            log("SessionKeepAlive", "Refresh OK (HTTP " + status
                    + ") — cookies updated in Burp's jar");
        }

        // Success
        errorState = false;
        lastRefreshTime = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        updateStatus();
    }

    /**
     * Handles a refresh failure: logs warning, sets error state, and schedules
     * a one-shot retry in 30 seconds (if still enabled).
     */
    private void handleFailure(String reason) {
        log("SessionKeepAlive", "WARNING: Session refresh failed — " + reason
                + ". Retrying in " + RETRY_INTERVAL_SECONDS + "s.");
        errorState = true;
        updateStatus();

        // Schedule a one-shot retry
        synchronized (schedulerLock) {
            if (scheduler != null && !scheduler.isShutdown() && enabled) {
                scheduler.schedule(this::replayLoginRequestSafe,
                        RETRY_INTERVAL_SECONDS, TimeUnit.SECONDS);
            }
        }
    }

    // ==================== LOGGING ====================

    private void log(String module, String message) {
        try {
            api.logging().logToOutput("[" + module + "] " + message);
        } catch (NullPointerException ignored) {
            // Burp API proxy may be null during unload
        }
        BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try {
                logger.accept(module, message);
            } catch (NullPointerException ignored) {
                // UI may be torn down during unload
            }
        }
    }
}
