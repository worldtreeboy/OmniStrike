package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Session Keep-Alive: periodically replays a saved login request and captures
 * Set-Cookie headers. Fresh cookies are injected into ALL outgoing requests
 * (Proxy, Repeater, Scanner, Intruder, Extensions) via the HttpHandler hook
 * in TrafficInterceptor.
 *
 * <p>Handles 302/301/303 redirects — follows up to 5 redirects, collecting
 * Set-Cookie headers from every response in the chain.
 *
 * <p>Entirely optional — does nothing unless the user explicitly enables it
 * AND sets a login request via the right-click context menu.
 */
public class SessionKeepAlive {

    private final MontoyaApi api;

    // The saved login request to replay
    private volatile HttpRequestResponse loginRequest;

    // Configuration
    private volatile boolean enabled = false;
    private volatile int intervalMinutes = 5;

    // Fresh cookies collected from the login replay — injected into outgoing requests for the SAME DOMAIN
    private final ConcurrentHashMap<String, String> freshCookies = new ConcurrentHashMap<>();

    // The domain of the login request — cookies are ONLY injected into requests to this domain
    private volatile String loginDomain = "";

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

    // Max redirects to follow during login replay
    private static final int MAX_REDIRECTS = 5;

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

    // ==================== COOKIE ACCESS (for TrafficInterceptor) ====================

    /**
     * Returns the fresh cookies if the given host matches the login request's domain.
     * Cookies are ONLY injected into requests for the same domain — never cross-domain.
     *
     * @param requestHost the host of the outgoing request (e.g., "example.com")
     * @return unmodifiable map of cookie name -> value, or empty map if domain doesn't match
     */
    public Map<String, String> getFreshCookiesForHost(String requestHost) {
        if (!enabled || freshCookies.isEmpty() || loginDomain.isEmpty()) return Collections.emptyMap();
        if (requestHost == null) return Collections.emptyMap();

        // Domain match: exact match or subdomain match (request is sub.example.com, login is example.com)
        String host = requestHost.toLowerCase();
        if (!host.equals(loginDomain) && !host.endsWith("." + loginDomain)) {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(new HashMap<>(freshCookies));
    }

    /**
     * Returns true if session keep-alive is enabled and has fresh cookies for the given host.
     */
    public boolean hasFreshCookiesForHost(String requestHost) {
        return !getFreshCookiesForHost(requestHost).isEmpty();
    }

    /**
     * Returns the domain of the saved login request.
     */
    public String getLoginDomain() {
        return loginDomain;
    }

    // ==================== LOGIN REQUEST MANAGEMENT ====================

    /**
     * Saves the login request for replay. Called from the context menu
     * "Set as Session Login Request".
     */
    public void setLoginRequest(HttpRequestResponse reqResp) {
        this.loginRequest = reqResp;
        this.errorState = false;
        try {
            this.loginDomain = reqResp.request().httpService().host().toLowerCase();
        } catch (Exception e) {
            this.loginDomain = "";
        }
        updateStatus();
        log("SessionKeepAlive", "Login request saved: " + reqResp.request().url()
                + " (domain: " + loginDomain + ")");

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
        this.loginDomain = "";
        freshCookies.clear();
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
     * stops but the saved login request and cookies are preserved.
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
            statusMessage = "Session: Active (last: " + lastRefreshTime
                    + ", " + freshCookies.size() + " cookies)";
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
     * 1. Send the saved login request
     * 2. Collect Set-Cookie headers from the response
     * 3. Follow 301/302/303 redirects (up to MAX_REDIRECTS), collecting cookies from each hop
     * 4. Store all collected cookies in freshCookies map
     * 5. On failure: log warning, set error state, schedule a retry in 30s
     * 6. On success: update last refresh time, clear error state
     */
    private void replayLoginRequest() {
        HttpRequestResponse savedReq = this.loginRequest;
        if (savedReq == null || !enabled) return;

        Map<String, String> collectedCookies = new LinkedHashMap<>();
        HttpRequest currentRequest = savedReq.request();
        int redirectCount = 0;

        while (redirectCount <= MAX_REDIRECTS) {
            HttpResponse response;
            try {
                HttpRequestResponse result = api.http().sendRequest(currentRequest);
                response = result.response();
            } catch (Exception e) {
                handleFailure("Request failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                return;
            }

            // Collect Set-Cookie headers from this response
            collectSetCookies(response, collectedCookies);

            int status = response.statusCode();

            // Follow redirects (301, 302, 303, 307, 308)
            if (status >= 301 && status <= 308 && status != 304 && status != 305 && status != 306) {
                String location = null;
                for (var h : response.headers()) {
                    if ("Location".equalsIgnoreCase(h.name())) {
                        location = h.value();
                        break;
                    }
                }

                if (location == null || location.isEmpty()) {
                    // Redirect without Location header — treat as success (cookies already collected)
                    break;
                }

                // Build redirect URL (handle relative and absolute)
                String redirectUrl = resolveRedirectUrl(currentRequest, location);

                log("SessionKeepAlive", "Following redirect (" + status + ") → " + truncate(redirectUrl, 80));

                // Build GET request to the redirect URL, carrying cookies from the chain
                try {
                    HttpRequest redirectRequest = HttpRequest.httpRequestFromUrl(redirectUrl);
                    // Copy auth headers from original
                    for (var h : savedReq.request().headers()) {
                        String name = h.name().toLowerCase();
                        if (name.equals("cookie") || name.equals("authorization")) {
                            redirectRequest = redirectRequest.withRemovedHeader(h.name())
                                    .withAddedHeader(h.name(), h.value());
                        }
                    }
                    // Inject collected cookies so far into the redirect request
                    if (!collectedCookies.isEmpty()) {
                        redirectRequest = injectCookiesIntoRequest(redirectRequest, collectedCookies);
                    }
                    currentRequest = redirectRequest;
                } catch (Exception e) {
                    log("SessionKeepAlive", "Failed to follow redirect: " + e.getMessage());
                    break;
                }

                redirectCount++;
                continue;
            }

            // Not a redirect — check final status
            if (status >= 200 && status < 400) {
                // Success
                break;
            } else {
                handleFailure("HTTP " + status + " — expected 2xx/3xx");
                return;
            }
        }

        if (redirectCount > MAX_REDIRECTS) {
            handleFailure("Too many redirects (>" + MAX_REDIRECTS + ")");
            return;
        }

        // Store collected cookies for injection into all outgoing requests
        if (!collectedCookies.isEmpty()) {
            freshCookies.putAll(collectedCookies);
            log("SessionKeepAlive", "Refresh OK — " + collectedCookies.size()
                    + " cookie(s) captured: " + String.join(", ", collectedCookies.keySet()));
        } else {
            log("SessionKeepAlive", "Refresh OK but no Set-Cookie headers — session may already be valid");
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

    // ==================== COOKIE HELPERS ====================

    /**
     * Extracts all Set-Cookie headers from a response and adds them to the map.
     * Later cookies with the same name overwrite earlier ones (newest wins).
     */
    private void collectSetCookies(HttpResponse response, Map<String, String> cookies) {
        for (var header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String val = header.value();
                String[] parts = val.split(";");
                if (parts.length > 0) {
                    int eq = parts[0].indexOf('=');
                    if (eq > 0) {
                        String name = parts[0].substring(0, eq).trim();
                        String value = parts[0].substring(eq + 1).trim();
                        if (!name.isEmpty()) {
                            cookies.put(name, value);
                        }
                    }
                }
            }
        }
    }

    /**
     * Injects cookies into a request's Cookie header.
     * Merges with existing cookies (new values overwrite old for same-name cookies).
     */
    private HttpRequest injectCookiesIntoRequest(HttpRequest request, Map<String, String> cookies) {
        Map<String, String> merged = new LinkedHashMap<>();

        // Parse existing Cookie header
        String existing = request.headerValue("Cookie");
        if (existing != null && !existing.isEmpty()) {
            for (String pair : existing.split(";")) {
                String trimmed = pair.trim();
                int eq = trimmed.indexOf('=');
                if (eq > 0) {
                    merged.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
                }
            }
        }

        // Overlay fresh cookies (new wins)
        merged.putAll(cookies);

        // Build Cookie header
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : merged.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }

        return request.withRemovedHeader("Cookie")
                .withAddedHeader("Cookie", sb.toString());
    }

    /**
     * Resolves a redirect Location header to an absolute URL.
     * Handles: absolute URLs, protocol-relative, and path-relative.
     */
    private String resolveRedirectUrl(HttpRequest originalRequest, String location) {
        if (location.startsWith("http://") || location.startsWith("https://")) {
            return location; // Already absolute
        }

        String baseUrl;
        try {
            String url = originalRequest.url();
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return location;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            baseUrl = pathStart >= 0 ? url.substring(0, pathStart) : url;
        } catch (Exception e) {
            return location;
        }

        if (location.startsWith("//")) {
            // Protocol-relative
            String scheme = baseUrl.substring(0, baseUrl.indexOf("://"));
            return scheme + ":" + location;
        }

        if (location.startsWith("/")) {
            // Path-relative to host
            return baseUrl + location;
        }

        // Relative to current path — append to base
        return baseUrl + "/" + location;
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "..." : s;
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
