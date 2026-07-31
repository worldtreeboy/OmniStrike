package com.omnistrike.framework;
import com.omnistrike.framework.stepper.StepperHttp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Session Keep-Alive: periodically replays a saved login request and captures
 * Set-Cookie headers. Matching cookies can be injected into outgoing requests
 * (Proxy, Repeater, Scanner, Intruder, Extensions) via the HttpHandler hook in
 * TrafficInterceptor; Domain/host-only, Path, and Secure scope is enforced.
 *
 * <p>Handles 301/302/303/307/308 redirects — follows up to 5 redirects, collecting
 * Set-Cookie headers from same-origin hops in the chain. Redirects to a
 * different origin (scheme/host/port) are followed without credentials.
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

    /** RFC 6265 identity for a cookie. */
    private record CookieKey(String name, String domain, String path) {}

    /** A cookie captured from a same-origin login response. */
    private record SessionCookie(String name, String value, String domain,
                                 boolean hostOnly, String path, boolean secure,
                                 long creationOrder, boolean delete) {}

    // Key by name + effective domain + path so same-named cookies with different
    // scopes do not overwrite one another.
    private final ConcurrentHashMap<CookieKey, SessionCookie> freshCookies = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong cookieCreationSequence =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong loginGeneration =
            new java.util.concurrent.atomic.AtomicLong();

    // Host of the login request, used for status and replay-level safety checks.
    private volatile String loginDomain = "";

    // Whether the login request used HTTPS — cookies captured over HTTPS are
    // never injected into plaintext HTTP requests to the same domain.
    private volatile boolean loginSecure = false;

    // State
    private volatile boolean errorState = false;
    private volatile String lastRefreshTime = "";
    private volatile String statusMessage = "Session: Not configured";

    // Scheduler
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> scheduledTask;
    private final Object schedulerLock = new Object();

    // Set on the scheduler thread while a login replay is in flight, so the
    // replay's own sends (which go through StepperHttp) don't get fresh cookies
    // injected back into them — the replay must stay faithful to the captured
    // request, and its redirect cookies are handled explicitly below.
    private final ThreadLocal<Boolean> replaying = ThreadLocal.withInitial(() -> Boolean.FALSE);

    // Retry interval on failure (seconds)
    private static final int RETRY_INTERVAL_SECONDS = 30;

    // Max redirects to follow during login replay
    private static final int MAX_REDIRECTS = 5;

    // UI callback
    private volatile BiConsumer<String, String> uiLogger;
    private volatile Consumer<String> statusCallback;

    // Only the non-sensitive refresh interval is persisted. Login requests are
    // deliberately memory-only because they can contain passwords, bearer
    // tokens, cookies, and CSRF secrets.
    private volatile PersistenceManager persistence;
    private static final String K_HOST = "session.loginHost";
    private static final String K_PORT = "session.loginPort";
    private static final String K_SECURE = "session.loginSecure";
    private static final String K_REQ = "session.loginReqB64";
    private static final String K_INTERVAL = "session.intervalMin";

    public SessionKeepAlive(MontoyaApi api) {
        this.api = api;
    }

    public void setPersistence(PersistenceManager persistence) {
        this.persistence = persistence;
    }

    /**
     * Restores the non-sensitive refresh interval and erases any raw login
     * request left by older OmniStrike versions. Login requests are deliberately
     * memory-only and must be selected again after a restart.
     */
    public void loadPersistedState() {
        PersistenceManager pm = persistence;
        if (pm == null) return;
        try {
            int interval = pm.getInt(K_INTERVAL, 0);
            if (interval > 0) this.intervalMinutes = Math.max(1, interval);

            String reqB64 = pm.getString(K_REQ, null);
            if (reqB64 != null && !reqB64.isBlank()) {
                log("SessionKeepAlive", "Removed a legacy plaintext saved login request. "
                        + "Login requests are now memory-only and must be selected again.");
            }
            clearPersistedLoginRequest(pm);
        } catch (Exception e) {
            log("SessionKeepAlive", "Could not restore session settings: " + e.getMessage());
        }
    }

    /** Writes only non-sensitive configuration and erases legacy credential fields. */
    private void persist() {
        PersistenceManager pm = persistence;
        if (pm == null) return;
        try {
            pm.setInt(K_INTERVAL, intervalMinutes);
            clearPersistedLoginRequest(pm);
        } catch (Exception e) {
            log("SessionKeepAlive", "Could not persist session settings: " + e.getMessage());
        }
    }

    /** Overwrite credential-bearing fields written by older releases. */
    private static void clearPersistedLoginRequest(PersistenceManager pm) {
        pm.setString(K_REQ, "");
        pm.setString(K_HOST, "");
        pm.setInt(K_PORT, 0);
        pm.setBoolean(K_SECURE, false);
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

    /** Backwards-compatible root-path lookup used by status/UI callers. */
    public Map<String, String> getFreshCookiesForHost(String requestHost, boolean requestSecure) {
        return getFreshCookiesForRequest(requestHost, "/", requestSecure);
    }

    /**
     * Returns cookies whose Domain/host-only, Path, and Secure scope matches the
     * outgoing request. When multiple matching paths use the same name, the
     * longest-path cookie wins in this map view; actual request injection keeps
     * all matching scoped cookies in browser order.
     */
    public Map<String, String> getFreshCookiesForRequest(
            String requestHost, String requestPath, boolean requestSecure) {
        List<SessionCookie> matches = matchingCookies(requestHost, requestPath, requestSecure,
                freshCookies.values());
        if (matches.isEmpty()) return Collections.emptyMap();
        Map<String, String> result = new LinkedHashMap<>();
        for (SessionCookie cookie : matches) {
            result.putIfAbsent(cookie.name(), cookie.value());
        }
        return Collections.unmodifiableMap(result);
    }

    /**
     * Returns true if session keep-alive is enabled and has fresh cookies for the given host.
     */
    public boolean hasFreshCookiesForHost(String requestHost, boolean requestSecure) {
        return !getFreshCookiesForHost(requestHost, requestSecure).isEmpty();
    }

    /**
     * Overlays the latest session cookies onto an outgoing request, returning the
     * (possibly) modified request. Fresh cookies replace same-named cookies already
     * present and are added if missing; all other cookies are preserved.
     *
     * <p>Returns the request unchanged when keep-alive is disabled, no fresh cookies
     * exist, the request's host doesn't match the login domain, or the call comes
     * from our own login replay.
     *
     * <p>This is the counterpart to the injection in {@code TrafficInterceptor}'s
     * HttpHandler. The HttpHandler covers requests from Burp's built-in tools
     * (Proxy, Repeater, Intruder, Scanner); this method is invoked from
     * {@code StepperHttp} so requests sent by OmniStrike's own modules — which use
     * {@code api.http().sendRequest()} and therefore bypass the HttpHandler — also
     * carry the freshest cookies. Together they cover all traffic leaving Burp.
     */
    public HttpRequest applyFreshCookies(HttpRequest request) {
        if (request == null || replaying.get()) return request;
        try {
            HttpService service = request.httpService();
            List<SessionCookie> fresh = matchingCookies(service.host(),
                    request.pathWithoutQuery(), service.secure(), freshCookies.values());
            if (fresh.isEmpty()) return request;
            return injectCookiesIntoRequest(request, fresh);
        } catch (Exception e) {
            // Never break a module's send because cookie injection threw.
            log("SessionKeepAlive", "Cookie injection skipped: " + e.getMessage());
            return request;
        }
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
        // Never carry session material from a previously-selected target into
        // the new login domain while its first refresh is still pending.
        loginGeneration.incrementAndGet();
        freshCookies.clear();
        this.loginRequest = reqResp;
        this.errorState = false;
        try {
            HttpService svc = reqResp.request().httpService();
            this.loginDomain = svc.host().toLowerCase();
            this.loginSecure = svc.secure();
        } catch (Exception e) {
            this.loginDomain = "";
            this.loginSecure = false;
        }
        updateStatus();
        persist();
        log("SessionKeepAlive", "Login request saved: " + reqResp.request().url()
                + " (domain: " + loginDomain + ", memory-only)");

        // If already enabled, start/restart the scheduler immediately
        if (enabled) {
            startScheduler();
        }
    }

    /**
     * Clears the saved login request and stops the scheduler.
     */
    public void clearLoginRequest() {
        loginGeneration.incrementAndGet();
        this.loginRequest = null;
        this.errorState = false;
        this.lastRefreshTime = "";
        this.loginDomain = "";
        this.loginSecure = false;
        freshCookies.clear();
        stopScheduler();
        updateStatus();
        persist();
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
        persist();
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
        replaying.set(Boolean.TRUE);
        try {
            replayLoginRequest();
        } catch (Exception e) {
            log("SessionKeepAlive", "Unexpected error during replay: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            replaying.set(Boolean.FALSE);
        }
    }

    /**
     * Core replay logic:
     * 1. Send the saved login request
     * 2. Collect Set-Cookie headers from the response
     * 3. Follow 301/302/303/307/308 redirects (up to MAX_REDIRECTS), collecting cookies from
     *    each hop that stays on the login origin; origin-changed hops are followed
     *    without credentials and their Set-Cookie headers are ignored
     * 4. Store all collected cookies in freshCookies map
     * 5. On failure: log warning, set error state, schedule a retry in 30s
     * 6. On success: update last refresh time, clear error state
     */
    private void replayLoginRequest() {
        HttpRequestResponse savedReq = this.loginRequest;
        long replayGeneration = loginGeneration.get();
        if (savedReq == null || !enabled) return;

        Map<CookieKey, SessionCookie> collectedCookies = new LinkedHashMap<>();
        HttpRequest currentRequest = savedReq.request();
        int redirectCount = 0;

        // ORIGIN = scheme + host + effective port of the saved login request.
        HttpService loginService = savedReq.request().httpService();
        String loginOrigin = origin(loginService.secure() ? "https" : "http",
                loginService.host(), loginService.port());

        while (redirectCount <= MAX_REDIRECTS) {
            HttpResponse response;
            try {
                HttpRequestResponse result = StepperHttp.sendRequest(currentRequest);
                response = result.response();
            } catch (Exception e) {
                handleFailure("Request failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                return;
            }

            // Collect Set-Cookie headers from this response — only from hops on the
            // login origin. Set-Cookie from an origin-changed hop must never be
            // merged into freshCookies (session fixation).
            HttpService currentService = currentRequest.httpService();
            String currentOrigin = origin(currentService.secure() ? "https" : "http",
                    currentService.host(), currentService.port());
            if (currentOrigin.equals(loginOrigin)) {
                collectSetCookies(response, currentRequest, collectedCookies);
            }

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

                // Build GET request to the redirect URL, carrying cookies from the chain
                try {
                    // ORIGIN = scheme + host + effective port. On ANY origin change the
                    // redirect is still followed, but credentials are stripped: no
                    // Authorization/Cookie headers are copied and no collected cookies
                    // are injected — an open redirect must not leak session credentials.
                    URI uri = new URI(redirectUrl);
                    String redirectHost = uri.getHost();
                    String redirectOrigin = redirectHost != null
                            ? origin(uri.getScheme() != null ? uri.getScheme() : "http",
                                    redirectHost, uri.getPort())
                            : null;
                    boolean credentialsAllowed = maySendCredentials(loginOrigin, redirectOrigin);

                    if (!credentialsAllowed) {
                        log("SessionKeepAlive", "Following redirect (" + status + ") outside login origin "
                                + (redirectOrigin != null ? redirectOrigin : truncate(redirectUrl, 80))
                                + " — credentials stripped");
                    } else {
                        log("SessionKeepAlive", "Following redirect (" + status + ") → " + truncate(redirectUrl, 80));
                    }

                    HttpRequest redirectRequest = HttpRequest.httpRequestFromUrl(redirectUrl);
                    if (credentialsAllowed) {
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
                            HttpService redirectService = redirectRequest.httpService();
                            List<SessionCookie> redirectCookies = matchingCookies(
                                    redirectService.host(), redirectRequest.pathWithoutQuery(),
                                    redirectService.secure(), collectedCookies.values());
                            if (!redirectCookies.isEmpty()) {
                                redirectRequest = injectCookiesIntoRequest(redirectRequest, redirectCookies);
                            }
                        }
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

        // If the user selected/cleared a login request while this replay was in
        // flight, discard its result rather than contaminating the new target.
        if (replayGeneration != loginGeneration.get() || savedReq != this.loginRequest) {
            log("SessionKeepAlive", "Discarded stale refresh result after login target changed");
            return;
        }

        // Store collected cookies for injection into all outgoing requests
        if (!collectedCookies.isEmpty()) {
            for (Map.Entry<CookieKey, SessionCookie> entry : collectedCookies.entrySet()) {
                if (entry.getValue().delete()) {
                    freshCookies.remove(entry.getKey());
                } else {
                    freshCookies.put(entry.getKey(), entry.getValue());
                }
            }
            Set<String> capturedNames = new LinkedHashSet<>();
            for (SessionCookie cookie : collectedCookies.values()) {
                capturedNames.add(cookie.name());
            }
            log("SessionKeepAlive", "Refresh OK — " + collectedCookies.size()
                    + " cookie(s) captured: " + String.join(", ", capturedNames));
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

    /** Extract and validate Set-Cookie values using the setting request's scope. */
    private void collectSetCookies(HttpResponse response, HttpRequest setterRequest,
                                   Map<CookieKey, SessionCookie> cookies) {
        HttpService setterService = setterRequest.httpService();
        String setterHost = normalizeHost(setterService.host());
        boolean setterSecure = setterService.secure();
        String defaultPath = defaultCookiePath(setterRequest.pathWithoutQuery());

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
                            String domainAttribute = null;
                            String path = defaultPath;
                            boolean secure = false;
                            boolean delete = false;

                            for (int i = 1; i < parts.length; i++) {
                                String attribute = parts[i].trim();
                                int attrEq = attribute.indexOf('=');
                                String attrName = (attrEq >= 0
                                        ? attribute.substring(0, attrEq) : attribute).trim();
                                String attrValue = attrEq >= 0
                                        ? attribute.substring(attrEq + 1).trim() : "";
                                if ("domain".equalsIgnoreCase(attrName) && !attrValue.isEmpty()) {
                                    domainAttribute = normalizeCookieDomain(attrValue);
                                } else if ("path".equalsIgnoreCase(attrName)
                                        && attrValue.startsWith("/")) {
                                    path = attrValue;
                                } else if ("secure".equalsIgnoreCase(attrName)) {
                                    secure = true;
                                } else if ("max-age".equalsIgnoreCase(attrName)) {
                                    try {
                                        delete = Long.parseLong(attrValue) <= 0;
                                    } catch (NumberFormatException ignored) {}
                                }
                            }

                            if (secure && !setterSecure) {
                                log("SessionKeepAlive", "Ignored Secure cookie '" + name
                                        + "' received over plaintext HTTP");
                                continue;
                            }
                            if (domainAttribute != null
                                    && !domainMatches(setterHost, domainAttribute)) {
                                log("SessionKeepAlive", "Ignored cookie '" + name
                                        + "' with invalid Domain=" + domainAttribute);
                                continue;
                            }

                            boolean hostOnly = domainAttribute == null;
                            String effectiveDomain = hostOnly ? setterHost : domainAttribute;
                            CookieKey key = new CookieKey(name, effectiveDomain, path);
                            cookies.put(key, new SessionCookie(name, value, effectiveDomain,
                                    hostOnly, path, secure,
                                    cookieCreationSequence.incrementAndGet(), delete));
                        }
                    }
                }
            }
        }
    }

    /** True if a Set-Cookie header value carries the Secure attribute. */
    static boolean hasSecureAttribute(String setCookieValue) {
        String[] parts = setCookieValue.split(";");
        for (int i = 1; i < parts.length; i++) {
            if ("secure".equalsIgnoreCase(parts[i].trim())) {
                return true;
            }
        }
        return false;
    }

    /** Credentials may only be sent to the original saved login origin. */
    static boolean maySendCredentials(String loginOrigin, String targetOrigin) {
        return loginOrigin != null && loginOrigin.equals(targetOrigin);
    }

    static boolean domainMatches(String requestHost, String cookieDomain) {
        if (requestHost == null || cookieDomain == null) return false;
        String host = normalizeHost(requestHost);
        String domain = normalizeCookieDomain(cookieDomain);
        return host.equals(domain) || host.endsWith("." + domain);
    }

    static boolean pathMatches(String requestPath, String cookiePath) {
        String request = requestPath == null || requestPath.isEmpty() ? "/" : requestPath;
        String cookie = cookiePath == null || cookiePath.isEmpty() ? "/" : cookiePath;
        if (request.equals(cookie)) return true;
        if (!request.startsWith(cookie)) return false;
        return cookie.endsWith("/")
                || (request.length() > cookie.length() && request.charAt(cookie.length()) == '/');
    }

    static boolean cookieMatches(String requestHost, String requestPath, boolean requestSecure,
                                 String cookieDomain, boolean hostOnly,
                                 String cookiePath, boolean cookieSecure) {
        if (requestHost == null || cookieDomain == null) return false;
        String host = normalizeHost(requestHost);
        boolean hostMatches = hostOnly
                ? host.equals(normalizeCookieDomain(cookieDomain))
                : domainMatches(host, cookieDomain);
        return hostMatches && (!cookieSecure || requestSecure)
                && pathMatches(requestPath, cookiePath);
    }

    private static String defaultCookiePath(String requestPath) {
        if (requestPath == null || !requestPath.startsWith("/")) return "/";
        int lastSlash = requestPath.lastIndexOf('/');
        return lastSlash <= 0 ? "/" : requestPath.substring(0, lastSlash);
    }

    private static String normalizeHost(String host) {
        String normalized = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String normalizeCookieDomain(String domain) {
        String normalized = normalizeHost(domain);
        while (normalized.startsWith(".")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    private List<SessionCookie> matchingCookies(String requestHost, String requestPath,
                                                boolean requestSecure,
                                                Collection<SessionCookie> candidates) {
        if (!enabled || candidates.isEmpty() || loginDomain.isEmpty() || requestHost == null) {
            return Collections.emptyList();
        }
        // Preserve the original safety guarantee: no cookie captured by an
        // HTTPS login workflow is ever downgraded to plaintext HTTP.
        if (loginSecure && !requestSecure) return Collections.emptyList();

        String host = normalizeHost(requestHost);
        String loginHost = normalizeHost(loginDomain);
        if (!host.equals(loginHost) && !host.endsWith("." + loginHost)) {
            return Collections.emptyList();
        }
        List<SessionCookie> result = new ArrayList<>();
        for (SessionCookie cookie : candidates) {
            if (cookie.delete()) continue;
            if (!cookieMatches(host, requestPath, requestSecure, cookie.domain(),
                    cookie.hostOnly(), cookie.path(), cookie.secure())) {
                continue;
            }
            result.add(cookie);
        }
        result.sort(Comparator
                .comparingInt((SessionCookie c) -> c.path().length()).reversed()
                .thenComparingLong(SessionCookie::creationOrder));
        return result;
    }

    /** Effective port for origin comparison: explicit port, or the scheme default. */
    private static int effectivePort(String scheme, int port) {
        if (port > 0) return port;
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    /** Normalized origin string: scheme://host:port (lowercased, effective port). */
    private static String origin(String scheme, String host, int port) {
        return scheme.toLowerCase(Locale.ROOT) + "://" + host.toLowerCase(Locale.ROOT)
                + ":" + effectivePort(scheme, port);
    }

    /** Inject matching cookies, preserving separate same-name path/domain values. */
    private HttpRequest injectCookiesIntoRequest(HttpRequest request, List<SessionCookie> cookies) {
        Set<String> replacedNames = new HashSet<>();
        for (SessionCookie cookie : cookies) replacedNames.add(cookie.name());

        List<String> pairs = new ArrayList<>();
        String existing = request.headerValue("Cookie");
        if (existing != null && !existing.isEmpty()) {
            for (String pair : existing.split(";")) {
                String trimmed = pair.trim();
                int eq = trimmed.indexOf('=');
                String name = eq > 0 ? trimmed.substring(0, eq).trim() : trimmed;
                if (!name.isEmpty() && !replacedNames.contains(name)) {
                    pairs.add(trimmed);
                }
            }
        }
        for (SessionCookie cookie : cookies) {
            pairs.add(cookie.name() + "=" + cookie.value());
        }

        return request.withRemovedHeader("Cookie")
                .withAddedHeader("Cookie", String.join("; ", pairs));
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
