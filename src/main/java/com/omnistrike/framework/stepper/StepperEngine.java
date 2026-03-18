package com.omnistrike.framework.stepper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.ScopeManager;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core Stepper engine. Executes a chain of prerequisite HTTP requests before
 * outgoing requests, extracting tokens/variables at each step and patching
 * them into the final outgoing request.
 *
 * Concurrency model:
 * - ThreadLocal EXECUTING_CHAIN prevents recursion when prerequisite requests
 *   flow back through handleHttpRequestToBeSent().
 * - ReentrantLock serializes chain execution so only one chain runs at a time.
 * - Token cache with TTL avoids re-running the chain for every request during scans.
 */
public class StepperEngine {

    private final MontoyaApi api;
    private final ScopeManager scopeManager;
    private final StepperVariableStore variableStore = new StepperVariableStore();
    private final List<StepperStep> steps = new ArrayList<>();

    /**
     * Automatic cookie jar — accumulates all Set-Cookie values from chain responses.
     * Key: cookie name, Value: cookie value.
     * Auto-injected into subsequent steps and the final outgoing request.
     * Individual cookies can be added/removed at any time via the UI.
     */
    private final ConcurrentHashMap<String, String> cookieJar = new ConcurrentHashMap<>();
    /** Manually-added cookies that persist across chain re-runs. */
    private final ConcurrentHashMap<String, String> pinnedCookies = new ConcurrentHashMap<>();
    private volatile boolean cookieJarEnabled = true;

    private volatile boolean enabled = false;
    private volatile int cacheTtlSeconds = 10;
    private volatile long lastChainRunTime = 0;

    private final ReentrantLock chainLock = new ReentrantLock();

    /** Prevents recursion: when Stepper sends prerequisite requests, skip the hook. */
    private static final ThreadLocal<Boolean> EXECUTING_CHAIN = ThreadLocal.withInitial(() -> false);

    private volatile BiConsumer<String, String> uiLogger;

    public StepperEngine(MontoyaApi api, ScopeManager scopeManager) {
        this.api = api;
        this.scopeManager = scopeManager;
    }

    // ── Configuration ────────────────────────────────────────────────────────

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getCacheTtlSeconds() { return cacheTtlSeconds; }
    public void setCacheTtlSeconds(int seconds) { this.cacheTtlSeconds = Math.max(0, seconds); }

    public long getLastChainRunTime() { return lastChainRunTime; }

    public StepperVariableStore getVariableStore() { return variableStore; }

    public void setUiLogger(BiConsumer<String, String> logger) { this.uiLogger = logger; }

    // ── Cookie Jar ───────────────────────────────────────────────────────────

    public boolean isCookieJarEnabled() { return cookieJarEnabled; }
    public void setCookieJarEnabled(boolean enabled) { this.cookieJarEnabled = enabled; }

    /** Returns an unmodifiable snapshot of the cookie jar. */
    public Map<String, String> getCookieJar() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(cookieJar));
    }

    /** Manually add or update a cookie in the jar. Pinned cookies survive chain re-runs. */
    public void setCookie(String name, String value) {
        if (name != null && value != null) {
            cookieJar.put(name, value);
            pinnedCookies.put(name, value);
        }
    }

    /** Remove a single cookie from the jar (also unpins it). */
    public void removeCookie(String name) {
        if (name != null) {
            cookieJar.remove(name);
            pinnedCookies.remove(name);
        }
    }

    /** Clear all cookies from the jar (including pinned). */
    public void clearCookieJar() {
        cookieJar.clear();
        pinnedCookies.clear();
    }

    /** Returns true if the current thread is executing a Stepper chain. */
    public static boolean isExecutingChain() {
        return Boolean.TRUE.equals(EXECUTING_CHAIN.get());
    }

    // ── Step Management ──────────────────────────────────────────────────────

    public synchronized List<StepperStep> getSteps() {
        return Collections.unmodifiableList(new ArrayList<>(steps));
    }

    public synchronized int getStepCount() { return steps.size(); }

    public synchronized void addStep(StepperStep step) {
        steps.add(step);
        uiLog("Stepper", "Added step " + steps.size() + ": " + step.getName()
                + " (" + step.getUrlSummary() + ")");
    }

    public synchronized void removeStep(int index) {
        if (index >= 0 && index < steps.size()) {
            StepperStep removed = steps.remove(index);
            uiLog("Stepper", "Removed step: " + removed.getName());
        }
    }

    public synchronized void moveStepUp(int index) {
        if (index > 0 && index < steps.size()) {
            StepperStep step = steps.remove(index);
            steps.add(index - 1, step);
        }
    }

    public synchronized void moveStepDown(int index) {
        if (index >= 0 && index < steps.size() - 1) {
            StepperStep step = steps.remove(index);
            steps.add(index + 1, step);
        }
    }

    public synchronized void clearSteps() {
        steps.clear();
        variableStore.clear();
        cookieJar.clear();
        lastChainRunTime = 0;
        uiLog("Stepper", "All steps cleared.");
    }

    public void invalidateCache() {
        lastChainRunTime = 0;
    }

    // ── Core: Process Outgoing Request ───────────────────────────────────────

    /**
     * Called from TrafficInterceptor.handleHttpRequestToBeSent().
     * If Stepper is enabled and the request is in scope, runs the prerequisite
     * chain (if cache is stale) and patches variables into the outgoing request.
     */
    public HttpRequest processOutgoingRequest(HttpRequest request) {
        if (!enabled) return request;

        // Skip if this thread is already executing a chain (recursion prevention)
        if (isExecutingChain()) return request;

        // Scope check
        try {
            String host = request.httpService().host();
            if (!scopeManager.isInScope(host)) return request;
        } catch (Exception e) {
            return request;
        }

        // Get a snapshot of steps
        List<StepperStep> currentSteps;
        synchronized (this) {
            if (steps.isEmpty()) return request;
            currentSteps = new ArrayList<>(steps);
        }

        // Check if cache is still valid
        long now = System.currentTimeMillis();
        long age = now - lastChainRunTime;
        boolean cacheValid = cacheTtlSeconds > 0 && age < (cacheTtlSeconds * 1000L);

        if (!cacheValid) {
            // Run the chain — serialize with lock so only one thread runs it
            try {
                chainLock.lockInterruptibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return request; // return unmodified request
            }
            try {
                // Double-check after acquiring lock (another thread may have just run it)
                long ageAfterLock = System.currentTimeMillis() - lastChainRunTime;
                if (cacheTtlSeconds <= 0 || ageAfterLock >= (cacheTtlSeconds * 1000L)) {
                    executeChain(currentSteps);
                }
            } finally {
                chainLock.unlock();
            }
        }

        // Apply variables to the outgoing request
        return applyVariables(request);
    }

    /**
     * Runs the chain manually (e.g., from the "Run Chain" button).
     * Returns true if the chain completed successfully.
     */
    public boolean runChainManually() {
        List<StepperStep> currentSteps;
        synchronized (this) {
            if (steps.isEmpty()) return false;
            currentSteps = new ArrayList<>(steps);
        }

        chainLock.lock();
        try {
            executeChain(currentSteps);
            return true;
        } catch (Exception e) {
            uiLog("Stepper", "Manual chain run failed: " + e.getMessage());
            return false;
        } finally {
            chainLock.unlock();
        }
    }

    // ── Chain Execution ──────────────────────────────────────────────────────

    private void executeChain(List<StepperStep> currentSteps) {
        EXECUTING_CHAIN.set(true);
        try {
            variableStore.clear();
            cookieJar.clear();
            // Restore manually-pinned cookies so they survive chain re-runs
            cookieJar.putAll(pinnedCookies);
            uiLog("Stepper", "Running chain (" + currentSteps.size() + " steps)...");

            for (int i = 0; i < currentSteps.size(); i++) {
                if (Thread.currentThread().isInterrupted()) break;
                StepperStep step = currentSteps.get(i);
                if (!step.isEnabled()) {
                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName() + "] — SKIPPED (disabled)");
                    continue;
                }

                try {
                    // Substitute variables into the step's request template
                    HttpRequest templated = substituteRequest(step.getOriginalRequest());

                    // Inject accumulated cookies from previous steps
                    if (cookieJarEnabled && !cookieJar.isEmpty()) {
                        templated = injectCookies(templated);
                    }

                    // Send the request
                    HttpRequestResponse result = api.http().sendRequest(templated);
                    HttpResponse response = result.response();

                    if (response == null) {
                        uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                                + "] — No response (connection failed?)");
                        continue;
                    }

                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                            + "] — " + response.statusCode() + " " + step.getUrlSummary());

                    // Auto-collect Set-Cookie headers into the cookie jar
                    if (cookieJarEnabled) {
                        collectCookies(response, i + 1, step.getName());
                    }

                    // Extract values from explicit extraction rules
                    for (ExtractionRule rule : step.getExtractionRules()) {
                        String value = extractValue(response, rule);
                        if (value != null && !value.isEmpty()) {
                            variableStore.set(rule.getVariableName(), value);
                            uiLog("Stepper", "    Extracted {{" + rule.getVariableName()
                                    + "}} = " + truncate(value, 50));
                        } else {
                            uiLog("Stepper", "    WARN: No value extracted for {{"
                                    + rule.getVariableName() + "}} (" + rule.getType() + ": " + rule.getPattern() + ")");
                        }
                    }
                } catch (Exception e) {
                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                            + "] — ERROR: " + e.getMessage());
                }
            }

            lastChainRunTime = System.currentTimeMillis();
            int varCount = variableStore.getAll().size();
            int cookieCount = cookieJar.size();
            uiLog("Stepper", "Chain complete. " + varCount + " variable(s), "
                    + cookieCount + " cookie(s) collected.");
        } finally {
            EXECUTING_CHAIN.set(false);
        }
    }

    // ── Variable Substitution ────────────────────────────────────────────────

    /**
     * Substitutes {{variables}} in all headers and body of an HttpRequest.
     */
    private HttpRequest substituteRequest(HttpRequest request) {
        // Substitute in headers — snapshot the list to avoid issues if modified mutates it
        HttpRequest modified = request;
        for (var header : List.copyOf(request.headers())) {
            String originalValue = header.value();
            String substituted = variableStore.substitute(originalValue);
            if (!originalValue.equals(substituted)) {
                modified = modified.withRemovedHeader(header.name())
                        .withAddedHeader(header.name(), substituted);
            }
        }

        // Substitute in body
        String body = modified.bodyToString();
        if (body != null && !body.isEmpty()) {
            String substitutedBody = variableStore.substitute(body);
            if (!body.equals(substitutedBody)) {
                modified = modified.withBody(substitutedBody);
            }
        }

        return modified;
    }

    /**
     * Applies stored variables and cookie jar to the outgoing request (the final target request).
     */
    private HttpRequest applyVariables(HttpRequest request) {
        HttpRequest modified = request;

        // Inject cookies from the jar
        if (cookieJarEnabled && !cookieJar.isEmpty()) {
            modified = injectCookies(modified);
        }

        // Substitute {{variables}} in headers — iterate over modified (post-cookie-injection) headers
        boolean hasVariables = !variableStore.getAll().isEmpty();
        if (hasVariables) {
            for (var header : List.copyOf(modified.headers())) {
                String originalValue = header.value();
                String substituted = variableStore.substitute(originalValue);
                if (!originalValue.equals(substituted)) {
                    modified = modified.withRemovedHeader(header.name())
                            .withAddedHeader(header.name(), substituted);
                }
            }

            // Substitute in body
            String body = modified.bodyToString();
            if (body != null && !body.isEmpty()) {
                String substitutedBody = variableStore.substitute(body);
                if (!body.equals(substitutedBody)) {
                    modified = modified.withBody(substitutedBody);
                }
            }
        }

        return modified;
    }

    // ── Extraction Methods ───────────────────────────────────────────────────

    private String extractValue(HttpResponse response, ExtractionRule rule) {
        try {
            return switch (rule.getType()) {
                case BODY_REGEX -> extractBodyRegex(response, rule.getPattern());
                case HEADER -> extractHeader(response, rule.getPattern());
                case COOKIE -> extractCookie(response, rule.getPattern());
                case JSON_PATH -> extractJsonPath(response, rule.getPattern());
            };
        } catch (Exception e) {
            return null;
        }
    }

    /** Extracts capture group 1 from a regex match against the response body. */
    private String extractBodyRegex(HttpResponse response, String regex) {
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) return null;
        Matcher m = Pattern.compile(regex).matcher(body);
        if (m.find()) {
            return m.groupCount() >= 1 ? m.group(1) : m.group(0);
        }
        return null;
    }

    /** Extracts the value of a named response header. */
    private String extractHeader(HttpResponse response, String headerName) {
        return response.headerValue(headerName);
    }

    /** Extracts the value of a named cookie from Set-Cookie headers. */
    private String extractCookie(HttpResponse response, String cookieName) {
        for (var header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String val = header.value();
                // Parse "name=value; ..." format
                String[] parts = val.split(";");
                if (parts.length > 0) {
                    String nameValue = parts[0].trim();
                    int eq = nameValue.indexOf('=');
                    if (eq > 0) {
                        String name = nameValue.substring(0, eq).trim();
                        if (name.equalsIgnoreCase(cookieName)) {
                            return nameValue.substring(eq + 1).trim();
                        }
                    }
                }
            }
        }
        return null;
    }

    /** Extracts a value via simple dot-notation JSON path (e.g., "data.token"). */
    private String extractJsonPath(HttpResponse response, String jsonPath) {
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) return null;

        try {
            JsonElement root = JsonParser.parseString(body);
            String[] segments = jsonPath.split("\\.");
            JsonElement current = root;

            for (String segment : segments) {
                if (current == null || !current.isJsonObject()) return null;
                JsonObject obj = current.getAsJsonObject();
                current = obj.get(segment);
            }

            if (current == null || current.isJsonNull()) return null;
            if (current.isJsonPrimitive()) return current.getAsString();
            return current.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ── Cookie Jar Helpers ─────────────────────────────────────────────────

    /**
     * Collects all Set-Cookie headers from a response into the cookie jar.
     * Later cookies with the same name overwrite earlier ones (newest wins).
     */
    private void collectCookies(HttpResponse response, int stepNum, String stepName) {
        for (var header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String val = header.value();
                String[] parts = val.split(";");
                if (parts.length > 0) {
                    String nameValue = parts[0].trim();
                    int eq = nameValue.indexOf('=');
                    if (eq > 0) {
                        String name = nameValue.substring(0, eq).trim();
                        String value = nameValue.substring(eq + 1).trim();
                        cookieJar.put(name, value);
                        uiLog("Stepper", "    Cookie: " + name + "=" + truncate(value, 40));
                    }
                }
            }
        }
    }

    /**
     * Merges the cookie jar into the request's Cookie header.
     * Preserves any existing cookies in the request that aren't in the jar,
     * and overwrites those that are (jar wins — it has the freshest values).
     */
    private HttpRequest injectCookies(HttpRequest request) {
        // Parse existing Cookie header
        Map<String, String> merged = new LinkedHashMap<>();
        String existingCookie = request.headerValue("Cookie");
        if (existingCookie != null && !existingCookie.isEmpty()) {
            for (String pair : existingCookie.split(";")) {
                String trimmed = pair.trim();
                int eq = trimmed.indexOf('=');
                if (eq > 0) {
                    merged.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
                }
            }
        }

        // Overlay with cookie jar (jar wins)
        merged.putAll(cookieJar);

        // Build the new Cookie header
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : merged.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }

        return request.withRemovedHeader("Cookie")
                .withAddedHeader("Cookie", sb.toString());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void uiLog(String module, String message) {
        try {
            api.logging().logToOutput("[" + module + "] " + message);
        } catch (NullPointerException ignored) {}
        BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try {
                logger.accept(module, message);
            } catch (NullPointerException ignored) {}
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
