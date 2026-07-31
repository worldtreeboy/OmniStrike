package com.omnistrike.framework.stepper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.PersistenceManager;
import com.omnistrike.framework.ScopeManager;

import java.util.Base64;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core Stepper engine. Executes a chain of prerequisite HTTP requests before
 * outgoing requests, extracting tokens/variables at each step and patching
 * them into the final outgoing request.
 *
 * Two execution modes:
 *
 * 1) Cached mode (default) — One shared ChainContext (the displayContext) holds
 *    extracted tokens. ReentrantLock serializes chain execution. TTL caches the
 *    result so the chain doesn't re-run for every outgoing request. Good when
 *    the chain produces reusable tokens (login session, persistent cookies).
 *
 * 2) Per-request mode — A fresh ChainContext is allocated for every outgoing
 *    request, no lock, no cache. Multiple Burp scanner threads can run A->B->C->D
 *    pipelines concurrently without clobbering each other. Required when each
 *    probe needs its own single-use token (e.g. CSRF nonce burned per request).
 *    The last completed run is snapshotted into displayContext for UI.
 *
 * Recursion is prevented in both modes via a ThreadLocal flag set while the
 * engine itself is sending prerequisite requests.
 */
public class StepperEngine {

    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\{\\{([^}]+)\\}\\}");

    private final MontoyaApi api;
    private final ScopeManager scopeManager;
    private final List<StepperStep> steps = new ArrayList<>();

    /**
     * Shared cached context (cached mode) AND UI display snapshot (both modes).
     * In per-request mode, after each per-thread chain completes, its state is
     * copied here so the UI shows the latest result.
     */
    private final ChainContext displayContext = new ChainContext();

    /** Manually-added cookies that persist across chain re-runs. Shared across modes. */
    private final ConcurrentHashMap<String, String> pinnedCookies = new ConcurrentHashMap<>();
    private final AtomicLong cookieCreationSequence = new AtomicLong();

    /**
     * Manually-added/overridden variables that persist across chain re-runs.
     * Re-applied to the per-run context after {@code ctx.reset()} so they survive
     * the "clear extracted vars" step at the start of each chain run.
     * Pinned vars win over auto-resolved values when both exist.
     */
    private final ConcurrentHashMap<String, String> pinnedVariables = new ConcurrentHashMap<>();

    private volatile boolean cookieJarEnabled = true;
    private volatile boolean enabled = false;
    private volatile int cacheTtlSeconds = 10;
    private volatile boolean stopOnFailure = false;
    private volatile boolean perRequestMode = false;

    /**
     * When true, processOutgoingRequest is a no-op and in-flight chains break at
     * the next step boundary. Set automatically when OmniStrike's scan is
     * stopped, and toggleable from the UI for manual abort during Burp's
     * built-in scans (which can't notify the extension when they pause).
     */
    private volatile boolean paused = false;

    /** Serializes chain execution in cached mode only. Bypassed in per-request mode. */
    private final ReentrantLock chainLock = new ReentrantLock();

    /** Prevents recursion: when Stepper sends prerequisite requests, skip the hook. */
    private static final ThreadLocal<Boolean> EXECUTING_CHAIN = ThreadLocal.withInitial(() -> false);

    private volatile BiConsumer<String, String> uiLogger;

    /** Persists the chain across Burp restarts. Null until wired; all ops then no-op. */
    private volatile PersistenceManager persistence;
    private static final String STATE_KEY = "stepper.state";
    /** Suppresses persist() while we're loading state back in (avoids redundant writes). */
    private volatile boolean loadingState = false;

    public StepperEngine(MontoyaApi api, ScopeManager scopeManager) {
        this.api = api;
        this.scopeManager = scopeManager;
    }

    // ── Persistence ────────────────────────────────────────────────────────

    public void setPersistence(PersistenceManager persistence) {
        this.persistence = persistence;
    }

    /**
     * Serializes the current chain (steps + rules + flags + pinned vars/cookies)
     * to the preferences store. Called after every mutation; safe to call from
     * any thread. Failure-isolated — a persistence error never breaks Stepper.
     * Note: the {@code enabled} flag is intentionally persisted so a configured
     * chain survives a restart, but it only ever fires in response to matching
     * outgoing traffic the user generates — never spontaneously.
     */
    public void saveState() {
        PersistenceManager pm = persistence;
        if (pm == null || loadingState) return;
        try {
            StepperStepCodec.StepperState state = new StepperStepCodec.StepperState();
            state.enabled = enabled;
            state.cookieJarEnabled = cookieJarEnabled;
            state.stopOnFailure = stopOnFailure;
            state.perRequestMode = perRequestMode;
            state.cacheTtlSeconds = cacheTtlSeconds;
            for (StepperStep step : getSteps()) {
                StepperStepCodec.StepData sd = new StepperStepCodec.StepData();
                sd.name = step.getName();
                sd.enabled = step.isEnabled();
                HttpRequest req = step.getOriginalRequest();
                HttpService svc = req.httpService();
                sd.host = svc.host();
                sd.port = svc.port();
                sd.secure = svc.secure();
                sd.requestB64 = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
                for (ExtractionRule rule : step.getExtractionRules()) {
                    StepperStepCodec.RuleData rd = new StepperStepCodec.RuleData();
                    rd.name = rule.getVariableName();
                    rd.type = rule.getType().name();
                    rd.pattern = rule.getPattern();
                    sd.rules.add(rd);
                }
                state.steps.add(sd);
            }
            state.pinnedVariables.putAll(getPinnedVariables());
            state.pinnedCookies.putAll(pinnedCookies);
            pm.setString(STATE_KEY, StepperStepCodec.toJson(state));
        } catch (Exception e) {
            uiLog("Stepper", "Could not persist state: " + e.getMessage());
        }
    }

    /** Internal alias used by mutators. */
    private void persist() { saveState(); }

    /**
     * Restores a previously-persisted chain. Call once at startup, before the UI
     * is built (the Stepper panel reads engine state at construction). Each step
     * is restored independently so one corrupt entry can't lose the rest.
     */
    public void loadPersistedState() {
        PersistenceManager pm = persistence;
        if (pm == null) return;
        String json = pm.getString(STATE_KEY, null);
        if (json == null || json.isBlank()) return;
        StepperStepCodec.StepperState state = StepperStepCodec.fromJson(json);
        loadingState = true;
        try {
            this.cookieJarEnabled = state.cookieJarEnabled;
            this.stopOnFailure = state.stopOnFailure;
            this.perRequestMode = state.perRequestMode;
            this.cacheTtlSeconds = Math.max(0, state.cacheTtlSeconds);

            int restored = 0;
            synchronized (this) {
                steps.clear();
                for (StepperStepCodec.StepData sd : state.steps) {
                    try {
                        if (sd == null || sd.requestB64 == null || sd.host == null) continue;
                        byte[] raw = Base64.getDecoder().decode(sd.requestB64);
                        HttpService svc = HttpService.httpService(sd.host, sd.port, sd.secure);
                        HttpRequest req = HttpRequest.httpRequest(svc, ByteArray.byteArray(raw));
                        StepperStep step = new StepperStep(
                                sd.name != null ? sd.name : "Step", req);
                        step.setEnabled(sd.enabled);
                        if (sd.rules != null) {
                            for (StepperStepCodec.RuleData rd : sd.rules) {
                                if (rd == null || rd.name == null || rd.type == null) continue;
                                try {
                                    step.addExtractionRule(new ExtractionRule(
                                            rd.name, ExtractionType.valueOf(rd.type), rd.pattern));
                                } catch (IllegalArgumentException badType) {
                                    // Unknown extraction type from a newer/older build — skip the rule.
                                }
                            }
                        }
                        steps.add(step);
                        restored++;
                    } catch (Exception perStep) {
                        // Skip this step; keep going.
                    }
                }
            }

            pinnedVariables.clear();
            if (state.pinnedVariables != null) {
                pinnedVariables.putAll(state.pinnedVariables);
                for (Map.Entry<String, String> e : state.pinnedVariables.entrySet()) {
                    displayContext.variableStore.set(e.getKey(), e.getValue());
                }
            }
            pinnedCookies.clear();
            if (state.pinnedCookies != null) {
                pinnedCookies.putAll(state.pinnedCookies);
                displayContext.cookieJar.putAll(state.pinnedCookies);
            }

            // Restore enabled last, after steps exist, so isEnabled() is consistent.
            this.enabled = state.enabled;
            uiLog("Stepper", "Restored " + restored + " step(s) from saved configuration.");
        } finally {
            loadingState = false;
        }
    }

    // ── Configuration ────────────────────────────────────────────────────────

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; persist(); }

    public int getCacheTtlSeconds() { return cacheTtlSeconds; }
    public void setCacheTtlSeconds(int seconds) { this.cacheTtlSeconds = Math.max(0, seconds); persist(); }

    public long getLastChainRunTime() { return displayContext.lastChainRunTime; }

    public boolean isStopOnFailure() { return stopOnFailure; }
    public void setStopOnFailure(boolean stop) { this.stopOnFailure = stop; persist(); }

    public boolean isPerRequestMode() { return perRequestMode; }
    public void setPerRequestMode(boolean on) {
        this.perRequestMode = on;
        displayContext.lastChainRunTime = 0;
        displayContext.lastChainPrereqCount = -1;
        persist();
    }

    public boolean isPaused() { return paused; }
    public void setPaused(boolean p) {
        boolean wasPaused = this.paused;
        this.paused = p;
        if (p && !wasPaused) uiLog("Stepper", "Paused — new chains blocked, in-flight chains will abort at next step.");
        else if (!p && wasPaused) uiLog("Stepper", "Resumed.");
    }

    public StepperVariableStore getVariableStore() { return displayContext.variableStore; }

    public void setUiLogger(BiConsumer<String, String> logger) { this.uiLogger = logger; }

    // ── Cookie Jar ───────────────────────────────────────────────────────────

    public boolean isCookieJarEnabled() { return cookieJarEnabled; }
    public void setCookieJarEnabled(boolean enabled) { this.cookieJarEnabled = enabled; persist(); }

    public Map<String, String> getCookieJar() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(displayContext.cookieJar));
    }

    public void setCookie(String name, String value) {
        if (name != null && value != null) {
            pinnedCookies.put(name, value);
            displayContext.cookieJar.put(name, value);
            persist();
        }
    }

    public void removeCookie(String name) {
        if (name != null) {
            pinnedCookies.remove(name);
            displayContext.cookieJar.remove(name);
            displayContext.scopedCookies.entrySet().removeIf(e -> e.getValue().name.equals(name));
            persist();
        }
    }

    public void clearCookieJar() {
        pinnedCookies.clear();
        displayContext.cookieJar.clear();
        displayContext.scopedCookies.clear();
        persist();
    }

    // ── Pinned Variables ─────────────────────────────────────────────────────

    /** Manually set or override a variable. Survives chain re-runs. */
    public void setVariable(String name, String value) {
        if (name != null && value != null) {
            pinnedVariables.put(name, value);
            displayContext.variableStore.set(name, value);
            persist();
        }
    }

    /** Remove a manually-pinned variable. Auto-extracted vars with the same name will re-populate on next chain run. */
    public void removeVariable(String name) {
        if (name != null) {
            pinnedVariables.remove(name);
            // Don't remove from displayContext immediately — next chain run will rebuild it.
            // But for UX clarity, remove from display too so the user sees the effect.
            displayContext.variableStore.clear();
            for (Map.Entry<String, String> e : pinnedVariables.entrySet()) {
                displayContext.variableStore.set(e.getKey(), e.getValue());
            }
            persist();
        }
    }

    /** Drop all pinned variables. */
    public void clearPinnedVariables() {
        pinnedVariables.clear();
        persist();
    }

    public Map<String, String> getPinnedVariables() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(pinnedVariables));
    }

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
        persist();
    }

    public synchronized void removeStep(int index) {
        if (index >= 0 && index < steps.size()) {
            StepperStep removed = steps.remove(index);
            uiLog("Stepper", "Removed step: " + removed.getName());
            persist();
        }
    }

    public synchronized void moveStepUp(int index) {
        if (index > 0 && index < steps.size()) {
            StepperStep step = steps.remove(index);
            steps.add(index - 1, step);
            persist();
        }
    }

    public synchronized void moveStepDown(int index) {
        if (index >= 0 && index < steps.size() - 1) {
            StepperStep step = steps.remove(index);
            steps.add(index + 1, step);
            persist();
        }
    }

    public synchronized void clearSteps() {
        steps.clear();
        displayContext.reset();
        displayContext.lastChainRunTime = 0;
        displayContext.lastChainPrereqCount = -1;
        uiLog("Stepper", "All steps cleared.");
        persist();
    }

    public void invalidateCache() {
        displayContext.lastChainRunTime = 0;
        displayContext.lastChainPrereqCount = -1;
    }

    // ── Core: Process Outgoing Request ───────────────────────────────────────

    public HttpRequest processOutgoingRequest(HttpRequest request) {
        if (!enabled) return request;
        if (paused) return request;
        if (isExecutingChain()) return request;

        try {
            String host = request.httpService().host();
            if (scopeManager.hasScope() && !scopeManager.isInScope(host)) return request;
        } catch (Exception e) {
            return request;
        }

        List<StepperStep> currentSteps;
        synchronized (this) {
            if (steps.isEmpty()) return request;
            currentSteps = new ArrayList<>(steps);
        }

        int matchIdx = findMatchingStepIndex(request, currentSteps);
        if (matchIdx < 0) {
            // No configured step matches this outgoing request. Pass through
            // unchanged. (Previously this fell back to "run all steps as prereqs"
            // which caused unrelated browser traffic to trigger the chain.)
            return request;
        }
        List<StepperStep> prereqSteps;
        if (matchIdx == 0) {
            prereqSteps = Collections.emptyList();
        } else {
            prereqSteps = currentSteps.subList(0, matchIdx);
        }

        if (perRequestMode) {
            return processPerRequest(request, prereqSteps);
        }
        return processCached(request, prereqSteps);
    }

    /** Cached / shared-state mode: cache the chain output, serialize chain runs. */
    private HttpRequest processCached(HttpRequest request, List<StepperStep> prereqSteps) {
        int prereqCount = prereqSteps.size();
        long now = System.currentTimeMillis();
        long age = now - displayContext.lastChainRunTime;
        boolean cacheValid = cacheTtlSeconds > 0
                && age < (cacheTtlSeconds * 1000L)
                && displayContext.lastChainPrereqCount == prereqCount;

        if (!cacheValid && !prereqSteps.isEmpty()) {
            try {
                chainLock.lockInterruptibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return request;
            }
            try {
                long ageAfterLock = System.currentTimeMillis() - displayContext.lastChainRunTime;
                if (cacheTtlSeconds <= 0
                        || ageAfterLock >= (cacheTtlSeconds * 1000L)
                        || displayContext.lastChainPrereqCount != prereqCount) {
                    executeChain(prereqSteps, displayContext);
                }
            } finally {
                chainLock.unlock();
            }
        }
        return applyVariables(request, displayContext);
    }

    /**
     * Per-request mode: fresh ChainContext per call. No global lock, no cache.
     * Each Burp scanner thread runs its own A->B->C->D pipeline in parallel.
     * The completed context is snapshotted into displayContext for UI display.
     */
    private HttpRequest processPerRequest(HttpRequest request, List<StepperStep> prereqSteps) {
        ChainContext ctx = new ChainContext();
        if (!prereqSteps.isEmpty()) {
            executeChain(prereqSteps, ctx);
            HttpRequest result = applyVariables(request, ctx);
            snapshotForDisplay(ctx);
            return result;
        }
        // No prereqs to run for this request — pull pinned cookies and any
        // previously-extracted variables from displayContext so substitution
        // still works. Do NOT snapshot back: ctx's lastChainRunTime is 0 and
        // would wipe displayContext's state.
        ctx.cookieJar.putAll(pinnedCookies);
        for (Map.Entry<String, String> e : displayContext.variableStore.getAll().entrySet()) {
            ctx.variableStore.set(e.getKey(), e.getValue());
        }
        return applyVariables(request, ctx);
    }

    /** Copy completed per-request context state into displayContext for the UI. */
    private void snapshotForDisplay(ChainContext src) {
        displayContext.variableStore.clear();
        for (Map.Entry<String, String> e : src.variableStore.getAll().entrySet()) {
            displayContext.variableStore.set(e.getKey(), e.getValue());
        }
        displayContext.cookieJar.clear();
        displayContext.cookieJar.putAll(src.cookieJar);
        displayContext.scopedCookies.clear();
        displayContext.scopedCookies.putAll(src.scopedCookies);
        synchronized (displayContext.stepResponses) {
            displayContext.stepResponses.clear();
            synchronized (src.stepResponses) {
                displayContext.stepResponses.addAll(src.stepResponses);
            }
        }
        displayContext.lastChainRunTime = src.lastChainRunTime;
        displayContext.lastChainPrereqCount = src.lastChainPrereqCount;
    }

    /**
     * Identifies which step the outgoing request corresponds to. Two-pass:
     *
     *   1. EXACT — method + host + port + full path (with query) + body match.
     *      Catches Repeater-style "send the exact configured request" so that
     *      multiple steps differing only in query/body params (postid=1, =2, =3)
     *      are distinguishable.
     *
     *   2. LOOSE — method + host + port + path-without-query. Returns the
     *      HIGHEST matching index, since users add the scan target as the last
     *      step by convention. Catches scanner-mutated probes whose body differs
     *      because of payload injection.
     *
     * Returns -1 if neither pass matches.
     */
    private int findMatchingStepIndex(HttpRequest request, List<StepperStep> steps) {
        String method, host, fullPath, pathOnly, body;
        int port;
        try {
            method   = request.method();
            host     = request.httpService().host();
            port     = request.httpService().port();
            fullPath = request.path();
            pathOnly = request.pathWithoutQuery();
            body     = request.bodyToString();
            if (body == null) body = "";
        } catch (Exception e) {
            return -1;
        }

        // Pass 1: exact match (path + query + body)
        for (int i = 0; i < steps.size(); i++) {
            try {
                HttpRequest s = steps.get(i).getOriginalRequest();
                if (method.equalsIgnoreCase(s.method())
                        && host.equalsIgnoreCase(s.httpService().host())
                        && port == s.httpService().port()
                        && fullPath.equals(s.path())) {
                    String stepBody = s.bodyToString();
                    if (stepBody == null) stepBody = "";
                    if (body.equals(stepBody)) return i;
                }
            } catch (Exception ignored) {}
        }

        // Pass 2: loose match — same method + path-without-query. Return last
        // matching index (convention: target step is added last).
        int lastLoose = -1;
        for (int i = 0; i < steps.size(); i++) {
            try {
                HttpRequest s = steps.get(i).getOriginalRequest();
                if (method.equalsIgnoreCase(s.method())
                        && host.equalsIgnoreCase(s.httpService().host())
                        && port == s.httpService().port()
                        && pathOnly.equals(s.pathWithoutQuery())) {
                    lastLoose = i;
                }
            } catch (Exception ignored) {}
        }
        return lastLoose;
    }

    /**
     * Runs the chain manually (e.g., from the "Run Chain" button). Always
     * targets displayContext regardless of mode, so the user sees the result.
     */
    public boolean runChainManually() {
        List<StepperStep> currentSteps;
        synchronized (this) {
            if (steps.isEmpty()) return false;
            currentSteps = new ArrayList<>(steps);
        }

        chainLock.lock();
        try {
            return executeChain(currentSteps, displayContext);
        } catch (Exception e) {
            uiLog("Stepper", "Manual chain run failed: " + e.getMessage());
            return false;
        } finally {
            chainLock.unlock();
        }
    }

    // ── Chain Execution ──────────────────────────────────────────────────────

    private boolean executeChain(List<StepperStep> currentSteps, ChainContext ctx) {
        EXECUTING_CHAIN.set(true);
        boolean successful = false;
        try {
            ctx.reset();
            // Invalidate any previous success before mutating its variables and
            // cookies. A failed manual refresh must not leave an apparently-valid TTL.
            ctx.lastChainRunTime = 0;
            ctx.lastChainPrereqCount = -1;
            ctx.cookieJar.putAll(pinnedCookies);
            // Re-apply pinned variables so manual overrides survive the reset.
            for (Map.Entry<String, String> e : pinnedVariables.entrySet()) {
                ctx.variableStore.set(e.getKey(), e.getValue());
            }
            uiLog("Stepper", "Running chain (" + currentSteps.size() + " steps)...");

            // Stamp the TTL only when every enabled prerequisite succeeds and
            // every configured extraction produces a value.
            boolean completed = true;
            boolean allStepsSucceeded = true;
            boolean anyStepSucceeded = false;
            for (int i = 0; i < currentSteps.size(); i++) {
                if (Thread.currentThread().isInterrupted()) { completed = false; break; }
                if (paused) {
                    uiLog("Stepper", "  Chain aborted at step " + (i + 1) + " (paused).");
                    completed = false;
                    break;
                }
                StepperStep step = currentSteps.get(i);
                if (!step.isEnabled()) {
                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName() + "] — SKIPPED (disabled)");
                    continue;
                }

                try {
                    HttpRequest templated = substituteAll(step.getOriginalRequest(), ctx);

                    if (cookieJarEnabled && !ctx.cookieJar.isEmpty()) {
                        templated = injectCookies(templated, ctx);
                    }

                    HttpRequestResponse result = api.http().sendRequest(templated);
                    HttpResponse response = result.response();

                    if (response == null) {
                        allStepsSucceeded = false;
                        uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                                + "] — No response (connection failed?)");
                        if (stopOnFailure) {
                            uiLog("Stepper", "  Chain aborted at step " + (i + 1) + " (stop-on-failure).");
                            completed = false;
                            break;
                        }
                        continue;
                    }

                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                            + "] — " + response.statusCode() + " " + step.getUrlSummary());

                    boolean stepSucceeded = response.statusCode() < 400;
                    if (!stepSucceeded) {
                        uiLog("Stepper", "    WARN: HTTP " + response.statusCode()
                                + " marks this prerequisite as failed");
                    }
                    ctx.stepResponses.add(response);

                    if (cookieJarEnabled) {
                        collectCookies(response, i + 1, step.getName(),
                                templated.httpService(), templated.pathWithoutQuery(), ctx);
                    }

                    for (ExtractionRule rule : step.getExtractionRules()) {
                        String value = extractValue(response, rule);
                        if (value != null && !value.isEmpty()) {
                            ctx.variableStore.set(rule.getVariableName(), value);
                            uiLog("Stepper", "    Extracted {{" + rule.getVariableName()
                                    + "}} = " + truncate(value, 50));
                        } else {
                            stepSucceeded = false;
                            uiLog("Stepper", "    WARN: No value extracted for {{"
                                    + rule.getVariableName() + "}} (" + rule.getType() + ": " + rule.getPattern() + ")");
                        }
                    }
                    if (stepSucceeded) {
                        anyStepSucceeded = true;
                    } else {
                        allStepsSucceeded = false;
                        if (stopOnFailure) {
                            uiLog("Stepper", "  Chain aborted at step " + (i + 1)
                                    + " (stop-on-failure).");
                            completed = false;
                            break;
                        }
                    }
                } catch (Exception e) {
                    allStepsSucceeded = false;
                    uiLog("Stepper", "  Step " + (i + 1) + " [" + step.getName()
                            + "] — ERROR: " + e.getMessage());
                    if (stopOnFailure) {
                        uiLog("Stepper", "  Chain aborted at step " + (i + 1) + " (stop-on-failure).");
                        completed = false;
                        break;
                    }
                }
            }

            // Re-apply pinned variables one more time so they win over anything
            // the chain extracted under the same name (user explicitly pinned them).
            for (Map.Entry<String, String> e : pinnedVariables.entrySet()) {
                ctx.variableStore.set(e.getKey(), e.getValue());
            }

            int varCount = ctx.variableStore.getAll().size();
            int cookieCount = ctx.cookieJar.size();
            if (shouldStampCache(completed, allStepsSucceeded, anyStepSucceeded)) {
                ctx.lastChainRunTime = System.currentTimeMillis();
                ctx.lastChainPrereqCount = currentSteps.size();
                successful = true;
                uiLog("Stepper", "Chain complete. " + varCount + " variable(s), "
                        + cookieCount + " cookie(s) collected.");
            } else if (!completed) {
                uiLog("Stepper", "Chain aborted — cache not stamped, chain will re-run on next request. "
                        + varCount + " variable(s), " + cookieCount + " cookie(s) collected so far.");
            } else {
                uiLog("Stepper", "Chain finished with failed or skipped prerequisites — cache not stamped, "
                        + "chain will re-run on next request.");
            }
        } finally {
            EXECUTING_CHAIN.set(false);
        }
        return successful;
    }

    static boolean shouldStampCache(boolean completed, boolean allStepsSucceeded,
                                    boolean anyStepSucceeded) {
        return completed && allStepsSucceeded && anyStepSucceeded;
    }

    // ── Variable Substitution ────────────────────────────────────────────────

    private HttpRequest applyVariables(HttpRequest request, ChainContext ctx) {
        HttpRequest modified = request;
        if (cookieJarEnabled && !ctx.cookieJar.isEmpty()) {
            modified = injectCookies(modified, ctx);
        }
        return substituteAll(modified, ctx);
    }

    private HttpRequest substituteAll(HttpRequest request, ChainContext ctx) {
        HttpRequest modified = request;

        try {
            String originalPath = request.path();
            if (originalPath != null && originalPath.contains("{{")) {
                String substituted = substituteString(originalPath, ctx);
                if (!originalPath.equals(substituted)) {
                    modified = modified.withPath(substituted);
                }
            }
        } catch (Exception ignored) {}

        for (var header : List.copyOf(modified.headers())) {
            String originalValue = header.value();
            if (originalValue == null || !originalValue.contains("{{")) continue;
            String substituted = substituteString(originalValue, ctx);
            if (!originalValue.equals(substituted)) {
                modified = modified.withRemovedHeader(header.name())
                        .withAddedHeader(header.name(), substituted);
            }
        }

        String body = modified.bodyToString();
        if (body != null && body.contains("{{")) {
            String substitutedBody = substituteString(body, ctx);
            if (!body.equals(substitutedBody)) {
                modified = modified.withBody(substitutedBody);
            }
        }

        return modified;
    }

    private String substituteString(String input, ChainContext ctx) {
        if (input == null || input.isEmpty()) return input;
        Matcher m = PLACEHOLDER_PATTERN.matcher(input);
        if (!m.find()) return input;

        StringBuilder sb = new StringBuilder();
        m.reset();
        while (m.find()) {
            String varName = m.group(1).trim();
            String value = ctx.variableStore.get(varName);
            if (value == null) {
                value = autoResolve(varName, ctx);
                if (value != null) {
                    ctx.variableStore.set(varName, value);
                    uiLog("Stepper", "  Auto-resolved {{" + varName + "}} = " + truncate(value, 50));
                }
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(value != null ? value : m.group(0)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String autoResolve(String varName, ChainContext ctx) {
        if (varName == null || varName.isEmpty()) return null;

        List<HttpResponse> snapshot;
        synchronized (ctx.stepResponses) {
            snapshot = new ArrayList<>(ctx.stepResponses);
        }

        for (int i = snapshot.size() - 1; i >= 0; i--) {
            HttpResponse resp = snapshot.get(i);
            String value = findInResponse(resp, varName);
            if (value != null && !value.isEmpty()) return value;
        }
        return null;
    }

    private String findInResponse(HttpResponse resp, String varName) {
        try {
            String h = resp.headerValue(varName);
            if (h != null && !h.isEmpty()) return h;
        } catch (Exception ignored) {}

        try {
            for (var header : resp.headers()) {
                if (!"Set-Cookie".equalsIgnoreCase(header.name())) continue;
                String val = header.value();
                int sc = val.indexOf(';');
                String nv = (sc >= 0 ? val.substring(0, sc) : val).trim();
                int eq = nv.indexOf('=');
                if (eq > 0) {
                    String name = nv.substring(0, eq).trim();
                    if (name.equalsIgnoreCase(varName)) {
                        return nv.substring(eq + 1).trim();
                    }
                }
            }
        } catch (Exception ignored) {}

        String body;
        try {
            body = resp.bodyToString();
        } catch (Exception e) {
            return null;
        }
        if (body == null || body.isEmpty()) return null;

        try {
            JsonElement root = JsonParser.parseString(body);
            String found = findJsonKey(root, varName);
            if (found != null) return found;
        } catch (Exception ignored) {}

        try {
            String quoted = Pattern.quote(varName);
            Matcher m = Pattern.compile("\"" + quoted + "\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
            if (m.find()) return m.group(1);
            m = Pattern.compile("\"" + quoted + "\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)").matcher(body);
            if (m.find()) return m.group(1);
            m = Pattern.compile("(?:^|[?&;\\s])" + quoted + "=([^&;\\s\"<>]+)").matcher(body);
            if (m.find()) return m.group(1);
        } catch (Exception ignored) {}

        return null;
    }

    private String findJsonKey(JsonElement el, String key) {
        if (el == null || el.isJsonNull()) return null;
        if (el.isJsonObject()) {
            JsonObject obj = el.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(key)) {
                    JsonElement v = entry.getValue();
                    if (v != null && v.isJsonPrimitive()) return v.getAsString();
                }
            }
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String found = findJsonKey(entry.getValue(), key);
                if (found != null) return found;
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            for (JsonElement child : arr) {
                String found = findJsonKey(child, key);
                if (found != null) return found;
            }
        }
        return null;
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

    private String extractBodyRegex(HttpResponse response, String regex) {
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) return null;
        Matcher m = Pattern.compile(regex).matcher(body);
        if (m.find()) {
            return m.groupCount() >= 1 ? m.group(1) : m.group(0);
        }
        return null;
    }

    private String extractHeader(HttpResponse response, String headerName) {
        return response.headerValue(headerName);
    }

    private String extractCookie(HttpResponse response, String cookieName) {
        for (var header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String val = header.value();
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

    private void collectCookies(HttpResponse response, int stepNum, String stepName,
                                HttpService service, String requestPath, ChainContext ctx) {
        // Record each cookie's RFC 6265 scope (setter host, Domain, Secure, Path)
        // so it is only re-injected into requests that fall inside that scope.
        // Pinned cookies get no origin entry and stay global.
        String setterHost = null;
        boolean setterSecure = false;
        if (service != null && service.host() != null) {
            setterHost = normalizeHost(service.host());
            setterSecure = service.secure();
        }
        String defaultPath = defaultCookiePath(requestPath);
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
                        if (name.isEmpty()) continue;

                        String domain = null;       // null = host-only (no Domain attribute)
                        boolean secureAttr = false;
                        boolean delete = false;
                        String path = defaultPath;
                        for (int p = 1; p < parts.length; p++) {
                            String attr = parts[p].trim();
                            int aeq = attr.indexOf('=');
                            String attrName = (aeq >= 0 ? attr.substring(0, aeq) : attr).trim();
                            String attrValue = aeq >= 0 ? attr.substring(aeq + 1).trim() : "";
                            if ("domain".equalsIgnoreCase(attrName) && !attrValue.isEmpty()) {
                                domain = normalizeCookieDomain(attrValue);
                            } else if ("secure".equalsIgnoreCase(attrName)) {
                                secureAttr = true;
                            } else if ("path".equalsIgnoreCase(attrName) && attrValue.startsWith("/")) {
                                path = attrValue;
                            } else if ("max-age".equalsIgnoreCase(attrName)) {
                                try {
                                    delete = Long.parseLong(attrValue) <= 0;
                                } catch (NumberFormatException ignored) {}
                            }
                        }

                        if (setterHost == null) continue;
                        if (secureAttr && !setterSecure) {
                            uiLog("Stepper", "    Ignored Secure cookie " + name
                                    + " received over plaintext HTTP");
                            continue;
                        }
                        if (domain != null && !domainMatches(setterHost, domain)) {
                            uiLog("Stepper", "    Ignored cookie " + name
                                    + " with invalid Domain=" + domain);
                            continue;
                        }

                        String effectiveDomain = domain == null ? setterHost : domain;
                        ChainContext.CookieKey key =
                                new ChainContext.CookieKey(name, effectiveDomain, path);
                        if (delete) {
                            ctx.scopedCookies.remove(key);
                            refreshCookieJarProjection(ctx, name);
                            continue;
                        }

                        ChainContext.CookieOrigin origin = new ChainContext.CookieOrigin(
                                setterHost, domain, secureAttr, path);
                        ctx.scopedCookies.put(key, new ChainContext.ScopedCookie(
                                name, value, origin, cookieCreationSequence.incrementAndGet()));
                        ctx.cookieJar.put(name, value);
                        uiLog("Stepper", "    Cookie: " + name + "=" + truncate(value, 40));
                    }
                }
            }
        }
    }

    /** RFC 6265 §5.1.4 default-path: everything up to the last '/', else '/'. */
    private static String defaultCookiePath(String requestPath) {
        if (requestPath == null || !requestPath.startsWith("/")) return "/";
        int lastSlash = requestPath.lastIndexOf('/');
        return lastSlash <= 0 ? "/" : requestPath.substring(0, lastSlash);
    }

    private void refreshCookieJarProjection(ChainContext ctx, String name) {
        String pinned = pinnedCookies.get(name);
        if (pinned != null) {
            ctx.cookieJar.put(name, pinned);
            return;
        }
        ChainContext.ScopedCookie newest = null;
        for (ChainContext.ScopedCookie cookie : ctx.scopedCookies.values()) {
            if (!cookie.name.equals(name)) continue;
            if (newest == null || cookie.creationOrder > newest.creationOrder) newest = cookie;
        }
        if (newest == null) ctx.cookieJar.remove(name);
        else ctx.cookieJar.put(name, newest.value);
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

    private static String normalizeHost(String host) {
        String normalized = host == null ? "" : host.trim().toLowerCase(java.util.Locale.ROOT);
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

    /**
     * Decides whether a chain-collected cookie may ride on an outgoing request.
     * Package-private and static so it is unit-testable. A null origin means a
     * pinned/manually-added cookie — user-intentional, always sent.
     */
    static boolean cookieMatches(String requestHost, String requestPath, boolean requestSecure,
                                 ChainContext.CookieOrigin origin) {
        if (origin == null) return true;
        if (requestHost == null) return false;
        String host = normalizeHost(requestHost);
        boolean hostMatches = origin.domain != null
                ? domainMatches(host, origin.domain)
                : host.equals(normalizeHost(origin.host));
        if (!hostMatches) return false;
        if (origin.secure && !requestSecure) return false;
        return pathMatches(requestPath, origin.path);
    }

    private HttpRequest injectCookies(HttpRequest request, ChainContext ctx) {
        String reqHost = null;
        String reqPath = "/";
        boolean reqSecure = false;
        try {
            HttpService svc = request.httpService();
            if (svc != null && svc.host() != null) {
                reqHost = normalizeHost(svc.host());
                reqSecure = svc.secure();
            }
            String p = request.pathWithoutQuery();
            if (p != null && !p.isEmpty()) reqPath = p;
        } catch (Exception ignored) {}

        List<ChainContext.ScopedCookie> matchingScoped = new ArrayList<>();
        if (reqHost != null) {
            for (ChainContext.ScopedCookie cookie : ctx.scopedCookies.values()) {
                if (!pinnedCookies.containsKey(cookie.name)
                        && cookieMatches(reqHost, reqPath, reqSecure, cookie.origin)) {
                    matchingScoped.add(cookie);
                }
            }
        }
        matchingScoped.sort(Comparator
                .comparingInt((ChainContext.ScopedCookie c) -> c.origin.path.length()).reversed()
                .thenComparingLong(c -> c.creationOrder));

        Set<String> replacedNames = new HashSet<>(pinnedCookies.keySet());
        for (ChainContext.ScopedCookie cookie : matchingScoped) replacedNames.add(cookie.name);

        List<String> pairs = new ArrayList<>();
        String existingCookie = request.headerValue("Cookie");
        if (existingCookie != null && !existingCookie.isEmpty()) {
            for (String pair : existingCookie.split(";")) {
                String trimmed = pair.trim();
                int eq = trimmed.indexOf('=');
                String name = eq > 0 ? trimmed.substring(0, eq).trim() : trimmed;
                if (!name.isEmpty() && !replacedNames.contains(name)) pairs.add(trimmed);
            }
        }
        for (Map.Entry<String, String> entry : pinnedCookies.entrySet()) {
            pairs.add(entry.getKey() + "=" + entry.getValue());
        }
        for (ChainContext.ScopedCookie cookie : matchingScoped) {
            pairs.add(cookie.name + "=" + cookie.value);
        }

        return request.withRemovedHeader("Cookie")
                .withAddedHeader("Cookie", String.join("; ", pairs));
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
