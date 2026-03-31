package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ScanModule;

import com.omnistrike.framework.stepper.StepperEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.BiConsumer;

/**
 * Intercepts all HTTP traffic via HttpHandler and ProxyResponseHandler.
 * Routes in-scope request/response pairs to all enabled modules.
 */
public class TrafficInterceptor implements HttpHandler, ProxyResponseHandler {

    private final MontoyaApi api;
    private final ModuleRegistry registry;
    private final FindingsStore findingsStore;
    private final ActiveScanExecutor executor;
    private final ScopeManager scopeManager;
    private volatile boolean running = false;
    private volatile BiConsumer<String, String> uiLogger;
    private volatile StepperEngine stepperEngine;
    private volatile SessionKeepAlive sessionKeepAlive;

    // Static file extensions — active injection scanners are skipped for these.
    // Passive analyzers still run (Client-Side Analyzer, Hidden Endpoint Finder, etc.)
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".mjs", ".jsx", ".ts", ".map",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".mp3", ".webm", ".pdf"
    );

    // Executor for passive modules so they don't block the proxy thread.
    // Not final — recreated when stopManualScans() is called to kill queued passive tasks.
    private volatile ExecutorService passiveExecutor;

    // Track futures from manual scans (context menu) so they can be cancelled
    private final CopyOnWriteArrayList<Future<?>> manualScanFutures = new CopyOnWriteArrayList<>();

    /**
     * Global cancellation flag for manual scans. Set to true by stopManualScans().
     * All scan task wrappers check this flag periodically. Reset to false when
     * new manual scans are started.
     *
     * This is the PRIMARY stop mechanism — Future.cancel() only works for queued tasks,
     * not tasks already executing. This flag handles the "already running" case.
     */
    private volatile boolean manualScansCancelled = false;

    /** Returns true if manual scans have been cancelled. Modules can check this. */
    public boolean isManualScanCancelled() { return manualScansCancelled; }

    public TrafficInterceptor(MontoyaApi api, ModuleRegistry registry,
                              FindingsStore findingsStore, ActiveScanExecutor executor,
                              ScopeManager scopeManager) {
        this.api = api;
        this.registry = registry;
        this.findingsStore = findingsStore;
        this.executor = executor;
        this.scopeManager = scopeManager;
        this.passiveExecutor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "OmniStrike-Passive");
            t.setDaemon(true);
            return t;
        });
    }

    /** Set a callback to log events to the UI Activity Log. Args: (module, message) */
    public void setUiLogger(BiConsumer<String, String> logger) {
        this.uiLogger = logger;
    }

    private void uiLog(String module, String message) {
        try {
            api.logging().logToOutput("[" + module + "] " + message);
        } catch (NullPointerException ignored) {
            // Burp API proxy becomes null during extension unload — discard safely
        }
        BiConsumer<String, String> logger = uiLogger;
        if (logger != null) {
            try {
                logger.accept(module, message);
            } catch (NullPointerException ignored) {
                // UI may also be torn down during unload
            }
        }
    }

    public void setStepperEngine(StepperEngine engine) {
        this.stepperEngine = engine;
    }

    public void setSessionKeepAlive(SessionKeepAlive keepAlive) {
        this.sessionKeepAlive = keepAlive;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public boolean isRunning() {
        return running;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        HttpRequest current = request;

        // SessionKeepAlive: inject fresh cookies from the periodic login replay.
        // Domain-scoped — only injects into requests matching the login request's domain.
        try {
            SessionKeepAlive keepAlive = sessionKeepAlive;
            if (keepAlive != null && keepAlive.isEnabled()) {
                String host = request.httpService().host();
                java.util.Map<String, String> freshCookies = keepAlive.getFreshCookiesForHost(host);
                if (!freshCookies.isEmpty()) {
                    current = injectCookies(current, freshCookies);
                }
            }
        } catch (Exception e) {
            // Never break the proxy pipeline
            uiLog("SessionKeepAlive", "ERROR in cookie injection: " + e.getMessage());
        }

        // Stepper: run prerequisite chain and patch variables into outgoing requests.
        // Skipped when the current thread is already executing a Stepper chain (recursion prevention).
        try {
            StepperEngine stepper = stepperEngine;
            if (stepper != null && stepper.isEnabled() && !StepperEngine.isExecutingChain()) {
                HttpRequest modified = stepper.processOutgoingRequest(current);
                if (modified != current) {
                    return RequestToBeSentAction.continueWith(modified);
                }
            }
        } catch (Exception e) {
            // Never break the proxy pipeline — log and pass through unmodified
            uiLog("Stepper", "ERROR in request hook: " + e.getMessage());
        }
        return RequestToBeSentAction.continueWith(current);
    }

    /**
     * Merges cookies into a request's Cookie header.
     * Preserves existing cookies; new values overwrite same-name cookies.
     */
    private HttpRequest injectCookies(HttpRequest request, java.util.Map<String, String> cookies) {
        java.util.LinkedHashMap<String, String> merged = new java.util.LinkedHashMap<>();

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

        // Overlay fresh cookies (new wins on conflicts)
        merged.putAll(cookies);

        // Build Cookie header
        StringBuilder sb = new StringBuilder();
        for (java.util.Map.Entry<String, String> entry : merged.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }

        return request.withRemovedHeader("Cookie")
                .withAddedHeader("Cookie", sb.toString());
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        // Only process proxy-originating traffic via the ProxyResponseHandler below.
        // Requests sent by modules via api.http().sendRequest() also flow through here,
        // which would cause every module's test request to re-trigger all other modules,
        // flooding the thread pool with cascading tasks. Skip them.
        return ResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(
            InterceptedResponse interceptedResponse) {
        if (!running) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        try {
            String host = interceptedResponse.initiatingRequest().httpService().host();
            if (!scopeManager.isInScope(host)) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            String url = interceptedResponse.initiatingRequest().url();

            // URL exclusion — completely skip excluded paths (active + passive)
            if (scopeManager.isExcludedPath(url)) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            // URL inclusion — if inclusion list is active, only scan matching URLs
            if (!scopeManager.isIncludedPath(url)) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            // Compute module lists once per request
            List<ScanModule> passiveModules = registry.getEnabledPassiveModules();
            boolean isStatic = isStaticResource(url);
            // Skip active injection scanners for static files (.js, .css, .png, etc.)
            // Passive analyzers still run — they find results in JS/HTML response bodies.
            List<ScanModule> activeModules = isStatic
                    ? List.of() : registry.getEnabledActiveModules();
            uiLog("Interceptor", "In-scope traffic: " + url
                    + " | Routing to " + passiveModules.size() + " passive + " + activeModules.size() + " active modules"
                    + (isStatic ? " (static — active skipped)" : ""));

            HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                    interceptedResponse.initiatingRequest(), interceptedResponse);

            processWithModules(reqResp, passiveModules, activeModules);
        } catch (Exception e) {
            uiLog("Interceptor", "ERROR: " + e.getClass().getName() + ": " + e.getMessage());
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(
            InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    /**
     * Manually scan a specific request/response with selected modules.
     * Called from the context menu "Send to OmniStrike" action.
     * Runs active modules on the executor thread pool, passive modules on passive executor.
     * Tracks futures so scans can be stopped via stopManualScans().
     */
    public void scanRequest(HttpRequestResponse reqResp, List<String> moduleIds) {
        scanRequest(reqResp, moduleIds, null);
    }

    /**
     * Manually scan a specific request/response with selected modules, optionally
     * targeting a single parameter. When targetParameter is non-null, active modules
     * use processHttpFlowForParameter() to restrict injection to that parameter only.
     */
    public void scanRequest(HttpRequestResponse reqResp, List<String> moduleIds, String targetParameter) {
        if (reqResp == null) return;

        // URL exclusion — skip excluded paths even on manual right-click
        if (scopeManager.isExcludedPath(reqResp.request().url())) {
            uiLog("ManualScan", "SKIPPED (excluded path): " + reqResp.request().url());
            return;
        }

        // URL inclusion — if inclusion list is active, only scan matching URLs
        if (!scopeManager.isIncludedPath(reqResp.request().url())) {
            uiLog("ManualScan", "SKIPPED (not in include list): " + reqResp.request().url());
            return;
        }

        // Reset cancellation flags — new scan is starting
        manualScansCancelled = false;
        ScanState.reset();

        // Clean up completed futures before adding new ones
        manualScanFutures.removeIf(Future::isDone);

        List<ScanModule> passiveModules = new ArrayList<>();
        List<ScanModule> activeModules = new ArrayList<>();

        for (String id : moduleIds) {
            ScanModule m = registry.getModule(id);
            if (m != null) {
                if (m.isPassive()) {
                    passiveModules.add(m);
                } else {
                    activeModules.add(m);
                }
            }
        }

        String url = reqResp.request().url();
        String paramNote = targetParameter != null ? " (parameter: " + targetParameter + ")" : "";
        uiLog("ManualScan", "Scanning " + url + " with " + moduleIds.size() + " module(s)" + paramNote);
        processWithModulesTracked(reqResp, passiveModules, activeModules, targetParameter);
    }

    /**
     * Scan a request with ALL enabled modules (both passive and active).
     * Called from the context menu "Send to OmniStrike (All Modules)" action.
     */
    public void scanRequestAllModules(HttpRequestResponse reqResp) {
        if (reqResp == null) return;

        // URL exclusion — skip excluded paths even on manual right-click
        if (scopeManager.isExcludedPath(reqResp.request().url())) {
            uiLog("ManualScan", "SKIPPED (excluded path): " + reqResp.request().url());
            return;
        }

        // URL inclusion — if inclusion list is active, only scan matching URLs
        if (!scopeManager.isIncludedPath(reqResp.request().url())) {
            uiLog("ManualScan", "SKIPPED (not in include list): " + reqResp.request().url());
            return;
        }

        // Reset cancellation flags — new scan is starting
        manualScansCancelled = false;
        ScanState.reset();
        manualScanFutures.removeIf(Future::isDone);

        List<ScanModule> passiveModules = registry.getEnabledPassiveModules();
        List<ScanModule> activeModules = registry.getEnabledActiveModules();
        String url = reqResp.request().url();
        uiLog("ManualScan", "Scanning " + url + " with ALL "
                + (passiveModules.size() + activeModules.size()) + " enabled module(s)");
        processWithModulesTracked(reqResp, passiveModules, activeModules, null);
    }

    private void processWithModules(HttpRequestResponse reqResp,
                                    List<ScanModule> passiveModules,
                                    List<ScanModule> activeModules) {
        // Passive modules run on a background executor to avoid blocking the proxy thread.
        // Each module gets its own task so a slow one doesn't delay others.
        for (ScanModule module : passiveModules) {
            passiveExecutor.submit(() -> {
                if (manualScansCancelled || Thread.currentThread().isInterrupted()) return;
                try {
                    List<Finding> findings = module.processHttpFlow(reqResp, api);
                    if (manualScansCancelled || Thread.currentThread().isInterrupted()) return;
                    if (findings != null && !findings.isEmpty()) {
                        findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                    }
                } catch (NullPointerException e) {
                    // During extension unload Burp's API proxy becomes null — discard safely.
                    // But if we're still running, this is a real bug — log it.
                    if (running && !manualScansCancelled) {
                        uiLog(module.getId(), "ERROR (passive): NullPointerException: " + e.getMessage());
                    }
                } catch (Exception e) {
                    if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                    uiLog(module.getId(), "ERROR (passive): " + e.getClass().getName()
                            + ": " + e.getMessage());
                }
            });
        }

        // Active modules run on the active scan thread pool
        for (ScanModule module : activeModules) {
            executor.submit(() -> {
                if (manualScansCancelled || Thread.currentThread().isInterrupted()) return;
                try {
                    uiLog(module.getId(), "Processing: " + reqResp.request().url());
                    List<Finding> findings = module.processHttpFlow(reqResp, api);
                    if (manualScansCancelled || Thread.currentThread().isInterrupted()) return;
                    if (findings != null && !findings.isEmpty()) {
                        findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                        uiLog(module.getId(), "Found " + findings.size() + " issue(s)");
                    }
                } catch (Exception e) {
                    if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                    uiLog(module.getId(), "ERROR: " + e.getClass().getName() + ": " + e.getMessage());
                }
            });
        }
    }

    /**
     * Like processWithModules but tracks futures for cancellation.
     * Used by scanRequest() (context menu scans).
     * When targetParameter is non-null, active modules use processHttpFlowForParameter()
     * to restrict injection testing to that single parameter.
     */
    private void processWithModulesTracked(HttpRequestResponse reqResp,
                                            List<ScanModule> passiveModules,
                                            List<ScanModule> activeModules,
                                            String targetParameter) {
        for (ScanModule module : passiveModules) {
            Future<?> f = passiveExecutor.submit(() -> {
                if (manualScansCancelled) return; // Check before starting
                try {
                    List<Finding> findings = module.processHttpFlow(reqResp, api);
                    if (manualScansCancelled) return; // Check after processing
                    if (findings != null && !findings.isEmpty()) {
                        findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                    }
                } catch (NullPointerException e) {
                    if (running && !manualScansCancelled) {
                        uiLog(module.getId(), "ERROR (passive): NullPointerException: " + e.getMessage());
                    }
                } catch (Exception e) {
                    if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                    uiLog(module.getId(), "ERROR (passive): " + e.getClass().getName()
                            + ": " + e.getMessage());
                }
            });
            manualScanFutures.add(f);
        }

        for (ScanModule module : activeModules) {
            Future<?> f = executor.submitTracked(() -> {
                if (manualScansCancelled) return; // Check before starting
                try {
                    uiLog(module.getId(), "Processing: " + reqResp.request().url()
                            + (targetParameter != null ? " [param: " + targetParameter + "]" : ""));
                    List<Finding> findings;
                    if (targetParameter != null) {
                        findings = module.processHttpFlowForParameter(reqResp, targetParameter, api);
                    } else {
                        findings = module.processHttpFlow(reqResp, api);
                    }
                    if (manualScansCancelled) return; // Check after processing
                    if (findings != null && !findings.isEmpty()) {
                        findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                        uiLog(module.getId(), "Found " + findings.size() + " issue(s)");
                    }
                } catch (Exception e) {
                    if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                    uiLog(module.getId(), "ERROR: " + e.getClass().getName() + ": " + e.getMessage());
                }
            });
            if (f != null) {
                manualScanFutures.add(f);
            }
        }
    }

    /**
     * Auto-fills requestResponse on findings that don't have it set.
     * Many passive modules return findings without attaching the original request/response;
     * this ensures every finding reaching DashboardReporter has the data Burp needs.
     */
    private static List<Finding> autoFillReqResp(List<Finding> findings, HttpRequestResponse reqResp) {
        return findings.stream()
                .map(f -> f.withRequestResponse(reqResp))
                .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Stops all running manual scans (context menu scans).
     * Interrupts threads so modules checking Thread.interrupted() will stop.
     * Returns the number of scans that were cancelled.
     */
    public int stopManualScans() {
        // Set the global cancellation flags FIRST — running tasks check these
        manualScansCancelled = true;
        ScanState.cancel();
        running = false;

        // Then cancel futures (handles queued-but-not-yet-started tasks)
        int cancelled = 0;
        for (Future<?> f : manualScanFutures) {
            if (!f.isDone() && f.cancel(true)) {
                cancelled++;
            }
        }
        int total = manualScanFutures.size();
        manualScanFutures.clear();

        // Purge the active scan executor's queue
        int purged = executor.cancelAll();

        // CRITICAL: Also kill and recreate the passive executor.
        // Without this, passive module tasks continue running after stop.
        ExecutorService oldPassive = this.passiveExecutor;
        int passivePurged = 0;
        if (oldPassive != null) {
            passivePurged = oldPassive.shutdownNow().size();
        }
        this.passiveExecutor = java.util.concurrent.Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "OmniStrike-Passive");
            t.setDaemon(true);
            return t;
        });

        // Stop internal thread pools inside modules (e.g., BypassUrlParser, OmniMap, WebSocket)
        stopModuleInternalPools();

        uiLog("ManualScan", "Stopped " + cancelled + " running + " + purged
                + " active + " + passivePurged + " passive task(s)");
        return cancelled + purged + passivePurged;
    }

    /**
     * Stops internal thread pools inside modules that manage their own executors.
     * Called by stopManualScans() to ensure module-internal work is also cancelled.
     */
    private void stopModuleInternalPools() {
        for (ScanModule module : registry.getAllModules()) {
            try {
                if (module instanceof com.omnistrike.modules.injection.BypassUrlParser) {
                    ((com.omnistrike.modules.injection.BypassUrlParser) module).stopScan();
                } else if (module instanceof com.omnistrike.framework.omnimap.OmniMapModule) {
                    ((com.omnistrike.framework.omnimap.OmniMapModule) module).stopExploit();
                }
            } catch (Exception ignored) {}
        }
        executor.resume();
    }

    /**
     * Returns the number of manual scan tasks still running.
     */
    public int getManualScanCount() {
        manualScanFutures.removeIf(Future::isDone);
        return manualScanFutures.size();
    }

    /**
     * Checks if a URL points to a static resource where active injection testing is pointless.
     */
    private static boolean isStaticResource(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        int qIdx = lower.indexOf('?');
        String path = qIdx > 0 ? lower.substring(0, qIdx) : lower;
        for (String ext : STATIC_EXTENSIONS) {
            if (path.endsWith(ext)) return true;
        }
        return false;
    }

    /**
     * Shut down the passive executor. Called during extension unload.
     */
    public void shutdown() {
        passiveExecutor.shutdown();
        try {
            if (!passiveExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                passiveExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            passiveExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
