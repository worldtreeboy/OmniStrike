package com.omnistrike.framework;
import com.omnistrike.framework.stepper.StepperHttp;

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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
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
    /** When true, log every in-scope passive routing decision (noisy under heavy browsing). */
    private volatile boolean verboseLogging = false;
    private volatile BiConsumer<String, String> uiLogger;
    private volatile StepperEngine stepperEngine;
    private volatile SessionKeepAlive sessionKeepAlive;
    // Used to bypass dedup for explicit manual scans (right-click), so re-scanning
    // a target that was already tested actually re-runs it.
    private volatile DeduplicationStore dedup;

    // Executor for passive modules so they don't block the proxy thread.
    // Not final — recreated when stopManualScans() is called to kill queued passive tasks.
    private volatile ExecutorService passiveExecutor;
    private static final int PASSIVE_QUEUE_CAPACITY = 256;
    private final AtomicLong droppedPassiveTasks = new AtomicLong();
    private final AtomicLong lastPassiveQueueWarningNanos = new AtomicLong();

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
        this.passiveExecutor = createPassiveExecutor();
    }

    private static ExecutorService createPassiveExecutor() {
        return new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(PASSIVE_QUEUE_CAPACITY), r -> {
            Thread t = new Thread(r, "OmniStrike-Passive");
            t.setDaemon(true);
            return t;
        }, new ThreadPoolExecutor.AbortPolicy());
    }

    private Future<?> submitPassive(Runnable task, String context) {
        try {
            return passiveExecutor.submit(task);
        } catch (RejectedExecutionException rejected) {
            long dropped = droppedPassiveTasks.incrementAndGet();
            long now = System.nanoTime();
            long previous = lastPassiveQueueWarningNanos.get();
            if (now - previous > TimeUnit.SECONDS.toNanos(5)
                    && lastPassiveQueueWarningNanos.compareAndSet(previous, now)) {
                uiLog("PassiveScan", "Queue full; skipped " + context
                        + " task (" + dropped + " skipped total). Reduce scan concurrency or retry later.");
            }
            return null;
        }
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

    public void setDeduplicationStore(DeduplicationStore dedup) {
        this.dedup = dedup;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public boolean isRunning() {
        return running;
    }

    /** Enable/disable verbose per-request routing logs. */
    public void setVerboseLogging(boolean verbose) {
        this.verboseLogging = verbose;
    }

    public boolean isVerboseLogging() {
        return verboseLogging;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        HttpRequest current = request;

        // SessionKeepAlive: inject fresh cookies from the periodic login replay.
        // RFC-scoped — Domain/host-only, Path, and Secure attributes are enforced.
        try {
            SessionKeepAlive keepAlive = sessionKeepAlive;
            if (keepAlive != null && keepAlive.isEnabled()) {
                current = keepAlive.applyFreshCookies(current);
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

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        // Only process proxy-originating traffic via the ProxyResponseHandler below.
        // Requests sent by modules via StepperHttp.sendRequest() also flow through here,
        // which would cause every module's test request to re-trigger all other modules,
        // flooding the thread pool with cascading tasks. Skip them.
        return ResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(
            InterceptedResponse interceptedResponse) {
        // Nothing runs automatically on proxy traffic — neither active nor passive.
        // Every scan, including the passive analyzers, is right-click driven:
        // user picks a request → Send to OmniStrike → all selected modules
        // (passive + active) run on that specific request/response. This keeps
        // the findings list to exactly what the user asked for.
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
        if (!isManualRequestAllowed(reqResp)) return;

        // Reset cancellation flags — new scan is starting
        manualScansCancelled = false;
        ScanState.reset();
        // Resume Stepper in case a prior stop paused it.
        StepperEngine ssr = stepperEngine;
        if (ssr != null) ssr.setPaused(false);

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
        if (!isManualRequestAllowed(reqResp)) return;

        // Reset cancellation flags — new scan is starting
        manualScansCancelled = false;
        ScanState.reset();
        // Resume Stepper in case a prior stop paused it.
        StepperEngine ssr = stepperEngine;
        if (ssr != null) ssr.setPaused(false);
        manualScanFutures.removeIf(Future::isDone);

        List<ScanModule> passiveModules = new ArrayList<>();
        List<ScanModule> activeModules = new ArrayList<>();
        for (ScanModule module : registry.getEnabledManualScanModules()) {
            if (module.isPassive()) passiveModules.add(module);
            else activeModules.add(module);
        }
        String url = reqResp.request().url();
        uiLog("ManualScan", "Scanning " + url + " with ALL "
                + (passiveModules.size() + activeModules.size()) + " enabled module(s)");
        processWithModulesTracked(reqResp, passiveModules, activeModules, null);
    }

    /**
     * Manual scan from the parameter-selection dialog.
     *
     * <p>Each selected ACTIVE module runs once per selected parameter (targeted
     * injection via {@code processHttpFlowForParameter}) — so the user scans
     * exactly the parameters they ticked, individually. Each (module, parameter)
     * pair is its own cancellable task. Selected PASSIVE modules run once over the
     * whole request. Dedup is bypassed on the worker thread since this is an
     * explicit, user-triggered scan that must re-test even already-seen targets.
     */
    public void scanRequestParameters(HttpRequestResponse reqResp,
                                      List<String> activeModuleIds,
                                      List<String> passiveModuleIds,
                                      List<String> parameters) {
        if (reqResp == null) return;
        if (!isManualRequestAllowed(reqResp)) return;

        String reqUrl = reqResp.request().url();
        // Reset cancellation flags — new scan is starting
        manualScansCancelled = false;
        ScanState.reset();
        StepperEngine ssr = stepperEngine;
        if (ssr != null) ssr.setPaused(false);
        manualScanFutures.removeIf(Future::isDone);

        // Resolve ids -> modules (defensive: keep only the matching kind)
        List<ScanModule> activeModules = new ArrayList<>();
        if (activeModuleIds != null) {
            for (String id : activeModuleIds) {
                ScanModule m = registry.getModule(id);
                if (m != null && !m.isPassive()) activeModules.add(m);
            }
        }
        List<ScanModule> passiveModules = new ArrayList<>();
        if (passiveModuleIds != null) {
            for (String id : passiveModuleIds) {
                ScanModule m = registry.getModule(id);
                if (m != null && m.isPassive()) passiveModules.add(m);
            }
        }

        // Distinct, non-empty parameter targets
        List<String> params = new ArrayList<>();
        if (parameters != null) {
            for (String p : parameters) {
                if (p != null && !p.isEmpty() && !params.contains(p)) params.add(p);
            }
        }

        if (activeModules.isEmpty() && passiveModules.isEmpty()) {
            uiLog("ManualScan", "Nothing to scan — no modules selected.");
            return;
        }

        uiLog("ManualScan", "Scanning " + reqUrl + " — " + activeModules.size()
                + " active module(s) x " + params.size() + " param(s) + "
                + passiveModules.size() + " passive module(s)");

        // ---- Passive modules: run once over the whole request ----
        for (ScanModule module : passiveModules) {
            Future<?> f = submitPassive(() -> {
                if (manualScansCancelled) return;
                DeduplicationStore d = dedup;
                if (d != null) d.setBypass(true);
                try {
                    List<Finding> findings = module.processHttpFlow(reqResp, api);
                    if (manualScansCancelled) return;
                    if (findings != null && !findings.isEmpty()) {
                        findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                    }
                } catch (NullPointerException e) {
                    if (running && !manualScansCancelled) {
                        uiLog(module.getId(), "ERROR (passive): NullPointerException: " + e.getMessage());
                    }
                } catch (Exception e) {
                    if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                    uiLog(module.getId(), "ERROR (passive): " + e.getClass().getName() + ": " + e.getMessage());
                } finally {
                    if (d != null) d.setBypass(false);
                }
            }, "manual " + module.getId());
            if (f != null) manualScanFutures.add(f);
        }

        // ---- Active modules ----
        // Modules that override processHttpFlowForParameter run once per selected
        // parameter (true per-parameter targeting). Modules that DON'T override it
        // would otherwise fall back to a full processHttpFlow per parameter — i.e.
        // redundant whole-request scans — so we run those exactly once instead.
        for (ScanModule module : activeModules) {
            boolean perParam = supportsParameterTargeting(module) && !params.isEmpty();
            List<String> targets = perParam ? params : java.util.Collections.singletonList(null);
            for (String param : targets) {
                Future<?> f = executor.submitTracked(() -> {
                    if (manualScansCancelled) return;
                    DeduplicationStore d = dedup;
                    if (d != null) d.setBypass(true);
                    try {
                        String label = param != null ? " [param: " + param + "]" : " [whole request]";
                        uiLog(module.getId(), "Processing: " + reqUrl + label);
                        List<Finding> findings = (param != null)
                                ? module.processHttpFlowForParameter(reqResp, param, api)
                                : module.processHttpFlow(reqResp, api);
                        if (manualScansCancelled) return;
                        if (findings != null && !findings.isEmpty()) {
                            findingsStore.addFindings(autoFillReqResp(findings, reqResp));
                            uiLog(module.getId(), "Found " + findings.size() + " issue(s)"
                                    + (param != null ? " on '" + param + "'" : ""));
                        }
                    } catch (Exception e) {
                        if (Thread.currentThread().isInterrupted() || manualScansCancelled) return;
                        uiLog(module.getId(), "ERROR: " + e.getClass().getName() + ": " + e.getMessage());
                    } finally {
                        if (d != null) d.setBypass(false);
                    }
                });
                if (f != null) manualScanFutures.add(f);
            }
        }
    }

    private boolean isManualRequestAllowed(HttpRequestResponse reqResp) {
        try {
            String url = reqResp.request().url();
            String host = reqResp.request().httpService().host();
            if (scopeManager.isExplicitScanAllowed(url, host)) return true;
            uiLog("Scope", "Skipped out-of-scope manual scan: "
                    + PrivacyManager.maskForDisplay(url));
            return false;
        } catch (Exception e) {
            uiLog("Scope", "Skipped manual scan because its target could not be validated: "
                    + e.getMessage());
            return false;
        }
    }

    /**
     * True if the module overrides {@code processHttpFlowForParameter} (i.e. it can
     * target a single parameter). Modules that rely on the interface default would
     * just re-scan the whole request, so callers run them once instead of per-param.
     */
    private boolean supportsParameterTargeting(ScanModule module) {
        try {
            java.lang.reflect.Method m = module.getClass().getMethod(
                    "processHttpFlowForParameter",
                    HttpRequestResponse.class, String.class,
                    burp.api.montoya.MontoyaApi.class);
            return m.getDeclaringClass() != ScanModule.class;
        } catch (Exception e) {
            return true; // assume targeting works — matches prior behavior
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
            Future<?> f = submitPassive(() -> {
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
            }, "manual " + module.getId());
            if (f != null) manualScanFutures.add(f);
        }

        for (ScanModule module : activeModules) {
            Future<?> f = executor.submitTracked(() -> {
                if (manualScansCancelled) return; // Check before starting
                // Explicit manual scan: bypass dedup so repeated user-requested scans
                // actually re-test the target. Reset in finally — threads are pooled.
                DeduplicationStore d = dedup;
                if (d != null) d.setBypass(true);
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
                } finally {
                    if (d != null) d.setBypass(false);
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
        // NOTE: do NOT clear `running` here. `running` means "extension is live"
        // (used to tell real NPEs from unload noise); only unload clears it.
        // Tell Stepper to pause so in-flight chains abort and new ones are blocked.
        StepperEngine s = stepperEngine;
        if (s != null) s.setPaused(true);

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
        this.passiveExecutor = createPassiveExecutor();

        // Stop internal thread pools inside modules
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
