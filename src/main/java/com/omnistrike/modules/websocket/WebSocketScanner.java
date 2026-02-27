package com.omnistrike.modules.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnistrike.framework.ActiveScanExecutor;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;

import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * ScanModule implementation for WebSocket scanning.
 *
 * WebSocket traffic arrives via Montoya's proxy WebSocket handlers (not HTTP flows),
 * so processHttpFlow() returns empty. The real work happens in:
 *   - WebSocketInterceptor (captures WS frames via proxy)
 *   - WebSocketAnalyzer (passive analysis on every frame)
 *   - WebSocketFuzzer (active testing when user clicks Scan)
 */
public class WebSocketScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;

    // Components
    private final WebSocketConnectionTracker connectionTracker;
    private final WebSocketInterceptor interceptor;
    private final WebSocketAnalyzer analyzer;
    private final WebSocketFuzzer fuzzer;

    // Dependencies
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    private ActiveScanExecutor executor;

    // Logger for UI activity log
    private Consumer<String> uiLogger;

    public WebSocketScanner() {
        this.connectionTracker = new WebSocketConnectionTracker();
        this.analyzer = new WebSocketAnalyzer();
        this.fuzzer = new WebSocketFuzzer();
        this.interceptor = new WebSocketInterceptor(null, connectionTracker, analyzer);
    }

    @Override
    public String getId() {
        return "ws-scanner";
    }

    @Override
    public String getName() {
        return "WebSocket Scanner";
    }

    @Override
    public String getDescription() {
        return "Intercepts WebSocket frames, performs passive analysis for sensitive data and auth issues, "
                + "and offers on-demand active fuzzing with OOB-first injection testing.";
    }

    @Override
    public ModuleCategory getCategory() {
        return ModuleCategory.INJECTION;
    }

    @Override
    public boolean isPassive() {
        return false; // Has active capabilities (fuzzer)
    }

    /**
     * WebSocket traffic doesn't arrive via HTTP flows — it uses Montoya's
     * proxy WebSocket creation handler. This method always returns empty.
     */
    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        return Collections.emptyList();
    }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;

        // Wire API to interceptor (was constructed with null api)
        interceptor.setApi(api);

        // Wire API to components
        interceptor.setLogger(msg -> {
            if (uiLogger != null) uiLogger.accept(msg);
        });

        fuzzer.setApi(api);
        fuzzer.setLogger(msg -> {
            if (uiLogger != null) uiLogger.accept(msg);
        });

        // Wire dependencies if already set
        if (findingsStore != null) {
            analyzer.setFindingsStore(findingsStore);
        }
        if (dedup != null || findingsStore != null || collaboratorManager != null) {
            fuzzer.setDependencies(dedup, findingsStore, collaboratorManager);
        }
        if (executor != null) {
            fuzzer.setExecutor(executor);
        }

        // Register the WebSocket creation handler with Burp's proxy
        api.proxy().registerWebSocketCreationHandler(interceptor);

        api.logging().logToOutput("[WS-Scanner] Initialized. WebSocket proxy interception active.");
    }

    @Override
    public void destroy() {
        fuzzer.shutdown();
        connectionTracker.clear();
    }

    /**
     * Called by OmniStrikeExtension to inject shared framework dependencies.
     */
    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;

        analyzer.setFindingsStore(findingsStore);
        fuzzer.setDependencies(dedup, findingsStore, collaboratorManager);
    }

    /**
     * Sets the ActiveScanExecutor for the fuzzer.
     */
    public void setExecutor(ActiveScanExecutor executor) {
        this.executor = executor;
        fuzzer.setExecutor(executor);
    }

    /**
     * Sets the UI logger callback for activity log messages.
     */
    public void setUiLogger(Consumer<String> logger) {
        this.uiLogger = logger;
        interceptor.setLogger(logger);
        fuzzer.setLogger(logger);
    }

    // ==================== Component Accessors ====================

    public WebSocketConnectionTracker getConnectionTracker() {
        return connectionTracker;
    }

    public WebSocketInterceptor getInterceptor() {
        return interceptor;
    }

    public WebSocketAnalyzer getAnalyzer() {
        return analyzer;
    }

    public WebSocketFuzzer getFuzzer() {
        return fuzzer;
    }
}
