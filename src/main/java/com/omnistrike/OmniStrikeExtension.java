package com.omnistrike;
import com.omnistrike.framework.stepper.StepperHttp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.omnistrike.framework.*;
import com.omnistrike.framework.stepper.StepperEngine;
import com.omnistrike.framework.tls.TlsAnalyzer;
import com.omnistrike.model.ModuleConfig;
import com.omnistrike.modules.injection.*;
// WebSocket module removed
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.framework.wordlist.WordlistGenerator;
import com.omnistrike.modules.recon.*;
import com.omnistrike.ui.GlobalThemeManager;
import com.omnistrike.ui.MainPanel;

import javax.swing.*;

/**
 * OmniStrike v1.84 — Entry Point
 *
 * A unified multi-module vulnerability scanning framework for Burp Suite:
 *   AI Analysis: AI Vulnerability Analyzer (Claude, Gemini, Codex, OpenCode CLI)
 *   Recon (Passive): Client-Side Analyzer, Endpoint Finder, Subdomain Collector, Security Header Analyzer,
 *       Technology Fingerprinter, Sensitive Data Exposure
 *   Injection (Active): SQLi Detector, NoSQL Operator Injection, SSTI Scanner, SSRF Scanner, XSS Scanner,
 *       Command Injection, Deserialization Scanner, GraphQL Tool, XXE Scanner,
 *       CORS Misconfiguration, Cache Poisoning, Host Header Injection, Prototype Pollution, Path Traversal,
 *       HTTP Parameter Pollution
 *
 * Built exclusively on the Montoya API.
 */
public class OmniStrikeExtension implements BurpExtension {

    private ModuleRegistry registry;
    private FindingsStore findingsStore;
    private ActiveScanExecutor executor;
    private TrafficInterceptor interceptor;
    private CollaboratorManager collaboratorManager;
    private SessionKeepAlive sessionKeepAlive;
    private StepperEngine stepperEngine;
    private TlsAnalyzer tlsAnalyzer;
    private volatile MainPanel mainPanel;
    private volatile Audit persistentAudit;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OmniStrike");
        api.logging().logToOutput("=== OmniStrike v1.84 initializing ===");

        // Core framework components
        findingsStore = new FindingsStore();
        findingsStore.setErrorLogger(msg -> api.logging().logToError(msg));
        // User-level settings store (survives Burp restarts). Failure-isolated:
        // if unavailable, every read falls back to defaults and writes no-op.
        PersistenceManager persistence = new PersistenceManager(api);
        persistence.setErrorLogger(msg -> api.logging().logToError(msg));
        DashboardReporter dashboardReporter = new DashboardReporter(api);
        // FindingsBundler wraps DashboardReporter — consolidates LOW/INFO findings per host
        FindingsBundler findingsBundler = new FindingsBundler(dashboardReporter, api);
        findingsStore.addListener(findingsBundler); // Bundler delegates to DashboardReporter
        DeduplicationStore dedup = new DeduplicationStore();
        executor = new ActiveScanExecutor(5);
        ThrottleController throttleController = new ThrottleController();
        throttleController.setLogger(msg -> api.logging().logToOutput(msg));
        executor.setThrottleController(throttleController);
        ResponseGuard.setThrottleController(throttleController);
        ScopeManager scopeManager = new ScopeManager();
        SharedDataBus dataBus = new SharedDataBus();
        registry = new ModuleRegistry();

        // Initialize Collaborator (Professional edition only)
        collaboratorManager = new CollaboratorManager(api);
        boolean collabAvailable = collaboratorManager.initialize();
        if (collabAvailable) {
            api.logging().logToOutput("Burp Collaborator: Available (Professional edition)");
            api.logging().logToOutput("OOB Mode: Burp Collaborator (default)");
        } else {
            api.logging().logToOutput("Burp Collaborator: Not available (Community edition or disabled)");
            collaboratorManager.switchToCustomOob();
            api.logging().logToOutput("OOB Mode: Custom OOB Listener (Collaborator unavailable)");
            api.logging().logToOutput("  → Configure a Custom OOB Listener in the OmniStrike tab to enable OOB testing.");
        }

        // ==================== REGISTER MODULES ====================

        // Recon modules (passive) — wire SharedDataBus for inter-module sharing
        HiddenEndpointFinder endpointFinder = new HiddenEndpointFinder();
        endpointFinder.setSharedDataBus(dataBus);
        endpointFinder.setFindingsStore(findingsStore);
        registry.registerModule(endpointFinder);

        SubdomainCollector subdomainCollector = new SubdomainCollector();
        subdomainCollector.setSharedDataBus(dataBus);
        registry.registerModule(subdomainCollector);

        registry.registerModule(new SecurityHeaderAnalyzer());
        registry.registerModule(new ClientSideAnalyzer());
        registry.registerModule(new TechFingerprinter());
        registry.registerModule(new SensitiveDataExposure());
        registry.registerModule(new ErrorDisclosureScanner());

        // Wordlist Generator (passive word harvester — framework tool, domain-scoped)
        WordlistGenerator wordlistGen = new WordlistGenerator();
        registry.registerModule(wordlistGen);

        // AI Vulnerability Analyzer (optional, disabled by default)
        AiVulnAnalyzer aiAnalyzer = new AiVulnAnalyzer();
        aiAnalyzer.setDependencies(findingsStore);
        aiAnalyzer.setModuleRegistry(registry);
        aiAnalyzer.setCollaboratorManager(collaboratorManager);
        aiAnalyzer.setSharedDataBus(dataBus);
        aiAnalyzer.setPersistence(persistence);
        registry.registerModuleDisabled(aiAnalyzer);

        // Injection modules (active) — wire dedup, findingsStore, collaborator to ALL
        SmartSqliDetector sqli = new SmartSqliDetector();
        sqli.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(sqli);

        NoSqlInjectionScanner nosqli = new NoSqlInjectionScanner();
        nosqli.setDependencies(dedup, findingsStore);
        registry.registerModule(nosqli);

        SstiScanner ssti = new SstiScanner();
        ssti.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(ssti);

        SsrfScanner ssrf = new SsrfScanner();
        ssrf.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(ssrf);

        CommandInjectionScanner cmdi = new CommandInjectionScanner();
        cmdi.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(cmdi);

        DeserializationScanner deser = new DeserializationScanner();
        deser.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(deser);

        GraphqlTool graphql = new GraphqlTool();
        graphql.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(graphql);

        XxeScanner xxe = new XxeScanner();
        xxe.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(xxe);

        CorsMisconfScanner cors = new CorsMisconfScanner();
        cors.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(cors);

        CachePoisonScanner cachePoison = new CachePoisonScanner();
        cachePoison.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(cachePoison);

        HostHeaderScanner hostHeader = new HostHeaderScanner();
        hostHeader.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(hostHeader);

        PrototypePollutionScanner protoPollution = new PrototypePollutionScanner();
        protoPollution.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(protoPollution);

        PathTraversalScanner pathTraversal = new PathTraversalScanner();
        pathTraversal.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(pathTraversal);

        HttpParamPollutionScanner hpp = new HttpParamPollutionScanner();
        hpp.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(hpp);

        // Dynamics 365 FetchXML Injection (auto-triggered, not user-triggerable)
        Dynamics365Scanner d365 = new Dynamics365Scanner();
        d365.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(d365);

        // SAP OData Injection (auto-triggered, not user-triggerable)
        SapODataScanner sapOData = new SapODataScanner();
        sapOData.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(sapOData);

        // Salesforce SOQL Injection (auto-triggered, not user-triggerable)
        SalesforceSOQLScanner sfSoql = new SalesforceSOQLScanner();
        sfSoql.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(sfSoql);

        // Firebase Misconfiguration (auto-triggered, not user-triggerable)
        FirebaseMisconfigScanner firebase = new FirebaseMisconfigScanner();
        firebase.setDependencies(dedup, findingsStore, collaboratorManager);
        firebase.setScopeManager(scopeManager);
        registry.registerModule(firebase);

        // SharePoint CAML Injection (auto-triggered, not user-triggerable)
        SharePointCAMLScanner sharepoint = new SharePointCAMLScanner();
        sharepoint.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(sharepoint);

        // ServiceNow GlideRecord Injection (auto-triggered, not user-triggerable)
        ServiceNowGlideScanner servicenow = new ServiceNowGlideScanner();
        servicenow.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(servicenow);

        // Apache Solr Query Injection (auto-triggered, not user-triggerable)
        SolrQueryScanner solr = new SolrQueryScanner();
        solr.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(solr);

        // Odoo Domain Filter Injection (auto-triggered, not user-triggerable)
        OdooDomainScanner odoo = new OdooDomainScanner();
        odoo.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(odoo);

        // Elasticsearch Query Injection (auto-triggered, not user-triggerable)
        ElasticsearchQueryScanner elasticsearch = new ElasticsearchQueryScanner();
        elasticsearch.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(elasticsearch);

        // Spring Boot Actuator Exposure (auto-triggered, not user-triggerable)
        SpringActuatorScanner springActuator = new SpringActuatorScanner();
        springActuator.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(springActuator);

        // Initialize all modules
        registry.initializeAll(api);
        // Restore the AI backend choice (CLI provider + binary path) now that the
        // module — and its LlmClient — has been initialized. API keys are never
        // persisted; AI stays disabled until the user re-selects a connection mode.
        aiAnalyzer.loadPersistedConfig();
        api.logging().logToOutput("Registered " + registry.getAllModules().size() + " modules.");

        // ==================== TRAFFIC INTERCEPTOR ====================
        interceptor = new TrafficInterceptor(api, registry, findingsStore, executor, scopeManager);
        // Lets manual right-click scans bypass dedup so they re-test targets already
        // covered by automatic scanning.
        interceptor.setDeduplicationStore(dedup);

        // Register with Burp's HTTP and proxy pipelines
        api.http().registerHttpHandler(interceptor);
        api.proxy().registerResponseHandler(interceptor);
        // Mark the extension live so genuine NPEs in scan tasks are logged
        // rather than mistaken for unload noise. Nothing runs automatically on
        // proxy traffic — every scan (passive + active) is right-click driven.
        interceptor.setRunning(true);
        api.logging().logToOutput("Traffic interceptor registered. Scans are right-click only.");

        // ==================== STEPPER ENGINE ====================
        stepperEngine = new StepperEngine(api, scopeManager);
        interceptor.setStepperEngine(stepperEngine);
        // Wire the StepperHttp wrapper so scan modules' sendRequest calls also
        // route through Stepper (Montoya's api.http().sendRequest bypasses HttpHandler).
        com.omnistrike.framework.stepper.StepperHttp.init(api, stepperEngine);
        // Restore any saved chain BEFORE the UI is built — the Stepper panel reads
        // engine state at construction (which happens later in invokeLater).
        stepperEngine.setPersistence(persistence);
        stepperEngine.loadPersistedState();
        api.logging().logToOutput("Stepper engine initialized (disabled by default).");

        // ==================== TLS ANALYZER ====================
        // Out-of-band TLS prober — separate connection from the plugin process,
        // since Burp's Montoya API does not expose negotiated TLS metadata.
        tlsAnalyzer = new TlsAnalyzer(api, findingsStore);
        api.logging().logToOutput("TLS Analyzer initialized.");

        // ==================== SESSION KEEP-ALIVE ====================
        sessionKeepAlive = new SessionKeepAlive(api);
        // Restore only the refresh interval and erase any legacy plaintext login request.
        sessionKeepAlive.setPersistence(persistence);
        sessionKeepAlive.loadPersistedState();
        // uiLogger is wired below after MainPanel is created (it needs logPanel)
        // Wire AFTER construction (the field is null until now): the interceptor's
        // HttpHandler injects fresh cookies into Burp's built-in tools, and
        // StepperHttp injects them into OmniStrike's own module sends.
        interceptor.setSessionKeepAlive(sessionKeepAlive);
        com.omnistrike.framework.stepper.StepperHttp.setSessionKeepAlive(sessionKeepAlive);
        api.logging().logToOutput("Session Keep-Alive initialized (disabled by default).");

        // ==================== SCANNER INTEGRATION ====================
        // Register OmniStrike modules as a native Burp ScanCheck so findings
        // appear in Dashboard task boxes (same as Burp's built-in active scan).
        // Only processes URLs explicitly queued via context menu — never scans random traffic.
        OmniStrikeScanCheck scanCheck = new OmniStrikeScanCheck(api, registry, findingsStore);
        api.scanner().registerScanCheck(scanCheck);
        api.logging().logToOutput("Scanner integration registered (findings appear in Dashboard).");

        // Create a single persistent Audit so ALL findings aggregate in one
        // "OmniStrike" Dashboard task box (like Burp's built-in "Live audit").
        // DashboardReporter feeds every finding into the deferred queue on
        // OmniStrikeScanCheck, then pokes this audit to trigger passiveAudit()
        // which drains the queue and returns AuditIssues into the task box.
        try {
            persistentAudit = api.scanner().startAudit(
                    AuditConfiguration.auditConfiguration(
                            BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS));
            dashboardReporter.setDashboardBridge(scanCheck, persistentAudit);
            api.logging().logToOutput("Persistent Dashboard task box created.");
        } catch (Exception e) {
            api.logging().logToOutput("Dashboard task box unavailable (findings still appear in Site Map): "
                    + e.getMessage());
        }

        // ==================== CONTEXT MENU ====================
        OmniStrikeContextMenu contextMenu = new OmniStrikeContextMenu(
                api, registry, interceptor, sessionKeepAlive, stepperEngine);
        contextMenu.setMainPanelSupplier(() -> mainPanel);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);
        api.logging().logToOutput("Context menu registered (right-click > Send to OmniStrike).");

        // ==================== THEME SYSTEM ====================
        // Snapshot Burp's original UIManager defaults before applying any theme
        GlobalThemeManager.saveOriginalDefaults();
        // v1.82 visual migration: select the new product theme before constructing
        // Swing components. Previously MainPanel was built in native mode, so all
        // style helpers became no-ops and a persisted "Default" preference could
        // make the redesign look identical to the old UI.
        String startupTheme = persistence.getString("theme.name", "Omni Pro");
        if (!persistence.getBoolean("ui.omniProMigrated", false)) {
            if (startupTheme == null || "Default".equals(startupTheme)) {
                startupTheme = "Omni Pro";
                persistence.setString("theme.name", startupTheme);
            }
            persistence.setBoolean("ui.omniProMigrated", true);
        }
        GlobalThemeManager.setCurrentScope(
                "GLOBAL".equals(persistence.getString("theme.scope", "OMNISTRIKE_ONLY"))
                        ? GlobalThemeManager.ThemeScope.GLOBAL
                        : GlobalThemeManager.ThemeScope.OMNISTRIKE_ONLY);
        com.omnistrike.ui.ThemePalette startupPalette =
                GlobalThemeManager.findThemeByName(startupTheme);
        if (startupPalette == null && !"Default".equals(startupTheme)) {
            startupPalette = com.omnistrike.ui.ThemePalette.omniPro();
        }
        GlobalThemeManager.applyTheme(startupPalette);
        final String startupThemeName = startupTheme;
        api.logging().logToOutput("Theme system initialized (startup theme: "
                + startupThemeName + ").");

        // ==================== UI ====================
        SwingUtilities.invokeLater(() -> {
            mainPanel = new MainPanel(
                    registry, findingsStore, scopeManager,
                    executor, interceptor, collaboratorManager, sessionKeepAlive,
                    stepperEngine, tlsAnalyzer, dataBus, persistence, api);
            api.userInterface().registerSuiteTab("OmniStrike", mainPanel);
            // Wire Stepper log messages to the Activity Log
            if (stepperEngine != null) {
                stepperEngine.setUiLogger((module, message) ->
                        javax.swing.SwingUtilities.invokeLater(() ->
                                mainPanel.getLogPanel().log("INFO", module, message)));
            }
            // Wire CollaboratorManager (Custom OOB) log messages to the Activity Log
            collaboratorManager.setUiLogger((module, message) ->
                    javax.swing.SwingUtilities.invokeLater(() ->
                            mainPanel.getLogPanel().log("INFO", module, message)));
            // Wire SessionKeepAlive log messages to the Activity Log
            sessionKeepAlive.setUiLogger((module, message) ->
                    javax.swing.SwingUtilities.invokeLater(() ->
                            mainPanel.getLogPanel().log("INFO", module, message)));
            // Wire TLS Analyzer log messages to the Activity Log
            if (tlsAnalyzer != null) {
                tlsAnalyzer.setUiLogger((module, message) ->
                        javax.swing.SwingUtilities.invokeLater(() ->
                                mainPanel.getLogPanel().log("INFO", module, message)));
            }
            api.logging().logToOutput("UI tab registered. Theme: " + startupThemeName + ".");
        });

        // ==================== CLEANUP ON UNLOAD ====================
        final AiVulnAnalyzer aiRef = aiAnalyzer;
        final FindingsBundler bundlerRef = findingsBundler;
        api.extension().registerUnloadingHandler(() -> {
            try { api.logging().logToOutput("OmniStrike unloading..."); }
            catch (NullPointerException ignored) {}
            interceptor.setRunning(false);
            executor.setUnloading(true); // Signal NPEs from dead API proxy are expected
            interceptor.shutdown(); // stop passive executor
            if (sessionKeepAlive != null) {
                sessionKeepAlive.shutdown();
            }
            // Stop UI timers to prevent leaks
            if (mainPanel != null) {
                SwingUtilities.invokeLater(() -> mainPanel.stopTimers());
            }
            registry.destroyAll();
            executor.shutdown();
            if (tlsAnalyzer != null) {
                tlsAnalyzer.shutdown();
            }
            if (collaboratorManager != null) {
                collaboratorManager.shutdown();
            }
            if (bundlerRef != null) {
                bundlerRef.shutdown();
            }
            if (persistentAudit != null) {
                try { persistentAudit.delete(); } catch (Exception ignored) {}
            }
            // Restore Burp's original look-and-feel
            GlobalThemeManager.setOmniStrikeRoot(null);
            GlobalThemeManager.restoreOriginal();
            try { api.logging().logToOutput("OmniStrike unloaded. Goodbye!"); }
            catch (NullPointerException ignored) {}
        });

        api.logging().logToOutput("=== OmniStrike v1.84 ready ===");
        String oobMode = switch (collaboratorManager.getMode()) {
            case BURP_COLLABORATOR -> "Burp Collaborator";
            case CUSTOM_OOB -> "Custom OOB (configure listener in UI)";
            case INTERACTSH -> "Interactsh (connect in UI)";
        };
        api.logging().logToOutput("Modules: " + registry.getAllModules().size()
                + " | OOB: " + oobMode);
        api.logging().logToOutput(
                "Configure target scope, then right-click a request and choose Send to OmniStrike.");
    }
}
