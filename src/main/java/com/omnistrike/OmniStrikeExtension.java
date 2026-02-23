package com.omnistrike;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.omnistrike.framework.*;
import com.omnistrike.model.ModuleConfig;
import com.omnistrike.modules.injection.*;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.modules.recon.*;
import com.omnistrike.ui.MainPanel;

import javax.swing.*;

/**
 * OmniStrike v1.15 — Entry Point
 *
 * A unified vulnerability scanning framework for Burp Suite with 20 modules:
 *   AI Analysis: AI Vulnerability Analyzer (Claude, Gemini, Codex, OpenCode CLI)
 *   Recon (Passive): Client-Side Analyzer, Endpoint Finder, Subdomain Collector, Security Header Analyzer
 *   Injection (Active): SQLi Detector, SSTI Scanner, SSRF Scanner, XSS Scanner,
 *       Command Injection, Deserialization Scanner, GraphQL Tool, XXE Scanner,
 *       CORS Misconfiguration, Cache Poisoning, Host Header Injection, Prototype Pollution, Path Traversal,
 *       CRLF Injection, HTTP Parameter Pollution
 *
 * Built exclusively on the Montoya API.
 */
public class OmniStrikeExtension implements BurpExtension {

    private ModuleRegistry registry;
    private FindingsStore findingsStore;
    private ActiveScanExecutor executor;
    private TrafficInterceptor interceptor;
    private CollaboratorManager collaboratorManager;
    private volatile MainPanel mainPanel;
    private volatile Audit persistentAudit;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OmniStrike");
        api.logging().logToOutput("=== OmniStrike v1.15 initializing ===");

        // Core framework components
        findingsStore = new FindingsStore();
        findingsStore.setErrorLogger(msg -> api.logging().logToError(msg));
        DashboardReporter dashboardReporter = new DashboardReporter(api);
        findingsStore.addListener(dashboardReporter); // Report all findings to Burp Dashboard
        DeduplicationStore dedup = new DeduplicationStore();
        executor = new ActiveScanExecutor(5);
        ScopeManager scopeManager = new ScopeManager();
        SharedDataBus dataBus = new SharedDataBus();
        registry = new ModuleRegistry();

        // Initialize Collaborator (Professional edition only)
        collaboratorManager = new CollaboratorManager(api);
        boolean collabAvailable = collaboratorManager.initialize();
        if (collabAvailable) {
            api.logging().logToOutput("Burp Collaborator: Available (Professional edition)");
        } else {
            api.logging().logToOutput("Burp Collaborator: Not available (Community edition or disabled)");
        }

        // ==================== REGISTER MODULES ====================

        // Recon modules (passive) — wire SharedDataBus for inter-module sharing
        HiddenEndpointFinder endpointFinder = new HiddenEndpointFinder();
        endpointFinder.setSharedDataBus(dataBus);
        registry.registerModule(endpointFinder);

        SubdomainCollector subdomainCollector = new SubdomainCollector();
        subdomainCollector.setSharedDataBus(dataBus);
        registry.registerModule(subdomainCollector);

        registry.registerModule(new SecurityHeaderAnalyzer());
        registry.registerModule(new ClientSideAnalyzer());

        // AI Vulnerability Analyzer (optional, disabled by default)
        AiVulnAnalyzer aiAnalyzer = new AiVulnAnalyzer();
        aiAnalyzer.setDependencies(findingsStore);
        aiAnalyzer.setModuleRegistry(registry);
        aiAnalyzer.setCollaboratorManager(collaboratorManager);
        registry.registerModuleDisabled(aiAnalyzer);

        // Injection modules (active) — wire dedup, findingsStore, collaborator to ALL
        SmartSqliDetector sqli = new SmartSqliDetector();
        sqli.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(sqli);

        SstiScanner ssti = new SstiScanner();
        ssti.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(ssti);

        SsrfScanner ssrf = new SsrfScanner();
        ssrf.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(ssrf);

        XssScanner xss = new XssScanner();
        xss.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(xss);

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

        CrlfInjectionScanner crlfInjection = new CrlfInjectionScanner();
        crlfInjection.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(crlfInjection);

        HttpParamPollutionScanner hpp = new HttpParamPollutionScanner();
        hpp.setDependencies(dedup, findingsStore, collaboratorManager);
        registry.registerModule(hpp);

        // Initialize all modules
        registry.initializeAll(api);
        api.logging().logToOutput("Registered " + registry.getAllModules().size() + " modules.");

        // ==================== TRAFFIC INTERCEPTOR ====================
        interceptor = new TrafficInterceptor(api, registry, findingsStore, executor, scopeManager);

        // Register with Burp's HTTP and proxy pipelines
        api.http().registerHttpHandler(interceptor);
        api.proxy().registerResponseHandler(interceptor);
        api.logging().logToOutput("Traffic interceptor registered.");

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
                            BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            dashboardReporter.setDashboardBridge(scanCheck, persistentAudit);
            api.logging().logToOutput("Persistent Dashboard task box created.");
        } catch (Exception e) {
            api.logging().logToOutput("Dashboard task box unavailable (findings still appear in Site Map): "
                    + e.getMessage());
        }

        // ==================== CONTEXT MENU ====================
        api.userInterface().registerContextMenuItemsProvider(
                new OmniStrikeContextMenu(api, registry, interceptor, scanCheck));
        api.logging().logToOutput("Context menu registered (right-click > Send to OmniStrike).");

        // ==================== UI ====================
        SwingUtilities.invokeLater(() -> {
            mainPanel = new MainPanel(
                    registry, findingsStore, scopeManager,
                    executor, interceptor, collaboratorManager, api);
            api.userInterface().registerSuiteTab("OmniStrike", mainPanel);
            api.logging().logToOutput("UI tab registered.");
        });

        // ==================== CLEANUP ON UNLOAD ====================
        final AiVulnAnalyzer aiRef = aiAnalyzer;
        api.extension().registerUnloadingHandler(() -> {
            try { api.logging().logToOutput("OmniStrike unloading..."); }
            catch (NullPointerException ignored) {}
            interceptor.setRunning(false);
            interceptor.shutdown(); // stop passive executor
            // Stop UI timers to prevent leaks
            if (mainPanel != null) {
                SwingUtilities.invokeLater(() -> mainPanel.stopTimers());
            }
            registry.destroyAll();
            executor.shutdown();
            if (collaboratorManager != null) {
                collaboratorManager.shutdown();
            }
            if (persistentAudit != null) {
                try { persistentAudit.delete(); } catch (Exception ignored) {}
            }
            try { api.logging().logToOutput("OmniStrike unloaded. Goodbye!"); }
            catch (NullPointerException ignored) {}
        });

        api.logging().logToOutput("=== OmniStrike v1.15 ready ===");
        api.logging().logToOutput("Modules: " + registry.getAllModules().size()
                + " | Collaborator: " + (collabAvailable ? "Yes" : "No"));
        api.logging().logToOutput("Configure target scope and click Start to begin scanning.");
    }
}
