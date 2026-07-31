package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.omnistrike.model.ScanModule;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.ui.ParameterScanDialog;

import com.omnistrike.framework.stepper.StepperEngine;
import com.omnistrike.framework.stepper.StepperStep;
import com.omnistrike.ui.MainPanel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Adds right-click context menu items in Burp's Proxy, Repeater, etc.
 *
 * New menu structure — each module has Normal Scan + AI Scan sub-options:
 *
 *   "Send to OmniStrike (All Modules)"     — runs all enabled non-AI modules
 *   "Send to OmniStrike >"
 *     Active Scanners (label)
 *       XSS Scanner >
 *         Normal Scan
 *         AI Scan >                          (only shown when AI is configured)
 *           Smart Fuzzing
 *           Smart Fuzzing + WAF Bypass
 *           Smart Fuzzing + Adaptive
 *           Full AI Scan
 *       SQLi Detector >
 *         Normal Scan
 *         AI Scan >
 *           ...
 *     ─────────────────
 *     Passive Analyzers (label)
 *       Client-Side Analyzer >
 *         Normal Scan
 *         AI Scan                            (single item — passive analysis only, no fuzzing)
 *       Security Header Analyzer >
 *         Normal Scan
 *         AI Scan
 *   ─────────────────
 *   "Stop OmniStrike Scans"
 */
public class OmniStrikeContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ModuleRegistry registry;
    private final TrafficInterceptor interceptor;
    private final SessionKeepAlive sessionKeepAlive;
    private final StepperEngine stepperEngine;
    private volatile Supplier<MainPanel> mainPanelSupplier;

    // Modules excluded from manual right-click scanning: WS scanner (own panel),
    // auto-triggered tech-specific scanners, and the passive wordlist harvester.
    private static final Set<String> MANUAL_SCAN_EXCLUDED = Set.of(
            "ws-scanner",
            "dynamics365-scanner", "sap-odata-scanner", "salesforce-soql-scanner",
            "firebase-misconfig-scanner", "sharepoint-caml-scanner", "servicenow-glide-scanner",
            "solr-query-scanner", "odoo-domain-scanner", "elasticsearch-query-scanner",
            "spring-actuator-scanner", "wordlist-generator"
    );

    // Static file extensions where active injection testing is pointless
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".mjs", ".jsx", ".ts", ".map",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".mp3", ".webm", ".pdf"
    );

    public OmniStrikeContextMenu(MontoyaApi api, ModuleRegistry registry,
                                  TrafficInterceptor interceptor,
                                  SessionKeepAlive sessionKeepAlive,
                                  StepperEngine stepperEngine) {
        this.api = api;
        this.registry = registry;
        this.interceptor = interceptor;
        this.sessionKeepAlive = sessionKeepAlive;
        this.stepperEngine = stepperEngine;
    }

    public void setMainPanelSupplier(Supplier<MainPanel> supplier) {
        this.mainPanelSupplier = supplier;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Get the selected request/response
        HttpRequestResponse reqResp = getSelectedRequestResponse(event);
        if (reqResp == null || reqResp.request() == null) {
            return items;
        }

        String url = PrivacyManager.maskForDisplay(truncate(reqResp.request().url(), 60));

        // Look up AI analyzer (may be null or unconfigured)
        AiVulnAnalyzer aiAnalyzer = findAiAnalyzer();
        boolean aiAvailable = aiAnalyzer != null && aiAnalyzer.isAiConfigured();

        // ============ "Send to OmniStrike (All Modules)" — opens parameter/module picker ============
        boolean staticResource = isStaticResource(reqResp.request().url());
        JMenuItem scanAll = new JMenuItem("Send to OmniStrike (All Modules)");
        scanAll.setToolTipText("Pick which parameters and modules to scan");
        scanAll.addActionListener(e -> {
            List<ScanModule> activeMods = new ArrayList<>();
            List<ScanModule> passiveMods = new ArrayList<>();
            collectScannableModules(activeMods, passiveMods);

            // Static resource (JS, CSS, images): active injection is pointless —
            // run passive analyzers directly over the whole response, no dialog.
            if (staticResource) {
                List<String> passiveIds = new ArrayList<>();
                for (ScanModule m : passiveMods) passiveIds.add(m.getId());
                if (passiveIds.isEmpty()) {
                    showToast("OmniStrike", "No passive analyzers enabled.");
                    return;
                }
                interceptor.scanRequest(reqResp, passiveIds);
                showToast("Sent to OmniStrike",
                        "Static resource — scanning with " + passiveIds.size()
                        + " passive analyzer(s)\n" + url);
                return;
            }

            List<ParameterScanDialog.ParamItem> paramItems = collectParamItems(reqResp);

            // No parameters to target — fall back to a whole-request scan with all modules.
            if (paramItems.isEmpty()) {
                List<String> ids = new ArrayList<>();
                for (ScanModule m : activeMods) ids.add(m.getId());
                for (ScanModule m : passiveMods) ids.add(m.getId());
                if (ids.isEmpty()) { showToast("OmniStrike", "No modules enabled."); return; }
                interceptor.scanRequest(reqResp, ids);
                showToast("Sent to OmniStrike",
                        "No parameters found — scanning whole request with "
                        + ids.size() + " module(s)\n" + url);
                return;
            }

            // Open the picker so the user ticks the exact parameters + modules to scan.
            ParameterScanDialog dialog = new ParameterScanDialog(
                    findVisibleFrame(), reqResp, paramItems, activeMods, passiveMods);
            dialog.setVisible(true); // modal — blocks until closed

            if (!dialog.isConfirmed()) return;

            List<String> selParams = dialog.getSelectedParameters();
            List<String> selActive = dialog.getSelectedActiveModuleIds();
            List<String> selPassive = dialog.getSelectedPassiveModuleIds();

            if (selActive.isEmpty() && selPassive.isEmpty()) {
                showToast("OmniStrike", "No modules selected — nothing scanned.");
                return;
            }
            if (!selActive.isEmpty() && selParams.isEmpty() && selPassive.isEmpty()) {
                showToast("OmniStrike", "No parameters selected for the active scanners.");
                return;
            }

            interceptor.scanRequestParameters(reqResp, selActive, selPassive, selParams);
            showToast("Sent to OmniStrike",
                    "Scanning " + selParams.size() + " parameter(s) with "
                    + selActive.size() + " active + " + selPassive.size() + " passive module(s)\n"
                    + url
                    + "\n\nResults will appear in Dashboard and OmniStrike tab.");
        });
        items.add(scanAll);

        // ============ "Queue for AI Batch Scan" — adds selected request(s) to batch queue ============
        if (aiAvailable) {
            int currentQueueSize = aiAnalyzer.getBatchQueueSize();
            String batchLabel = currentQueueSize > 0
                    ? "Queue for AI Batch Scan (" + currentQueueSize + " queued)"
                    : "Queue for AI Batch Scan";

            // Get ALL selected requests (multi-select support)
            List<HttpRequestResponse> allSelected = event.selectedRequestResponses();
            int selectCount = allSelected.isEmpty() ? 1 : allSelected.size();

            JMenuItem batchItem = new JMenuItem(batchLabel);
            batchItem.setToolTipText("Add " + selectCount + " request(s) to the batch queue for cross-file AI analysis");
            batchItem.addActionListener(e -> {
                int newSize;
                if (!allSelected.isEmpty()) {
                    newSize = aiAnalyzer.addAllToBatchQueue(allSelected);
                } else {
                    newSize = aiAnalyzer.addToBatchQueue(reqResp);
                }
                int added = !allSelected.isEmpty() ? allSelected.size() : 1;
                showToast("Batch Queue",
                        added + " request(s) added to batch queue\n"
                        + newSize + " total file(s) queued\n\n"
                        + "Run the batch scan from the AI Module tab.");
            });
            items.add(batchItem);

            // "Clear Batch Queue" — only shown when queue is non-empty
            if (currentQueueSize > 0) {
                JMenuItem clearBatchItem = new JMenuItem("Clear Batch Queue (" + currentQueueSize + ")");
                clearBatchItem.addActionListener(e -> {
                    aiAnalyzer.clearBatchQueue();
                    showToast("Batch Queue", "Batch queue cleared.");
                });
                items.add(clearBatchItem);
            }
        }

        // ============ "AI Scan (Custom Prompt)" — user enters their own prompt ============
        if (aiAvailable) {
            JMenuItem customPromptItem = new JMenuItem("AI Scan (Custom Prompt)");
            customPromptItem.setToolTipText("Enter your own prompt for the AI to analyze this request");
            customPromptItem.addActionListener(e -> {
                // Build a dialog with a JTextArea for multi-line prompt input
                JTextArea promptArea = new JTextArea(8, 50);
                promptArea.setLineWrap(true);
                promptArea.setWrapStyleWord(true);
                promptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
                promptArea.setText("Enter your prompt here. Example: Look for authentication bypass vulnerabilities and insecure direct object references.");
                promptArea.selectAll();
                JScrollPane scrollPane = new JScrollPane(promptArea);
                scrollPane.setPreferredSize(new java.awt.Dimension(500, 200));

                JPanel panel = new JPanel(new BorderLayout(0, 8));
                panel.add(new JLabel("<html>Enter your prompt for AI analysis of:<br><b>"
                        + PrivacyManager.maskForDisplay(truncate(reqResp.request().url(), 80))
                        + "</b></html>"), BorderLayout.NORTH);
                panel.add(scrollPane, BorderLayout.CENTER);
                panel.add(new JLabel("<html><i>The HTTP request/response will be appended automatically. "
                        + "Findings appear in Dashboard & OmniStrike tab.</i></html>"), BorderLayout.SOUTH);

                int result = JOptionPane.showConfirmDialog(null, panel,
                        "OmniStrike — Custom AI Prompt", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (result == JOptionPane.OK_OPTION) {
                    String userPrompt = promptArea.getText();
                    if (userPrompt != null && !userPrompt.isBlank()) {
                        aiAnalyzer.manualScanCustomPrompt(reqResp, userPrompt.trim());
                        showToast("AI Custom Prompt",
                                "Custom AI analysis started\n" + url
                                + "\n\nResults will appear in Dashboard and OmniStrike tab.");
                    }
                }
            });
            items.add(customPromptItem);
        }

        // WebSocket Scanner removed
        // TLS analysis is available via the TLS Analyzer panel (Framework Tools) — no context menu item.

        // ============ Module lists for the "Send to OmniStrike >" per-module submenu ============
        // (Per-parameter scanning now lives in the ParameterScanDialog opened from
        //  "Send to OmniStrike (All Modules)".)
        List<ScanModule> activeModulesAll = new ArrayList<>();
        List<ScanModule> passiveModulesAll = new ArrayList<>();
        collectScannableModules(activeModulesAll, passiveModulesAll);

        // ============ "Send to OmniStrike >" submenu — per-module with Normal/AI options ============
        JMenu subMenu = new JMenu("Send to OmniStrike");

        // Group: Active Scanners
        if (!activeModulesAll.isEmpty()) {
            subMenu.add(createSectionLabel("Active Scanners"));
            for (ScanModule module : activeModulesAll) {
                subMenu.add(buildModuleMenu(module, reqResp, url, aiAnalyzer, aiAvailable));
            }
        }

        // Group: Passive Analyzers
        if (!passiveModulesAll.isEmpty()) {
            if (!activeModulesAll.isEmpty()) subMenu.addSeparator();
            subMenu.add(createSectionLabel("Passive Analyzers"));
            for (ScanModule module : passiveModulesAll) {
                subMenu.add(buildModuleMenu(module, reqResp, url, aiAnalyzer, aiAvailable));
            }
        }

        if (subMenu.getItemCount() > 0) {
            items.add(subMenu);
        }

        // ============ Send to Stepper (only when Stepper is enabled) ============
        if (stepperEngine != null && stepperEngine.isEnabled()) {
            items.add(new JSeparator());
            int stepCount = stepperEngine.getStepCount();
            String stepLabel = stepCount > 0
                    ? "Send to Stepper (" + stepCount + " steps)"
                    : "Send to Stepper";
            JMenuItem stepperItem = new JMenuItem(stepLabel);
            stepperItem.setToolTipText("Add this request as a prerequisite step in the Stepper chain");
            stepperItem.addActionListener(e -> {
                String defaultName = "Step " + (stepperEngine.getStepCount() + 1);
                String name = JOptionPane.showInputDialog(null,
                        "Step name:", defaultName);
                if (name == null || name.isBlank()) return;
                StepperStep step = new StepperStep(name.trim(), reqResp.request());
                stepperEngine.addStep(step);

                // Switch to Stepper panel in the UI
                MainPanel mp = mainPanelSupplier != null ? mainPanelSupplier.get() : null;
                if (mp != null) {
                    mp.selectModule("stepper");
                }
                showToast("Stepper", "Added step: " + name.trim()
                        + "\n" + PrivacyManager.maskForDisplay(truncate(reqResp.request().url(), 60))
                        + "\n\nConfigure extraction rules in the Stepper panel.");
            });
            items.add(stepperItem);
        }

        // ============ Session Keep-Alive ============
        items.add(new JSeparator());

        // "Set as Session Login Request" — retains the selected request in memory for replay
        JMenuItem setLoginItem = new JMenuItem("Set as Session Login Request");
        setLoginItem.setToolTipText("Keep this request in memory for periodic replay (cleared on restart)");
        setLoginItem.addActionListener(e -> {
            sessionKeepAlive.setLoginRequest(reqResp);
            showToast("Session Keep-Alive",
                    "Login request kept in memory:\n" + url
                    + "\n\nEnable 'Session Keep-Alive' in the OmniStrike tab to start.");
        });
        items.add(setLoginItem);

        // "Clear Session Login Request" — only shown when a login request is set
        if (sessionKeepAlive.hasLoginRequest()) {
            JMenuItem clearLoginItem = new JMenuItem("Clear Session Login Request");
            clearLoginItem.setToolTipText("Remove the saved login request and stop session refresh");
            clearLoginItem.addActionListener(e -> {
                sessionKeepAlive.clearLoginRequest();
                showToast("Session Keep-Alive", "Login request cleared. Session refresh stopped.");
            });
            items.add(clearLoginItem);
        }

        // ============ "Stop OmniStrike Scans" ============
        int running = interceptor.getManualScanCount();
        if (running > 0) {
            items.add(new JSeparator());
            JMenuItem stopItem = new JMenuItem("Stop OmniStrike Scans (" + running + " running)");
            stopItem.addActionListener(e -> {
                int stopped = interceptor.stopManualScans();
                showToast("Scans Stopped", "Stopped " + stopped + " scan task(s).");
            });
            items.add(stopItem);
        }

        return items;
    }

    // ==================== Per-Module Submenu Builder ====================

    /**
     * Builds a submenu for a single module:
     *
     * Active modules:
     *   Module Name >
     *     Normal Scan
     *     AI Scan >              (only when AI is configured)
     *       Smart Fuzzing
     *       Smart Fuzzing + WAF Bypass
     *       Smart Fuzzing + Adaptive
     *       Full AI Scan
     *
     * Passive modules (e.g., Client-Side Analyzer):
     *   Module Name >
     *     Normal Scan
     *     AI Scan                (single item — passive analysis only, no fuzzing/WAF bypass)
     */
    private JMenu buildModuleMenu(ScanModule module, HttpRequestResponse reqResp,
                                   String url, AiVulnAnalyzer aiAnalyzer, boolean aiAvailable) {
        final String moduleName = module.getName();
        final String moduleId = module.getId();
        boolean isStatic = isStaticResource(reqResp.request().url());

        JMenu moduleMenu = new JMenu(moduleName);
        moduleMenu.setToolTipText(module.getDescription());

        // --- Normal Scan ---
        JMenuItem normalItem = new JMenuItem("Normal Scan");
        normalItem.setToolTipText("Run " + moduleName + " (no AI)");
        normalItem.addActionListener(e -> {
            // Run module directly via interceptor thread pool
            interceptor.scanRequest(reqResp, List.of(moduleId));
            showToast(moduleName,
                    "Normal scan started\n" + url);
        });
        moduleMenu.add(normalItem);

        // --- AI Scan (only when AI is configured) ---
        if (aiAvailable) {
            if (module.isPassive()) {
                // Passive modules: single "AI Scan" item — AI analyzes the response JS/HTML code,
                // no fuzzing, WAF bypass, or adaptive testing (those are for active injection modules)
                JMenuItem aiItem = new JMenuItem("AI Scan");
                aiItem.setToolTipText("AI analyzes response body for " + moduleName + " findings");
                aiItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, false, false, false, moduleId);
                    showToast(moduleName + " + AI",
                            "AI analysis started\n" + url);
                });
                moduleMenu.add(aiItem);
            } else {
                // Active modules: full AI submenu with fuzzing options
                JMenu aiMenu = new JMenu("AI Scan");
                aiMenu.setToolTipText("AI-powered scanning for " + moduleName);

                // Smart Fuzzing
                JMenuItem fuzzItem = new JMenuItem("Smart Fuzzing");
                fuzzItem.setToolTipText("AI generates targeted payloads (active)");
                fuzzItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, false, false, moduleId);
                    showToast(moduleName + " + AI",
                            "AI smart fuzzing started\n" + url);
                });
                aiMenu.add(fuzzItem);

                // Smart Fuzzing + WAF Bypass
                JMenuItem wafItem = new JMenuItem("Smart Fuzzing + WAF Bypass");
                wafItem.setToolTipText("AI fuzzing with WAF evasion when payloads are blocked");
                wafItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, true, false, moduleId);
                    showToast(moduleName + " + AI + WAF Bypass",
                            "AI fuzzing with WAF bypass started\n" + url);
                });
                aiMenu.add(wafItem);

                // Smart Fuzzing + Adaptive
                JMenuItem adaptiveItem = new JMenuItem("Smart Fuzzing + Adaptive");
                adaptiveItem.setToolTipText("AI fuzzing with multi-round adaptive testing");
                adaptiveItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, false, true, moduleId);
                    showToast(moduleName + " + AI + Adaptive",
                            "AI adaptive fuzzing started\n" + url);
                });
                aiMenu.add(adaptiveItem);

                aiMenu.addSeparator();

                // Full AI Scan (all capabilities)
                JMenuItem fullItem = new JMenuItem("Full AI Scan");
                fullItem.setToolTipText("Passive analysis + smart fuzzing + WAF bypass + adaptive");
                fullItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, true, true, moduleId);
                    showToast(moduleName + " + Full AI",
                            "Full AI scan started\n" + url);
                });
                aiMenu.add(fullItem);

                moduleMenu.add(aiMenu);
            }
        }

        return moduleMenu;
    }

    // Common route words to skip when extracting path segment targets for the context menu
    private static final Set<String> COMMON_ROUTE_WORDS = Set.of(
            "api", "v1", "v2", "v3", "v4", "search", "users", "admin", "static", "assets",
            "css", "js", "img", "public", "login", "logout", "register", "profile",
            "settings", "dashboard", "results", "page", "index", "home", "about",
            "contact", "auth", "oauth", "callback", "webhook", "health", "status",
            "docs", "help", "faq", "terms", "privacy", "legal", "blog", "news",
            "feed", "rss", "sitemap", "robots", "favicon", "manifest"
    );

    /**
     * Extracts testable URL path segments from the request URL.
     * Adds names in "path:INDEX:VALUE" format matching what the scanners use internally.
     */
    private void extractPathSegmentNames(HttpRequest request, LinkedHashSet<String> targets) {
        try {
            String urlStr = request.url();
            // Extract path portion
            String path = urlStr;
            if (path.contains("://")) path = path.substring(path.indexOf("://") + 3);
            int slashIdx = path.indexOf('/');
            if (slashIdx < 0) return;
            int queryIdx = path.indexOf('?', slashIdx);
            path = queryIdx >= 0 ? path.substring(slashIdx, queryIdx) : path.substring(slashIdx);

            if (path.length() < 2) return;

            String[] segments = path.split("/");
            for (int i = 0; i < segments.length; i++) {
                String segment = segments[i].trim();
                if (segment.isEmpty()) continue;

                // Skip common route words
                if (COMMON_ROUTE_WORDS.contains(segment.toLowerCase())) continue;

                // Skip very short purely-alpha segments
                if (segment.matches("^[a-z]+$") && segment.length() < 4) continue;

                // Skip static file extensions
                if (segment.matches(".*\\.(css|js|png|jpg|gif|svg|ico|woff|woff2|ttf|map|html)$")) continue;

                // Include: numeric IDs, UUIDs, alphanumeric identifiers, filenames
                boolean isNumeric = segment.matches("^\\d+$");
                boolean isUuid = segment.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
                boolean isAlphanumericId = segment.matches("^[a-zA-Z0-9_-]+$") && segment.length() >= 3;
                boolean hasFileExtension = segment.matches(".*\\.[a-zA-Z0-9]{1,5}$");

                if (isNumeric || isUuid || isAlphanumericId || hasFileExtension) {
                    targets.add("path:" + i + ":" + segment);
                }
            }
        } catch (Exception ignored) {}
    }

    // ==================== Manual-scan collection ====================

    /**
     * Fills the given lists with the non-AI modules eligible for manual scanning,
     * split into active and passive. Skips {@link #MANUAL_SCAN_EXCLUDED} modules
     * (WS scanner, auto-triggered tech scanners, passive wordlist harvester).
     */
    private void collectScannableModules(List<ScanModule> activeOut, List<ScanModule> passiveOut) {
        for (ScanModule m : registry.getEnabledManualScanModules()) {
            if (MANUAL_SCAN_EXCLUDED.contains(m.getId())) continue;
            if (m.isPassive()) passiveOut.add(m);
            else activeOut.add(m);
        }
    }

    /**
     * Collects every scannable parameter target for the request: query/body/cookie
     * parameters, parameters embedded in Referer/Origin URLs, injectable header
     * names, and testable URL path segments. Each item carries the internal name
     * passed to scanners plus a friendly display name and a category for grouping.
     */
    private List<ParameterScanDialog.ParamItem> collectParamItems(HttpRequestResponse reqResp) {
        List<ParameterScanDialog.ParamItem> out = new ArrayList<>();
        LinkedHashSet<String> paramNames = new LinkedHashSet<>();

        // Query / body / cookie / JSON params parsed by Burp
        for (ParsedHttpParameter param : reqResp.request().parameters()) {
            paramNames.add(param.name());
        }

        // Params embedded in Referer/Origin URLs (e.g. Referer: https://x/?id=q22&Submit=Submit)
        for (var header : reqResp.request().headers()) {
            String hName = header.name().toLowerCase();
            if (hName.equals("referer") || hName.equals("origin")) {
                String hVal = header.value();
                int qMark = hVal.indexOf('?');
                if (qMark >= 0) {
                    String query = hVal.substring(qMark + 1);
                    int hashIdx = query.indexOf('#');
                    if (hashIdx >= 0) query = query.substring(0, hashIdx);
                    for (String pair : query.split("&")) {
                        int eq = pair.indexOf('=');
                        String key = (eq > 0 ? pair.substring(0, eq) : pair).trim();
                        if (!key.isEmpty()) paramNames.add(key);
                    }
                }
            }
        }
        for (String name : paramNames) {
            out.add(new ParameterScanDialog.ParamItem(name, name, "Parameters"));
        }

        // Injectable header names (header injection testing)
        Set<String> injectableHeaderNames = Set.of("referer", "user-agent", "x-forwarded-for",
                "x-forwarded-host", "origin", "host", "x-real-ip", "x-custom-ip-authorization");
        LinkedHashSet<String> headerTargets = new LinkedHashSet<>();
        for (var header : reqResp.request().headers()) {
            if (injectableHeaderNames.contains(header.name().toLowerCase())) {
                headerTargets.add(header.name());
            }
        }
        for (String h : headerTargets) {
            out.add(new ParameterScanDialog.ParamItem(h, h, "Headers"));
        }

        // Testable URL path segments (internal name "path:N:value", display = value)
        LinkedHashSet<String> pathSegmentTargets = new LinkedHashSet<>();
        extractPathSegmentNames(reqResp.request(), pathSegmentTargets);
        for (String pathTarget : pathSegmentTargets) {
            String displayName = pathTarget.contains(":")
                    ? pathTarget.substring(pathTarget.lastIndexOf(':') + 1) : pathTarget;
            out.add(new ParameterScanDialog.ParamItem(pathTarget, displayName, "Path Segments"));
        }

        return out;
    }

    /** Returns the first visible AWT frame to parent dialogs to, or null. */
    private Frame findVisibleFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible()) return f;
        }
        return null;
    }

    // ==================== Helpers ====================

    /**
     * Finds the AiVulnAnalyzer module instance from the registry, or null if not registered.
     */
    private AiVulnAnalyzer findAiAnalyzer() {
        ScanModule module = registry.getModule(ModuleRegistry.AI_MODULE_ID);
        if (module instanceof AiVulnAnalyzer ai) {
            return ai;
        }
        return null;
    }


    /**
     * Shows a brief auto-dismissing toast notification.
     */
    private void showToast(String title, String message) {
        SwingUtilities.invokeLater(() -> {
            Frame parentFrame = null;
            for (Frame f : Frame.getFrames()) {
                if (f.isVisible() && f.getTitle() != null && f.getTitle().contains("Burp")) {
                    parentFrame = f;
                    break;
                }
            }
            if (parentFrame == null) {
                for (Frame f : Frame.getFrames()) {
                    if (f.isVisible()) {
                        parentFrame = f;
                        break;
                    }
                }
            }

            JPanel toast = new JPanel(new BorderLayout(8, 4));
            toast.setBackground(new Color(30, 30, 30));
            toast.setBorder(BorderFactory.createCompoundBorder(
                    new com.omnistrike.ui.CyberTheme.GlowLineBorder(new Color(80, 80, 80), 1),
                    BorderFactory.createEmptyBorder(12, 16, 12, 16)));

            JLabel titleLabel = new JLabel(title);
            titleLabel.setForeground(new Color(100, 200, 100));
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
            toast.add(titleLabel, BorderLayout.NORTH);

            JTextArea msgArea = new JTextArea(message);
            msgArea.setForeground(new Color(220, 220, 220));
            msgArea.setBackground(new Color(30, 30, 30));
            msgArea.setFont(msgArea.getFont().deriveFont(Font.PLAIN, 11f));
            msgArea.setEditable(false);
            msgArea.setLineWrap(true);
            msgArea.setWrapStyleWord(true);
            msgArea.setOpaque(false);
            toast.add(msgArea, BorderLayout.CENTER);

            JDialog dialog = new JDialog(parentFrame, false);
            dialog.setUndecorated(true);
            dialog.setContentPane(toast);
            dialog.pack();

            int width = Math.min(dialog.getWidth(), 380);
            dialog.setSize(width, dialog.getHeight());

            if (parentFrame != null) {
                Rectangle bounds = parentFrame.getBounds();
                int x = bounds.x + bounds.width - width - 20;
                int y = bounds.y + bounds.height - dialog.getHeight() - 60;
                dialog.setLocation(x, y);
            }

            dialog.setAlwaysOnTop(true);
            dialog.setVisible(true);

            Timer dismissTimer = new Timer(3000, ev -> {
                dialog.setVisible(false);
                dialog.dispose();
            });
            dismissTimer.setRepeats(false);
            dismissTimer.start();

            toast.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent ev) {
                    dismissTimer.stop();
                    dialog.setVisible(false);
                    dialog.dispose();
                }
            });
        });
    }

    /**
     * Extracts the selected HttpRequestResponse from the context menu event.
     */
    private HttpRequestResponse getSelectedRequestResponse(ContextMenuEvent event) {
        var editorReqRes = event.messageEditorRequestResponse();
        if (editorReqRes.isPresent()) {
            return editorReqRes.get().requestResponse();
        }

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (!selected.isEmpty()) {
            return selected.get(0);
        }

        return null;
    }

    private JMenuItem createSectionLabel(String text) {
        JMenuItem label = new JMenuItem(text);
        label.setEnabled(false);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        return label;
    }

    /**
     * Checks if a URL points to a static resource (JS, CSS, HTML, images, fonts, etc.)
     * where active injection testing is pointless.
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

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

}
