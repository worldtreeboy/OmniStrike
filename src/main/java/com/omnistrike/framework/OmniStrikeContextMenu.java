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
import com.omnistrike.modules.exploit.omnimap.OmniMapModule;
import com.omnistrike.ui.OmniMapConfigDialog;
import com.omnistrike.ui.ScanConfigDialog;

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
    private final OmniStrikeScanCheck scanCheck;
    private final SessionKeepAlive sessionKeepAlive;
    private volatile Supplier<MainPanel> mainPanelSupplier;

    // Static file extensions where active injection testing is pointless
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".css", ".js", ".mjs", ".jsx", ".ts", ".map",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".mp3", ".webm", ".pdf"
    );

    public OmniStrikeContextMenu(MontoyaApi api, ModuleRegistry registry,
                                  TrafficInterceptor interceptor,
                                  OmniStrikeScanCheck scanCheck,
                                  SessionKeepAlive sessionKeepAlive) {
        this.api = api;
        this.registry = registry;
        this.interceptor = interceptor;
        this.scanCheck = scanCheck;
        this.sessionKeepAlive = sessionKeepAlive;
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

        String url = truncate(reqResp.request().url(), 60);

        // Look up AI analyzer (may be null or unconfigured)
        AiVulnAnalyzer aiAnalyzer = findAiAnalyzer();
        boolean aiAvailable = aiAnalyzer != null && aiAnalyzer.isAiConfigured();

        // ============ "Send to OmniStrike (All Modules)" — runs all non-AI modules ============
        boolean staticResource = isStaticResource(reqResp.request().url());
        JMenuItem scanAll = new JMenuItem("Send to OmniStrike (All Modules)");
        scanAll.addActionListener(e -> {
            List<ScanModule> nonAi = registry.getEnabledNonAiModules();
            List<String> moduleIds = new ArrayList<>();
            int passive = 0, active = 0;

            if (staticResource) {
                // Static resource (JS, CSS, HTML, etc.) — only run passive analyzers.
                // Active injection scanners (SQLi, XSS, etc.) are pointless against static file URLs.
                for (ScanModule m : nonAi) {
                    if ("ws-scanner".equals(m.getId())) continue; // WS scanner has its own panel
                    if ("omnimap-exploiter".equals(m.getId())) continue; // OmniMap uses its own dialog
                    if (m.isPassive()) {
                        moduleIds.add(m.getId());
                        passive++;
                    }
                }
            } else {
                for (ScanModule m : nonAi) {
                    if ("ws-scanner".equals(m.getId())) continue; // WS scanner has its own panel
                    if ("omnimap-exploiter".equals(m.getId())) continue; // OmniMap uses its own dialog
                    moduleIds.add(m.getId());
                    if (m.isPassive()) passive++;
                    else active++;
                }
            }
            int total = passive + active;

            // Run modules directly via the interceptor's thread pool.
            // Previously this used scanCheck.queueForScan() + startAuditSafe(), which
            // relied on Burp's scanner calling passiveAudit() — but Burp's scanner queue
            // is unreliable and the URL matching is fragile. Direct execution is instant.
            // Findings still appear in Dashboard via DashboardReporter.
            interceptor.scanRequest(reqResp, moduleIds);

            String staticNote = staticResource
                    ? "\n(Static resource — active scanners skipped)" : "";
            showToast("Sent to OmniStrike",
                    "Scanning with " + total + " module(s) (" + active + " active, " + passive + " passive)\n"
                    + url + staticNote
                    + "\n\nResults will appear in Dashboard and OmniStrike tab.");
        });
        items.add(scanAll);

        // ============ "Send to OmniStrike (Custom)" — opens config dialog ============
        JMenuItem scanCustom = new JMenuItem("Send to OmniStrike (Custom)");
        scanCustom.setToolTipText("Choose modules and configure settings before scanning");
        scanCustom.addActionListener(e -> {
            Frame parentFrame = null;
            for (Frame f : Frame.getFrames()) {
                if (f.isVisible()) { parentFrame = f; break; }
            }
            ScanConfigDialog dialog = new ScanConfigDialog(
                    parentFrame, registry, api, reqResp, interceptor, scanCheck);
            dialog.setVisible(true); // blocks until closed (modal)

            if (dialog.isConfirmed()) {
                List<String> selectedIds = dialog.getSelectedModuleIds();
                if (selectedIds.isEmpty()) {
                    showToast("Custom Scan", "No modules selected.");
                    return;
                }

                // Separate AI module from the rest — AI needs manualScan(), not processHttpFlow()
                boolean aiSelected = selectedIds.remove(ModuleRegistry.AI_MODULE_ID);
                List<String> nonAiIds = selectedIds;

                // Run non-AI modules directly via interceptor thread pool
                if (!nonAiIds.isEmpty()) {
                    interceptor.scanRequest(reqResp, nonAiIds);
                }

                // Run AI analysis via manualScan() if AI was selected
                if (aiSelected && aiAnalyzer != null && aiAvailable) {
                    if (nonAiIds.size() == 1) {
                        // Single non-AI module: focused AI analysis on that module type
                        aiAnalyzer.manualScan(reqResp, true, false, false, false, nonAiIds.get(0));
                    } else {
                        // Multiple modules or AI alone: general AI analysis
                        aiAnalyzer.manualScan(reqResp, true, false, false, false, null);
                    }
                }

                int totalCount = nonAiIds.size() + (aiSelected ? 1 : 0);
                String aiNote = aiSelected ? "\nAI analysis: enabled" : "";
                showToast("Custom Scan",
                        "Scanning with " + totalCount + " module(s)\n" + url
                        + aiNote
                        + "\n\nResults will appear in Dashboard and OmniStrike tab.");
            }
        });
        items.add(scanCustom);

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

        // ============ "Open WebSocket Scanner" — switch to WS Scanner panel ============
        {
            Supplier<MainPanel> supplier = mainPanelSupplier;
            if (supplier != null) {
                JMenuItem wsItem = new JMenuItem("Open WebSocket Scanner");
                wsItem.setToolTipText("Open the WebSocket Scanner panel for passive analysis and active fuzzing");
                wsItem.addActionListener(e -> {
                    MainPanel panel = supplier.get();
                    if (panel == null) return;
                    panel.selectModule("ws-scanner");
                });
                items.add(wsItem);
            }
        }

        // ============ "Send to OmniMap" — SQL injection exploitation ============
        {
            Supplier<MainPanel> supplier = mainPanelSupplier;
            JMenuItem omniMapItem = new JMenuItem("Send to OmniMap");
            omniMapItem.setToolTipText("OmniMap — high-speed sqlmap variant: extract databases, tables, and data via SQL injection");
            omniMapItem.addActionListener(e -> {
                Frame parentFrame = null;
                for (Frame f : Frame.getFrames()) {
                    if (f.isVisible()) { parentFrame = f; break; }
                }
                OmniMapConfigDialog dialog = new OmniMapConfigDialog(parentFrame, reqResp, api);
                dialog.setVisible(true);
                if (dialog.isConfirmed()) {
                    ScanModule mod = registry.getModule("omnimap-exploiter");
                    if (mod instanceof OmniMapModule omniMapMod) {
                        omniMapMod.exploit(reqResp, dialog.getConfig());
                        if (supplier != null) {
                            MainPanel mp = supplier.get();
                            if (mp != null) mp.selectModule("omnimap-exploiter");
                        }
                        showToast("OmniMap",
                                "Exploitation started on parameter '" + dialog.getConfig().getParameterName() + "'\n"
                                + truncate(reqResp.request().url(), 60)
                                + "\n\nOther scans paused for priority. Results in OmniMap panel.");
                    }
                }
            });
            items.add(omniMapItem);
        }

        // ============ "Scan This Parameter" — targeted parameter scanning ============
        // Build module lists early (needed for both parameter menu and per-module submenu)
        // Exclude ws-scanner — it doesn't process HTTP flows (uses its own WS interceptor)
        List<ScanModule> activeModules = new ArrayList<>();
        List<ScanModule> passiveModules = new ArrayList<>();
        for (ScanModule m : registry.getEnabledNonAiModules()) {
            if ("ws-scanner".equals(m.getId())) continue; // WS scanner has its own panel
            if ("omnimap-exploiter".equals(m.getId())) continue; // OmniMap uses its own dialog
            if (m.isPassive()) {
                passiveModules.add(m);
            } else {
                activeModules.add(m);
            }
        }

        String selectedParam = detectSelectedParameter(event);
        if (selectedParam != null && !staticResource) {
            // "Scan This Parameter (ip) — All Modules"
            JMenuItem scanParamAll = new JMenuItem("Scan This Parameter (" + selectedParam + ") \u2014 All Modules");
            scanParamAll.addActionListener(e -> {
                List<String> moduleIds = new ArrayList<>();
                for (ScanModule m : activeModules) {
                    moduleIds.add(m.getId());
                }
                interceptor.scanRequest(reqResp, moduleIds, selectedParam);
                showToast("Parameter Scan",
                        "Scanning parameter '" + selectedParam + "' with " + moduleIds.size() + " active module(s)\n"
                        + url
                        + "\n\nResults will appear in Dashboard and OmniStrike tab.");
            });
            items.add(scanParamAll);

            // "Scan This Parameter (ip) >" — per-module submenu (active modules only)
            JMenu paramSubMenu = new JMenu("Scan This Parameter (" + selectedParam + ")");
            for (ScanModule module : activeModules) {
                JMenu moduleParamMenu = new JMenu(module.getName());
                moduleParamMenu.setToolTipText(module.getDescription());

                // Normal Scan (parameter-targeted)
                JMenuItem normalItem = new JMenuItem("Normal Scan");
                normalItem.addActionListener(e -> {
                    interceptor.scanRequest(reqResp, List.of(module.getId()), selectedParam);
                    showToast(module.getName(),
                            "Scanning parameter '" + selectedParam + "'\n" + url);
                });
                moduleParamMenu.add(normalItem);

                // AI Scan options (parameter-targeted)
                if (aiAvailable) {
                    JMenu aiMenu = new JMenu("AI Scan");

                    JMenuItem fuzzItem = new JMenuItem("Smart Fuzzing");
                    fuzzItem.addActionListener(e -> {
                        aiAnalyzer.manualScan(reqResp, true, true, false, false, module.getId(), selectedParam);
                        showToast(module.getName() + " + AI",
                                "AI smart fuzzing parameter '" + selectedParam + "'\n" + url);
                    });
                    aiMenu.add(fuzzItem);

                    JMenuItem wafItem = new JMenuItem("Smart Fuzzing + WAF Bypass");
                    wafItem.addActionListener(e -> {
                        aiAnalyzer.manualScan(reqResp, true, true, true, false, module.getId(), selectedParam);
                        showToast(module.getName() + " + AI + WAF Bypass",
                                "AI fuzzing parameter '" + selectedParam + "' with WAF bypass\n" + url);
                    });
                    aiMenu.add(wafItem);

                    JMenuItem adaptiveItem = new JMenuItem("Smart Fuzzing + Adaptive");
                    adaptiveItem.addActionListener(e -> {
                        aiAnalyzer.manualScan(reqResp, true, true, false, true, module.getId(), selectedParam);
                        showToast(module.getName() + " + AI + Adaptive",
                                "AI adaptive fuzzing parameter '" + selectedParam + "'\n" + url);
                    });
                    aiMenu.add(adaptiveItem);

                    aiMenu.addSeparator();

                    JMenuItem fullItem = new JMenuItem("Full AI Scan");
                    fullItem.addActionListener(e -> {
                        aiAnalyzer.manualScan(reqResp, true, true, true, true, module.getId(), selectedParam);
                        showToast(module.getName() + " + Full AI",
                                "Full AI scan on parameter '" + selectedParam + "'\n" + url);
                    });
                    aiMenu.add(fullItem);

                    moduleParamMenu.add(aiMenu);
                }

                paramSubMenu.add(moduleParamMenu);
            }
            items.add(paramSubMenu);
        }

        // ============ "Scan Parameter >" — always-visible parameter picker (no selection needed) ============
        if (!staticResource) {
            // Collect all scannable parameter names (preserving order, no dupes)
            LinkedHashSet<String> allParams = new LinkedHashSet<>();
            for (ParsedHttpParameter param : reqResp.request().parameters()) {
                allParams.add(param.name());
            }

            // Extract params embedded in header values (e.g., Referer URL: ?id=q22&Submit=Submit)
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
                            String key = eq > 0 ? pair.substring(0, eq) : pair;
                            key = key.trim();
                            if (!key.isEmpty()) allParams.add(key);
                        }
                    }
                }
            }

            // Collect injectable header names (for header injection testing)
            Set<String> injectableHeaderNames = Set.of("referer", "user-agent", "x-forwarded-for",
                    "x-forwarded-host", "origin", "host", "x-real-ip", "x-custom-ip-authorization");
            LinkedHashSet<String> headerTargets = new LinkedHashSet<>();
            for (var header : reqResp.request().headers()) {
                if (injectableHeaderNames.contains(header.name().toLowerCase())) {
                    headerTargets.add(header.name());
                }
            }

            if (!allParams.isEmpty() || !headerTargets.isEmpty()) {
                JMenu scanParamMenu = new JMenu("Scan Parameter");

                // Regular parameters (URL, body, cookie, + those from Referer/Origin)
                for (String paramName : allParams) {
                    scanParamMenu.add(buildParameterTargetMenu(
                            paramName, reqResp, url, activeModules, aiAnalyzer, aiAvailable));
                }

                // Injectable header names as separate section
                if (!headerTargets.isEmpty()) {
                    scanParamMenu.addSeparator();
                    scanParamMenu.add(createSectionLabel("Headers"));
                    for (String headerName : headerTargets) {
                        scanParamMenu.add(buildParameterTargetMenu(
                                headerName, reqResp, url, activeModules, aiAnalyzer, aiAvailable));
                    }
                }

                items.add(scanParamMenu);
            }
        }

        // ============ "Send to OmniStrike >" submenu — per-module with Normal/AI options ============
        JMenu subMenu = new JMenu("Send to OmniStrike");

        // Group: Active Scanners
        if (!activeModules.isEmpty()) {
            subMenu.add(createSectionLabel("Active Scanners"));
            for (ScanModule module : activeModules) {
                subMenu.add(buildModuleMenu(module, reqResp, url, aiAnalyzer, aiAvailable));
            }
        }

        // Group: Passive Analyzers
        if (!passiveModules.isEmpty()) {
            if (!activeModules.isEmpty()) subMenu.addSeparator();
            subMenu.add(createSectionLabel("Passive Analyzers"));
            for (ScanModule module : passiveModules) {
                subMenu.add(buildModuleMenu(module, reqResp, url, aiAnalyzer, aiAvailable));
            }
        }

        if (subMenu.getItemCount() > 0) {
            items.add(subMenu);
        }

        // ============ Session Keep-Alive ============
        items.add(new JSeparator());

        // "Set as Session Login Request" — saves the selected request for periodic replay
        JMenuItem setLoginItem = new JMenuItem("Set as Session Login Request");
        setLoginItem.setToolTipText("Save this request for periodic replay to keep session cookies fresh");
        setLoginItem.addActionListener(e -> {
            sessionKeepAlive.setLoginRequest(reqResp);
            showToast("Session Keep-Alive",
                    "Login request saved:\n" + url
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

    // ==================== Selected Parameter Detection ====================

    /**
     * Detects which HTTP parameter the user has selected in the message editor.
     * <p>
     * Strategy 1: Match selection byte offsets against parsed parameter offsets.
     * This works when the user selects a parameter in the URL query string or body.
     * <p>
     * Strategy 2 (fallback): Extract the selected text and match it against known
     * parameter names/values. This handles selections inside headers (e.g., Referer,
     * Origin) where the same parameters appear at different byte positions.
     */
    private String detectSelectedParameter(ContextMenuEvent event) {
        var editorOpt = event.messageEditorRequestResponse();
        if (editorOpt.isEmpty()) return null;

        var editor = editorOpt.get();
        var rangeOpt = editor.selectionOffsets();
        if (rangeOpt.isEmpty()) return null;

        Range selection = rangeOpt.get();
        HttpRequest request = editor.requestResponse().request();
        List<ParsedHttpParameter> params = request.parameters();

        // Strategy 1: Byte-offset overlap against parsed parameter ranges
        for (ParsedHttpParameter param : params) {
            Range nameRange = param.nameOffsets();
            Range valueRange = param.valueOffsets();

            boolean overlapsName = selection.startIndexInclusive() < nameRange.endIndexExclusive()
                    && selection.endIndexExclusive() > nameRange.startIndexInclusive();
            boolean overlapsValue = selection.startIndexInclusive() < valueRange.endIndexExclusive()
                    && selection.endIndexExclusive() > valueRange.startIndexInclusive();

            if (overlapsName || overlapsValue) {
                return param.name();
            }
        }

        // Strategy 2: Text-based fallback — handles selections inside headers
        // (e.g., Referer: https://...?id=test&Submit=Submit)
        String selectedText = extractSelectedText(request, selection);
        if (selectedText == null || selectedText.isEmpty()) return null;

        // 2a: Selected text exactly matches a parameter name (e.g., user selected "id")
        for (ParsedHttpParameter param : params) {
            if (param.name().equalsIgnoreCase(selectedText)) {
                return param.name();
            }
        }

        // 2b: Selected text exactly matches a parameter value → return that param's name
        for (ParsedHttpParameter param : params) {
            if (param.value() != null && param.value().equals(selectedText)) {
                return param.name();
            }
        }

        // 2c: Selected text contains key=value pairs (e.g., "id=q22" or "id=q22&Submit=Submit")
        //     Parse and return the first key that matches a known parameter
        String[] pairs = selectedText.split("[&?]");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            String key = eq > 0 ? pair.substring(0, eq).trim() : pair.trim();
            if (key.isEmpty()) continue;
            for (ParsedHttpParameter param : params) {
                if (param.name().equalsIgnoreCase(key)) {
                    return param.name();
                }
            }
        }

        // 2d: Expand selection to surrounding key=value context within the line.
        //     If user selected just a value like "q22", find it within the raw request
        //     line and walk backwards to find the "key=" prefix.
        String contextParam = findParamFromContext(request, selection, params);
        if (contextParam != null) return contextParam;

        // 2e: Selected text matches a request header name (e.g., "Referer", "User-Agent").
        //     Scanners extract these as header injection targets with the header name.
        for (var header : request.headers()) {
            if (header.name().equalsIgnoreCase(selectedText)) {
                return header.name();
            }
        }

        return null;
    }

    /**
     * Extracts the selected text from the raw request bytes.
     */
    private String extractSelectedText(HttpRequest request, Range selection) {
        try {
            byte[] raw = request.toByteArray().getBytes();
            int start = selection.startIndexInclusive();
            int end = selection.endIndexExclusive();
            if (start < 0 || end > raw.length || start >= end) return null;
            return new String(raw, start, end - start, java.nio.charset.StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * When the user selects a value (e.g., "q22") inside a header like Referer,
     * expand to the surrounding context to find the "key=" prefix.
     * Walks backwards from the selection start to find "key=" and checks if that
     * key matches a known request parameter.
     */
    private String findParamFromContext(HttpRequest request, Range selection,
                                        List<ParsedHttpParameter> params) {
        try {
            byte[] raw = request.toByteArray().getBytes();
            int start = selection.startIndexInclusive();

            // Walk backwards from selection start, looking for '=' preceded by a param name
            // Stop at line boundary, '&', '?', or beginning of raw bytes
            int eqPos = -1;
            for (int i = start - 1; i >= 0 && i >= start - 200; i--) {
                char c = (char) (raw[i] & 0xFF);
                if (c == '=') { eqPos = i; break; }
                if (c == '&' || c == '?' || c == '\n' || c == '\r' || c == ' ') break;
            }
            if (eqPos < 1) return null;

            // Extract the key before '='
            int keyStart = eqPos - 1;
            for (; keyStart >= 0; keyStart--) {
                char c = (char) (raw[keyStart] & 0xFF);
                if (c == '&' || c == '?' || c == '\n' || c == '\r' || c == ' ' || c == ';') {
                    keyStart++;
                    break;
                }
            }
            if (keyStart < 0) keyStart = 0;

            String key = new String(raw, keyStart, eqPos - keyStart, java.nio.charset.StandardCharsets.UTF_8).trim();
            if (key.isEmpty()) return null;

            for (ParsedHttpParameter param : params) {
                if (param.name().equalsIgnoreCase(key)) {
                    return param.name();
                }
            }
        } catch (Exception ignored) {}
        return null;
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

    // ==================== Parameter Target Submenu ====================

    /**
     * Builds a submenu for scanning a specific parameter:
     *
     *   paramName >
     *     All Modules
     *     ─────
     *     SQLi Detector >
     *       Normal Scan
     *       AI Scan > ...
     *     XSS Scanner >
     *       Normal Scan
     *       AI Scan > ...
     */
    private JMenu buildParameterTargetMenu(String paramName, HttpRequestResponse reqResp,
                                            String url, List<ScanModule> activeModules,
                                            AiVulnAnalyzer aiAnalyzer, boolean aiAvailable) {
        JMenu paramMenu = new JMenu(paramName);

        // "All Modules" — runs all active scanners on this parameter
        JMenuItem allItem = new JMenuItem("All Modules");
        allItem.addActionListener(e -> {
            List<String> moduleIds = new ArrayList<>();
            for (ScanModule m : activeModules) moduleIds.add(m.getId());
            interceptor.scanRequest(reqResp, moduleIds, paramName);
            showToast("Parameter Scan",
                    "Scanning '" + paramName + "' with " + moduleIds.size() + " active module(s)\n" + url);
        });
        paramMenu.add(allItem);
        paramMenu.addSeparator();

        // Per-module submenus with Normal + AI scan options
        for (ScanModule module : activeModules) {
            JMenu moduleMenu = new JMenu(module.getName());
            moduleMenu.setToolTipText(module.getDescription());

            JMenuItem normalItem = new JMenuItem("Normal Scan");
            normalItem.addActionListener(e -> {
                interceptor.scanRequest(reqResp, List.of(module.getId()), paramName);
                showToast(module.getName(),
                        "Scanning parameter '" + paramName + "'\n" + url);
            });
            moduleMenu.add(normalItem);

            if (aiAvailable) {
                JMenu aiMenu = new JMenu("AI Scan");

                JMenuItem fuzzItem = new JMenuItem("Smart Fuzzing");
                fuzzItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, false, false, module.getId(), paramName);
                    showToast(module.getName() + " + AI",
                            "AI fuzzing parameter '" + paramName + "'\n" + url);
                });
                aiMenu.add(fuzzItem);

                JMenuItem wafItem = new JMenuItem("Smart Fuzzing + WAF Bypass");
                wafItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, true, false, module.getId(), paramName);
                    showToast(module.getName() + " + AI + WAF Bypass",
                            "AI fuzzing parameter '" + paramName + "' with WAF bypass\n" + url);
                });
                aiMenu.add(wafItem);

                JMenuItem adaptiveItem = new JMenuItem("Smart Fuzzing + Adaptive");
                adaptiveItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, false, true, module.getId(), paramName);
                    showToast(module.getName() + " + AI + Adaptive",
                            "AI adaptive fuzzing parameter '" + paramName + "'\n" + url);
                });
                aiMenu.add(adaptiveItem);

                aiMenu.addSeparator();

                JMenuItem fullItem = new JMenuItem("Full AI Scan");
                fullItem.addActionListener(e -> {
                    aiAnalyzer.manualScan(reqResp, true, true, true, true, module.getId(), paramName);
                    showToast(module.getName() + " + Full AI",
                            "Full AI scan on parameter '" + paramName + "'\n" + url);
                });
                aiMenu.add(fullItem);

                moduleMenu.add(aiMenu);
            }

            paramMenu.add(moduleMenu);
        }

        return paramMenu;
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
