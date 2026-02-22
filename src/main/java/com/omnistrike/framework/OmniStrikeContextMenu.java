package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.omnistrike.model.ScanModule;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.ui.ScanConfigDialog;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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


    // Static file extensions where active injection testing is pointless
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".js", ".css", ".html", ".htm", ".svg", ".png", ".jpg", ".jpeg",
            ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
            ".webp", ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".zip", ".gz",
            ".tar", ".xml", ".json", ".txt", ".csv", ".wasm", ".mjs"
    );

    public OmniStrikeContextMenu(MontoyaApi api, ModuleRegistry registry,
                                  TrafficInterceptor interceptor,
                                  OmniStrikeScanCheck scanCheck) {
        this.api = api;
        this.registry = registry;
        this.interceptor = interceptor;
        this.scanCheck = scanCheck;
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
                    if (m.isPassive()) {
                        moduleIds.add(m.getId());
                        passive++;
                    }
                }
            } else {
                for (ScanModule m : nonAi) {
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

        // ============ "Send to OmniStrike >" submenu — per-module with Normal/AI options ============
        JMenu subMenu = new JMenu("Send to OmniStrike");

        List<ScanModule> activeModules = new ArrayList<>();
        List<ScanModule> passiveModules = new ArrayList<>();
        for (ScanModule m : registry.getAllModules()) {
            // Skip AI module — it's embedded inside each module's submenu
            if (ModuleRegistry.AI_MODULE_ID.equals(m.getId())) continue;

            if (m.isPassive()) {
                passiveModules.add(m);
            } else {
                activeModules.add(m);
            }
        }

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
                    BorderFactory.createLineBorder(new Color(80, 80, 80), 1),
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
