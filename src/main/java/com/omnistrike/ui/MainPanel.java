package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.*;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ScanModule;
import com.omnistrike.model.Severity;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.ui.modules.AiModulePanel;
import com.omnistrike.ui.modules.GenericModulePanel;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Top-level Burp Suite tab panel for the OmniStrike.
 * Layout: top config bar, left sidebar (module list), right detail area,
 * bottom tabs for findings overview and log.
 */
public class MainPanel extends JPanel {

    private final ModuleRegistry registry;
    private final FindingsStore findingsStore;
    private final ScopeManager scopeManager;
    private final ActiveScanExecutor executor;
    private final TrafficInterceptor interceptor;
    private final CollaboratorManager collaboratorManager;
    private final MontoyaApi api;
    private final LogPanel logPanel;

    private final JPanel moduleDetailContainer;
    private final CardLayout cardLayout;
    private final Map<String, JPanel> modulePanels = new HashMap<>();
    private final ModuleListPanel moduleListPanel;
    private final JTextField scopeField;
    private final JTextField threadField;
    private final JTextField rateLimitField;
    private final JToggleButton startStopBtn;
    private final JLabel statusLabel;
    private final JLabel threadStatusLabel;

    // Store timer as a field so it can be stopped on extension unload
    private final Timer updateTimer;

    // Child panels that have timers
    private final FindingsOverviewPanel activeFindingsPanel;
    private final FindingsOverviewPanel passiveFindingsPanel;
    private final RequestResponsePanel requestResponsePanel;

    // Stats bar severity count labels
    private final JLabel critLabel;
    private final JLabel highLabel;
    private final JLabel medLabel;
    private final JLabel lowLabel;
    private final JLabel infoLabel;
    private final JLabel totalLabel;

    // Scan progress bar
    private final JProgressBar progressBar;

    // Default border for thread field (saved for resetting after validation)
    private final Border defaultThreadFieldBorder;

    public MainPanel(ModuleRegistry registry, FindingsStore findingsStore, ScopeManager scopeManager,
                     ActiveScanExecutor executor, TrafficInterceptor interceptor,
                     CollaboratorManager collaboratorManager, MontoyaApi api) {
        this.registry = registry;
        this.findingsStore = findingsStore;
        this.scopeManager = scopeManager;
        this.executor = executor;
        this.interceptor = interceptor;
        this.collaboratorManager = collaboratorManager;
        this.api = api;
        this.logPanel = new LogPanel();

        setLayout(new BorderLayout());

        // ============ TOP AREA (2 rows + stats bar) ============
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        // --- Row 1: Scope, Threads, Rate Limit ---
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));

        row1.add(new JLabel("Target Scope:"));
        scopeField = new JTextField(30);
        scopeField.setToolTipText("Comma-separated target domains (e.g., example.com, api.example.com). Used for automated scanning and site map scraping.");
        scopeField.putClientProperty("JTextField.placeholderText",
                "e.g. example.com, api.example.com");
        row1.add(scopeField);

        // Live-sync scope field to ScopeManager so features like Scrape Site Map work without pressing Start
        scopeField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { syncScope(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { syncScope(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { syncScope(); }
            private void syncScope() {
                String text = scopeField.getText().trim();
                if (!text.isEmpty()) {
                    scopeManager.setTargetDomains(text);
                }
            }
        });

        row1.add(new JLabel("Threads:"));
        threadField = new JTextField("5", 3);
        threadField.setToolTipText("Number of concurrent scan threads (1-100). Higher values increase speed but also load.");
        defaultThreadFieldBorder = threadField.getBorder();

        // Input validation with visual feedback for thread count
        threadField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { validateThreadField(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { validateThreadField(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { validateThreadField(); }
        });
        row1.add(threadField);

        row1.add(new JLabel("Rate Limit (ms):"));
        rateLimitField = new JTextField("0", 4);
        rateLimitField.setToolTipText("Global delay (ms) before each scan task. 0 = no limit. Applies to all modules. Per-module delays stack on top of this.");
        rateLimitField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyRateLimit(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyRateLimit(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyRateLimit(); }
        });
        row1.add(rateLimitField);

        topContainer.add(row1);

        // --- Row 2: Buttons, Status, Thread Status, Collaborator, Progress Bar ---
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));

        startStopBtn = new JToggleButton("Start Auto-Scan");
        startStopBtn.setBackground(new Color(50, 150, 50));
        startStopBtn.setForeground(Color.WHITE);
        startStopBtn.setFocusPainted(false);
        startStopBtn.setToolTipText("Start or stop automated scanning of all in-scope proxied traffic");
        startStopBtn.addActionListener(e -> toggleScanning());
        row2.add(startStopBtn);

        JButton stopScansBtn = new JButton("Stop Manual Scans");
        stopScansBtn.setBackground(new Color(200, 50, 50));
        stopScansBtn.setForeground(Color.WHITE);
        stopScansBtn.setFocusPainted(false);
        stopScansBtn.setToolTipText("Stop all scans launched via right-click context menu");
        stopScansBtn.addActionListener(e -> {
            int stopped = interceptor.stopManualScans();
            int purged = executor.cancelAll();
            if (stopped > 0 || purged > 0) {
                logPanel.log("INFO", "Framework",
                        "Stopped " + stopped + " scan task(s), purged " + purged + " queued.");
            } else {
                logPanel.log("INFO", "Framework", "No scans running.");
            }
            MainPanel.this.progressBar.setIndeterminate(false);
            MainPanel.this.progressBar.setVisible(false);
        });
        row2.add(stopScansBtn);

        // Time-based testing toggle — disabled by default, must be explicitly enabled.
        // Controls ALL time-based blind injection tests (SQLi sleep, CmdI sleep/ping).
        JCheckBox timeBasedCheckbox = new JCheckBox("Time-Based Testing");
        timeBasedCheckbox.setSelected(false); // OFF by default
        timeBasedCheckbox.setToolTipText(
                "Enable time-based blind injection tests (SQLi SLEEP, CmdI sleep/ping). "
                + "These tests are slow and can cause delays on the target server. "
                + "Disabled by default — tick to enable.");
        timeBasedCheckbox.addActionListener(e -> {
            boolean selected = timeBasedCheckbox.isSelected();
            TimingLock.setEnabled(selected);
            logPanel.log("INFO", "Framework",
                    "Time-based blind testing " + (selected ? "ENABLED" : "DISABLED"));
        });
        row2.add(timeBasedCheckbox);

        statusLabel = new JLabel("Stopped");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        row2.add(statusLabel);

        threadStatusLabel = new JLabel("Threads: 0 active | Queue: 0");
        threadStatusLabel.setForeground(Color.GRAY);
        threadStatusLabel.setFont(threadStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        row2.add(threadStatusLabel);

        // Collaborator status
        String collabStatus = collaboratorManager != null && collaboratorManager.isAvailable()
                ? "Collaborator: Active" : "Collaborator: N/A (Pro only)";
        JLabel collabLabel = new JLabel(collabStatus);
        collabLabel.setForeground(collaboratorManager != null && collaboratorManager.isAvailable()
                ? new Color(50, 150, 50) : Color.GRAY);
        row2.add(collabLabel);

        // Progress bar (visible only while scanning)
        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(150, 16));
        progressBar.setStringPainted(false);
        progressBar.setForeground(new Color(135, 206, 250)); // sky blue
        progressBar.setVisible(false);
        row2.add(progressBar);

        topContainer.add(row2);

        // --- Stats Bar: severity count badges ---
        JPanel statsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        statsBar.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));

        critLabel = createSeverityBadge("CRITICAL: 0", new Color(180, 30, 30), Color.WHITE);
        highLabel = createSeverityBadge("HIGH: 0", new Color(220, 80, 40), Color.WHITE);
        medLabel = createSeverityBadge("MEDIUM: 0", new Color(230, 160, 30), Color.BLACK);
        lowLabel = createSeverityBadge("LOW: 0", new Color(70, 140, 200), Color.WHITE);
        infoLabel = createSeverityBadge("INFO: 0", new Color(130, 130, 130), Color.WHITE);

        statsBar.add(critLabel);
        statsBar.add(highLabel);
        statsBar.add(medLabel);
        statsBar.add(lowLabel);
        statsBar.add(infoLabel);
        statsBar.add(new JLabel("  |  "));
        totalLabel = new JLabel("Total: 0");
        totalLabel.setFont(totalLabel.getFont().deriveFont(Font.BOLD));
        statsBar.add(totalLabel);

        topContainer.add(statsBar);

        add(topContainer, BorderLayout.NORTH);

        // ============ LEFT SIDEBAR ============
        moduleListPanel = new ModuleListPanel(registry, findingsStore);
        moduleListPanel.setOnModuleSelected(this::showModulePanel);

        // ============ RIGHT DETAIL AREA ============
        cardLayout = new CardLayout();
        moduleDetailContainer = new JPanel(cardLayout);

        // Create a panel for each module
        for (ScanModule module : registry.getAllModules()) {
            JPanel panel;
            if ("ai-vuln-analyzer".equals(module.getId()) && module instanceof AiVulnAnalyzer aiModule) {
                panel = new AiModulePanel(aiModule, findingsStore, registry, api, scopeManager);
            } else {
                panel = new GenericModulePanel(module.getId(), module.getName(), findingsStore, api);
            }
            modulePanels.put(module.getId(), panel);
            moduleDetailContainer.add(panel, module.getId());
        }

        // Placeholder when no module selected
        JPanel placeholder = new JPanel(new GridBagLayout());
        placeholder.add(new JLabel("Select a module from the left sidebar"));
        moduleDetailContainer.add(placeholder, "none");
        cardLayout.show(moduleDetailContainer, "none");

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                moduleListPanel, moduleDetailContainer);
        centerSplit.setDividerLocation(250);

        // ============ BOTTOM TABS ============
        JTabbedPane bottomTabs = new JTabbedPane();

        // Build set of passive module IDs for categorizing findings
        java.util.Set<String> passiveModuleIds = new java.util.HashSet<>();
        for (ScanModule m : registry.getAllModules()) {
            if (m.isPassive() && !"ai-vuln-analyzer".equals(m.getId())) {
                passiveModuleIds.add(m.getId());
            }
        }

        java.util.function.Predicate<Finding> activeFilter = f -> {
            String mid = f.getModuleId();
            if ("ai-vuln-analyzer".equals(mid)) {
                String target = f.getTargetModuleId();
                return target == null || !passiveModuleIds.contains(target);
            }
            return !passiveModuleIds.contains(mid);
        };

        java.util.function.Predicate<Finding> passiveFilter = f -> {
            String mid = f.getModuleId();
            if ("ai-vuln-analyzer".equals(mid)) {
                String target = f.getTargetModuleId();
                return target != null && passiveModuleIds.contains(target);
            }
            return passiveModuleIds.contains(mid);
        };

        activeFindingsPanel = new FindingsOverviewPanel(findingsStore, activeFilter);
        activeFindingsPanel.setApi(api);
        passiveFindingsPanel = new FindingsOverviewPanel(findingsStore, passiveFilter);
        passiveFindingsPanel.setApi(api);
        requestResponsePanel = new RequestResponsePanel(findingsStore);
        bottomTabs.addTab("Active Findings", activeFindingsPanel);
        bottomTabs.addTab("Passive Findings", passiveFindingsPanel);
        bottomTabs.addTab("Request/Response", requestResponsePanel);
        bottomTabs.addTab("Activity Log", logPanel);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                centerSplit, bottomTabs);
        mainSplit.setDividerLocation(450);
        mainSplit.setResizeWeight(0.5);

        // Allow the bottom tabs to be pulled up high — set small minimum sizes
        centerSplit.setMinimumSize(new Dimension(0, 80));
        bottomTabs.setMinimumSize(new Dimension(0, 80));

        add(mainSplit, BorderLayout.CENTER);

        // Wire interceptor events to the Activity Log
        interceptor.setUiLogger((module, message) ->
                javax.swing.SwingUtilities.invokeLater(() -> logPanel.log("INFO", module, message)));

        // Wire AI Analyzer events to the Activity Log
        ScanModule aiModule = registry.getModule("ai-vuln-analyzer");
        if (aiModule instanceof AiVulnAnalyzer aiAnalyzer) {
            aiAnalyzer.setUiLogger((module, message) ->
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        String level = message.startsWith("ERROR:") ? "ERROR" : "INFO";
                        logPanel.log(level, module, message);
                    }));
        }

        // Timer to periodically update finding counts, thread status, and stats bar
        updateTimer = new Timer(3000, e -> {
            moduleListPanel.updateFindingsCounts();
            updateThreadStatus();
            updateStatsBar();
        });
        updateTimer.start();
    }

    /**
     * Applies the global rate limit from the UI field to the executor.
     */
    private void applyRateLimit() {
        String text = rateLimitField.getText().trim();
        if (text.isEmpty()) {
            executor.setRateLimitMs(0);
            return;
        }
        try {
            int value = Integer.parseInt(text);
            executor.setRateLimitMs(value);
        } catch (NumberFormatException ignored) {
            // Invalid input — keep current value
        }
    }

    /**
     * Validates the thread count field and provides visual feedback.
     * Valid input: integer between 1 and 100.
     * Invalid input gets a red border.
     */
    private void validateThreadField() {
        String text = threadField.getText().trim();
        if (text.isEmpty()) {
            threadField.setBorder(defaultThreadFieldBorder);
            return;
        }
        try {
            int value = Integer.parseInt(text);
            if (value >= 1 && value <= 100) {
                threadField.setBorder(defaultThreadFieldBorder);
                threadField.setToolTipText("Number of concurrent scan threads (1-100). Higher values increase speed but also load.");
            } else {
                threadField.setBorder(BorderFactory.createLineBorder(Color.RED, 2));
                threadField.setToolTipText("Invalid: thread count must be between 1 and 100");
            }
        } catch (NumberFormatException ex) {
            threadField.setBorder(BorderFactory.createLineBorder(Color.RED, 2));
            threadField.setToolTipText("Invalid: enter a numeric value between 1 and 100");
        }
    }

    /**
     * Updates the status label showing active thread count and queue size.
     */
    private void updateThreadStatus() {
        SwingUtilities.invokeLater(() -> {
            int active = executor.getActiveCount();
            int queue = executor.getQueueSize();
            threadStatusLabel.setText("Threads: " + active + " active | Queue: " + queue);

            // Show progress bar when there are active threads, hide when idle
            if (active > 0) {
                if (!progressBar.isVisible()) {
                    progressBar.setIndeterminate(true);
                    progressBar.setVisible(true);
                }
            } else if (!startStopBtn.isSelected()) {
                progressBar.setIndeterminate(false);
                progressBar.setVisible(false);
            }
        });
    }

    private void toggleScanning() {
        if (startStopBtn.isSelected()) {
            // Start scanning
            String scope = scopeField.getText().trim();
            if (scope.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please configure target scope first.");
                startStopBtn.setSelected(false);
                return;
            }

            scopeManager.setTargetDomains(scope);

            try {
                int threads = Integer.parseInt(threadField.getText().trim());
                if (threads < 1 || threads > 100) {
                    JOptionPane.showMessageDialog(this, "Thread count must be between 1 and 100.");
                    startStopBtn.setSelected(false);
                    return;
                }
                executor.resize(threads);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "Invalid thread count. Please enter a number between 1 and 100.");
                startStopBtn.setSelected(false);
                return;
            }

            interceptor.setRunning(true);
            startStopBtn.setText("Stop Auto-Scan");
            startStopBtn.setBackground(new Color(200, 50, 50));
            statusLabel.setText("Running");
            statusLabel.setForeground(new Color(50, 150, 50));
            progressBar.setIndeterminate(true);
            progressBar.setVisible(true);

            logPanel.log("INFO", "Framework", "Scanner started. Scope: " + scope
                    + " | Threads: " + executor.getThreadPoolSize());

        } else {
            // Stop scanning
            interceptor.setRunning(false);
            executor.cancelAll();
            startStopBtn.setText("Start Auto-Scan");
            startStopBtn.setBackground(new Color(50, 150, 50));
            statusLabel.setText("Stopped");
            statusLabel.setForeground(Color.RED);
            progressBar.setIndeterminate(false);
            progressBar.setVisible(false);

            logPanel.log("INFO", "Framework", "Scanner stopped.");
        }
    }

    private void showModulePanel(String moduleId) {
        cardLayout.show(moduleDetailContainer, moduleId);
        logPanel.log("INFO", "UI", "Viewing module: " + moduleId);
    }

    /**
     * Stops the update timer and all child panel timers.
     * Call this from the extension unload handler.
     */
    public void stopTimers() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
        // FindingsOverviewPanels do not currently have timers that need stopping.
        if (requestResponsePanel != null) {
            requestResponsePanel.stopTimers();
        }
        // Stop timers on all module panels
        for (JPanel panel : modulePanels.values()) {
            if (panel instanceof GenericModulePanel) {
                ((GenericModulePanel) panel).stopTimers();
            } else if (panel instanceof AiModulePanel) {
                ((AiModulePanel) panel).stopTimers();
            }
        }
    }

    private static JLabel createSeverityBadge(String text, Color bg, Color fg) {
        JLabel label = new JLabel(text);
        label.setOpaque(true);
        label.setBackground(bg);
        label.setForeground(fg);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        label.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        return label;
    }

    private void updateStatsBar() {
        SwingUtilities.invokeLater(() -> {
            critLabel.setText("CRITICAL: " + findingsStore.getCountBySeverity(Severity.CRITICAL));
            highLabel.setText("HIGH: " + findingsStore.getCountBySeverity(Severity.HIGH));
            medLabel.setText("MEDIUM: " + findingsStore.getCountBySeverity(Severity.MEDIUM));
            lowLabel.setText("LOW: " + findingsStore.getCountBySeverity(Severity.LOW));
            infoLabel.setText("INFO: " + findingsStore.getCountBySeverity(Severity.INFO));
            totalLabel.setText("Total: " + findingsStore.getCount());
        });
    }

    public LogPanel getLogPanel() {
        return logPanel;
    }
}
