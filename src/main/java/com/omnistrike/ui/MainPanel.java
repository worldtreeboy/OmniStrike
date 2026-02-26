package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.*;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ScanModule;
import com.omnistrike.model.Severity;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.ui.modules.AiModulePanel;
import com.omnistrike.ui.modules.DeserModulePanel;
import com.omnistrike.ui.modules.GenericModulePanel;

import static com.omnistrike.ui.CyberTheme.*;

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
    private final SessionKeepAlive sessionKeepAlive;
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

    // Custom module panel for deserializer (exposed for context menu "Send to Deserializer")
    private DeserModulePanel deserModulePanel;

    // Stats bar severity count labels
    private final JLabel critLabel;
    private final JLabel highLabel;
    private final JLabel medLabel;
    private final JLabel lowLabel;
    private final JLabel infoLabel;
    private final JLabel totalLabel;

    // Scan progress bar
    private final JProgressBar progressBar;

    // Session keep-alive status label
    private final JLabel sessionStatusLabel;

    // Default border for thread field (saved for resetting after validation)
    private final Border defaultThreadFieldBorder;

    public MainPanel(ModuleRegistry registry, FindingsStore findingsStore, ScopeManager scopeManager,
                     ActiveScanExecutor executor, TrafficInterceptor interceptor,
                     CollaboratorManager collaboratorManager, SessionKeepAlive sessionKeepAlive,
                     MontoyaApi api) {
        this.registry = registry;
        this.findingsStore = findingsStore;
        this.scopeManager = scopeManager;
        this.executor = executor;
        this.interceptor = interceptor;
        this.collaboratorManager = collaboratorManager;
        this.sessionKeepAlive = sessionKeepAlive;
        this.api = api;
        this.logPanel = new LogPanel();

        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        // ============ TOP AREA (2 rows + stats bar) ============
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBackground(BG_DARK);
        topContainer.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER));

        // --- Row 1: Scope, Threads, Rate Limit ---
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        row1.setBackground(BG_DARK);

        JLabel scopeLabel = new JLabel("Target Scope:");
        scopeLabel.setForeground(NEON_CYAN);
        scopeLabel.setFont(MONO_LABEL);
        row1.add(scopeLabel);
        scopeField = new JTextField(30);
        styleTextField(scopeField);
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

        JLabel threadsLabel = new JLabel("Threads:");
        threadsLabel.setForeground(NEON_CYAN);
        threadsLabel.setFont(MONO_LABEL);
        row1.add(threadsLabel);
        threadField = new JTextField("5", 3);
        styleTextField(threadField);
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

        JLabel rateLimitLabel = new JLabel("Rate Limit (ms):");
        rateLimitLabel.setForeground(NEON_CYAN);
        rateLimitLabel.setFont(MONO_LABEL);
        row1.add(rateLimitLabel);
        rateLimitField = new JTextField("0", 4);
        styleTextField(rateLimitField);
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

        // Theme selector dropdown
        JLabel themeLabel = new JLabel("Theme:");
        themeLabel.setForeground(NEON_CYAN);
        themeLabel.setFont(MONO_LABEL);
        row1.add(themeLabel);

        JComboBox<String> themeCombo = new JComboBox<>(GlobalThemeManager.THEME_NAMES);
        themeCombo.setSelectedIndex(0); // Default
        styleComboBox(themeCombo);
        themeCombo.setToolTipText("Switch the global theme for the entire Burp Suite application");
        themeCombo.addActionListener(e -> {
            int idx = themeCombo.getSelectedIndex();
            if (idx >= 0 && idx < GlobalThemeManager.ALL_THEMES.length) {
                ThemePalette palette = GlobalThemeManager.ALL_THEMES[idx];
                GlobalThemeManager.applyTheme(palette);
                // Re-apply OmniStrike-specific styling after palette swap
                if (palette != null) {
                    reapplyTheme();
                }
            }
        });
        row1.add(themeCombo);

        topContainer.add(row1);

        // --- Row 2: Buttons, Status, Thread Status, Collaborator, Progress Bar ---
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        row2.setBackground(BG_DARK);

        startStopBtn = new JToggleButton("Start Auto-Scan");
        startStopBtn.setBackground(BG_PANEL);
        startStopBtn.setForeground(NEON_GREEN);
        startStopBtn.setFocusPainted(false);
        startStopBtn.setFont(MONO_BOLD);
        startStopBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(NEON_GREEN, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        startStopBtn.setToolTipText("Start or stop automated scanning of all in-scope proxied traffic");
        startStopBtn.addActionListener(e -> toggleScanning());
        row2.add(startStopBtn);

        JButton stopScansBtn = new JButton("Stop Manual Scans");
        stopScansBtn.setBackground(BG_PANEL);
        stopScansBtn.setForeground(NEON_RED);
        stopScansBtn.setFocusPainted(false);
        stopScansBtn.setFont(MONO_BOLD);
        stopScansBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(NEON_RED, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
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
        styleCheckBox(timeBasedCheckbox);
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
        statusLabel.setForeground(NEON_RED);
        statusLabel.setFont(MONO_BOLD);
        row2.add(statusLabel);

        threadStatusLabel = new JLabel("Threads: 0 active | Queue: 0");
        threadStatusLabel.setForeground(FG_SECONDARY);
        threadStatusLabel.setFont(MONO_SMALL);
        row2.add(threadStatusLabel);

        // Collaborator status
        String collabStatus = collaboratorManager != null && collaboratorManager.isAvailable()
                ? "Collaborator: Active" : "Collaborator: N/A (Pro only)";
        JLabel collabLabel = new JLabel(collabStatus);
        collabLabel.setForeground(collaboratorManager != null && collaboratorManager.isAvailable()
                ? NEON_GREEN : FG_DIM);
        collabLabel.setFont(MONO_SMALL);
        row2.add(collabLabel);

        // Progress bar (visible only while scanning)
        progressBar = new JProgressBar();
        styleProgressBar(progressBar);
        progressBar.setPreferredSize(new Dimension(150, 16));
        progressBar.setStringPainted(false);
        progressBar.setVisible(false);
        row2.add(progressBar);

        topContainer.add(row2);

        // --- Row 3: Session Keep-Alive controls ---
        JPanel sessionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        sessionRow.setBackground(BG_DARK);

        JCheckBox sessionCheckbox = new JCheckBox("Session Keep-Alive");
        styleCheckBox(sessionCheckbox);
        sessionCheckbox.setSelected(false);
        sessionCheckbox.setToolTipText(
                "Periodically replay a saved login request to keep session cookies fresh. "
                + "Right-click any request > 'Set as Session Login Request' to configure.");
        sessionRow.add(sessionCheckbox);

        JLabel intervalLabel = new JLabel("Interval:");
        intervalLabel.setForeground(NEON_CYAN);
        intervalLabel.setFont(MONO_LABEL);
        sessionRow.add(intervalLabel);
        JComboBox<String> intervalCombo = new JComboBox<>(new String[]{
                "1 min", "2 min", "3 min", "5 min", "10 min", "15 min", "30 min"});
        intervalCombo.setSelectedItem("5 min");
        intervalCombo.setToolTipText("How often to replay the login request");
        styleComboBox(intervalCombo);
        sessionRow.add(intervalCombo);

        sessionStatusLabel = new JLabel("Session: Not configured");
        sessionStatusLabel.setForeground(FG_SECONDARY);
        sessionStatusLabel.setFont(MONO_SMALL);
        sessionRow.add(sessionStatusLabel);

        // Wire checkbox to SessionKeepAlive
        sessionCheckbox.addActionListener(e -> {
            boolean selected = sessionCheckbox.isSelected();
            if (selected && !sessionKeepAlive.hasLoginRequest()) {
                JOptionPane.showMessageDialog(this,
                        "No login request configured.\n"
                        + "Right-click any request in Burp and select\n"
                        + "'Set as Session Login Request' first.",
                        "Session Keep-Alive", JOptionPane.INFORMATION_MESSAGE);
                sessionCheckbox.setSelected(false);
                return;
            }
            sessionKeepAlive.setEnabled(selected);
            logPanel.log("INFO", "SessionKeepAlive",
                    selected ? "Enabled" : "Disabled");
        });

        // Wire interval combo to SessionKeepAlive
        intervalCombo.addActionListener(e -> {
            String selected = (String) intervalCombo.getSelectedItem();
            if (selected != null) {
                int minutes = Integer.parseInt(selected.split(" ")[0]);
                sessionKeepAlive.setIntervalMinutes(minutes);
            }
        });

        // Wire status callback from SessionKeepAlive to update label
        sessionKeepAlive.setStatusCallback(status -> {
            SwingUtilities.invokeLater(() -> {
                sessionStatusLabel.setText(status);
                if (status.contains("ERROR")) {
                    sessionStatusLabel.setForeground(NEON_RED);
                    sessionStatusLabel.setFont(MONO_BOLD.deriveFont(11f));
                } else if (status.contains("Active")) {
                    sessionStatusLabel.setForeground(NEON_GREEN);
                    sessionStatusLabel.setFont(MONO_SMALL);
                } else if (status.contains("Disabled")) {
                    sessionStatusLabel.setForeground(NEON_ORANGE);
                    sessionStatusLabel.setFont(MONO_SMALL);
                } else {
                    sessionStatusLabel.setForeground(FG_SECONDARY);
                    sessionStatusLabel.setFont(MONO_SMALL);
                }
            });
        });

        topContainer.add(sessionRow);

        // --- Stats Bar: severity count badges (left) + author credit (right) ---
        JPanel statsBarWrapper = new JPanel(new BorderLayout());
        statsBarWrapper.setBackground(BG_DARK);
        statsBarWrapper.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));

        JPanel statsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        statsBar.setBackground(BG_DARK);

        critLabel = CyberTheme.createSeverityBadge("CRITICAL: 0", SEV_CRITICAL);
        highLabel = CyberTheme.createSeverityBadge("HIGH: 0", SEV_HIGH);
        medLabel = CyberTheme.createSeverityBadge("MEDIUM: 0", SEV_MEDIUM);
        lowLabel = CyberTheme.createSeverityBadge("LOW: 0", SEV_LOW);
        infoLabel = CyberTheme.createSeverityBadge("INFO: 0", SEV_INFO);

        statsBar.add(critLabel);
        statsBar.add(highLabel);
        statsBar.add(medLabel);
        statsBar.add(lowLabel);
        statsBar.add(infoLabel);
        JLabel separatorLabel = new JLabel("  |  ");
        separatorLabel.setForeground(FG_DIM);
        statsBar.add(separatorLabel);
        totalLabel = new JLabel("Total: 0");
        totalLabel.setForeground(FG_PRIMARY);
        totalLabel.setFont(MONO_BOLD);
        statsBar.add(totalLabel);

        statsBarWrapper.add(statsBar, BorderLayout.WEST);

        // Author credit — neon glow label, right-aligned
        JLabel creditLabel = new JLabel("github.com/worldtreeboy  ") {
            private boolean hovered = false;
            private float glowPhase = 0f;
            private final Timer pulseTimer = new Timer(40, evt -> {
                glowPhase += 0.02f;  // slow breathing cycle (~8 seconds full loop)
                if (glowPhase > (float)(2 * Math.PI)) glowPhase -= (float)(2 * Math.PI);
                repaint();
            });
            {
                pulseTimer.start();
            }
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

                String text = getText();
                FontMetrics fm = g2.getFontMetrics(getFont());
                int x = (getWidth() - fm.stringWidth(text)) / 2;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;

                Color glowColor = NEON_CYAN;

                // Slow breathing: fades from dim (0.08) to full bright (1.0) and back
                float breathe = 0.5f + 0.5f * (float) Math.sin(glowPhase); // 0..1
                float pulse = hovered
                        ? 0.85f + 0.15f * breathe   // hover: always bright
                        : 0.08f + 0.92f * breathe;  // idle: faint → full bright

                // Draw glow layers — full circle offsets for smooth halo
                g2.setFont(getFont());
                for (int i = 6; i >= 1; i--) {
                    float alpha = pulse * (0.06f + 0.04f * (6 - i));
                    g2.setColor(new Color(
                            glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(),
                            Math.min(255, (int)(alpha * 255))));
                    // 8 directions: N, NE, E, SE, S, SW, W, NW
                    for (int dx = -1; dx <= 1; dx++) {
                        for (int dy = -1; dy <= 1; dy++) {
                            if (dx == 0 && dy == 0) continue;
                            g2.drawString(text, x + dx * i, y + dy * i);
                        }
                    }
                }

                // Draw the crisp foreground text — fades with the breathing
                int textAlpha = Math.min(255, (int)(((0.3f + 0.7f * pulse)) * 255));
                g2.setColor(new Color(
                        glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(), textAlpha));
                g2.drawString(text, x, y);
                g2.dispose();
            }
            public void setHovered(boolean h) { this.hovered = h; }
        };
        creditLabel.setForeground(FG_DIM);
        Font creditFont = MONO_SMALL.deriveFont(MONO_SMALL.getSize() * 1.2f);
        creditLabel.setFont(creditFont);
        creditLabel.setOpaque(false);
        creditLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        creditLabel.setToolTipText("OmniStrike by worldtreeboy");
        creditLabel.setPreferredSize(new Dimension(
                creditLabel.getFontMetrics(creditFont).stringWidth("github.com/worldtreeboy  ") + 20,
                28));
        creditLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                try { var m = creditLabel.getClass().getMethod("setHovered", boolean.class);
                    m.invoke(creditLabel, true);
                } catch (Exception ignored) {}
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                try { var m = creditLabel.getClass().getMethod("setHovered", boolean.class);
                    m.invoke(creditLabel, false);
                } catch (Exception ignored) {}
            }
        });
        statsBarWrapper.add(creditLabel, BorderLayout.EAST);

        topContainer.add(statsBarWrapper);

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
            } else if ("deser-scanner".equals(module.getId())) {
                deserModulePanel = new DeserModulePanel(api, findingsStore);
                panel = deserModulePanel;
            } else {
                panel = new GenericModulePanel(module.getId(), module.getName(), findingsStore, api);
            }
            modulePanels.put(module.getId(), panel);
            moduleDetailContainer.add(panel, module.getId());
        }

        // Placeholder when no module selected
        JPanel placeholder = new JPanel(new GridBagLayout());
        placeholder.setBackground(BG_DARK);
        JLabel placeholderLabel = new JLabel("Select a module from the left sidebar");
        placeholderLabel.setForeground(FG_SECONDARY);
        placeholderLabel.setFont(MONO_FONT);
        placeholder.add(placeholderLabel);
        moduleDetailContainer.add(placeholder, "none");
        cardLayout.show(moduleDetailContainer, "none");

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                moduleListPanel, moduleDetailContainer);
        centerSplit.setDividerLocation(250);
        styleSplitPane(centerSplit);

        // ============ BOTTOM TABS ============
        JTabbedPane bottomTabs = new JTabbedPane();
        styleTabbedPane(bottomTabs);

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
        requestResponsePanel.setApi(api);
        bottomTabs.addTab("Active Findings", activeFindingsPanel);
        bottomTabs.addTab("Passive Findings", passiveFindingsPanel);
        bottomTabs.addTab("Request/Response", requestResponsePanel);
        bottomTabs.addTab("Activity Log", logPanel);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                centerSplit, bottomTabs);
        mainSplit.setDividerLocation(450);
        mainSplit.setResizeWeight(0.5);
        styleSplitPane(mainSplit);

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

        // Timer to periodically update finding counts, thread status, stats bar, and session status
        updateTimer = new Timer(3000, e -> {
            moduleListPanel.updateFindingsCounts();
            updateThreadStatus();
            updateStatsBar();
            updateSessionStatus();
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
                threadField.setBorder(BorderFactory.createLineBorder(NEON_RED, 2));
                threadField.setToolTipText("Invalid: thread count must be between 1 and 100");
            }
        } catch (NumberFormatException ex) {
            threadField.setBorder(BorderFactory.createLineBorder(NEON_RED, 2));
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
            startStopBtn.setBackground(BG_PANEL);
            startStopBtn.setForeground(NEON_RED);
            startStopBtn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(NEON_RED, 1),
                    BorderFactory.createEmptyBorder(4, 12, 4, 12)));
            statusLabel.setText("Running");
            statusLabel.setForeground(NEON_GREEN);
            progressBar.setIndeterminate(true);
            progressBar.setVisible(true);

            logPanel.log("INFO", "Framework", "Scanner started. Scope: " + scope
                    + " | Threads: " + executor.getThreadPoolSize());

        } else {
            // Stop scanning
            interceptor.setRunning(false);
            executor.cancelAll();
            startStopBtn.setText("Start Auto-Scan");
            startStopBtn.setBackground(BG_PANEL);
            startStopBtn.setForeground(NEON_GREEN);
            startStopBtn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(NEON_GREEN, 1),
                    BorderFactory.createEmptyBorder(4, 12, 4, 12)));
            statusLabel.setText("Stopped");
            statusLabel.setForeground(NEON_RED);
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
            } else if (panel instanceof DeserModulePanel) {
                ((DeserModulePanel) panel).stopTimers();
            }
        }
    }

    private static JLabel createSeverityBadge(String text, Color neon) {
        return CyberTheme.createSeverityBadge(text, neon);
    }

    /**
     * Polls the SessionKeepAlive status and updates the label.
     * Acts as a fallback in case the callback-based update misses an event.
     */
    private void updateSessionStatus() {
        SwingUtilities.invokeLater(() -> {
            String status = sessionKeepAlive.getStatusMessage();
            sessionStatusLabel.setText(status);
        });
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

    /**
     * Re-applies OmniStrike-specific component styling after a palette swap.
     * CyberTheme.applyRecursive handles most components; this method fixes
     * custom-styled elements like severity badges, the start/stop button,
     * and status labels that have specific color logic.
     */
    private void reapplyTheme() {
        SwingUtilities.invokeLater(() -> {
            // Re-style entire OmniStrike component tree with new CyberTheme colors
            CyberTheme.applyRecursive(this);

            // Fix start/stop button colors based on current state
            if (startStopBtn.isSelected()) {
                startStopBtn.setBackground(BG_PANEL);
                startStopBtn.setForeground(NEON_RED);
                startStopBtn.setFont(MONO_BOLD);
                startStopBtn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(NEON_RED, 1),
                        BorderFactory.createEmptyBorder(4, 12, 4, 12)));
                statusLabel.setText("Running");
                statusLabel.setForeground(NEON_GREEN);
                statusLabel.setFont(MONO_BOLD);
            } else {
                startStopBtn.setBackground(BG_PANEL);
                startStopBtn.setForeground(NEON_GREEN);
                startStopBtn.setFont(MONO_BOLD);
                startStopBtn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(NEON_GREEN, 1),
                        BorderFactory.createEmptyBorder(4, 12, 4, 12)));
                statusLabel.setText("Stopped");
                statusLabel.setForeground(NEON_RED);
                statusLabel.setFont(MONO_BOLD);
            }

            // Re-style severity badges with new palette colors
            restyleSeverityBadge(critLabel, SEV_CRITICAL);
            restyleSeverityBadge(highLabel, SEV_HIGH);
            restyleSeverityBadge(medLabel, SEV_MEDIUM);
            restyleSeverityBadge(lowLabel, SEV_LOW);
            restyleSeverityBadge(infoLabel, SEV_INFO);
            totalLabel.setForeground(FG_PRIMARY);
            totalLabel.setFont(MONO_BOLD);

            // Refresh severity badge text counts
            updateStatsBar();

            // Repaint everything
            revalidate();
            repaint();
        });
    }

    /** Re-applies neon badge styling to a severity label with the current theme colors. */
    private void restyleSeverityBadge(JLabel badge, Color neonColor) {
        badge.setOpaque(true);
        badge.setBackground(CyberTheme.darken(neonColor, 0.2f));
        badge.setForeground(neonColor);
        badge.setFont(MONO_BOLD.deriveFont(11f));
        badge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(neonColor, 1),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
    }

    public LogPanel getLogPanel() {
        return logPanel;
    }

    /** Returns the custom DeserModulePanel, or null if not yet created. */
    public DeserModulePanel getDeserModulePanel() {
        return deserModulePanel;
    }

    /** Programmatically switches to the given module's detail panel. */
    public void selectModule(String moduleId) {
        SwingUtilities.invokeLater(() -> {
            cardLayout.show(moduleDetailContainer, moduleId);
            moduleListPanel.selectModule(moduleId);
        });
    }
}
