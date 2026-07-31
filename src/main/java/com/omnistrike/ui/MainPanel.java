package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.*;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ScanModule;
import com.omnistrike.model.Severity;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.framework.stepper.StepperEngine;
import com.omnistrike.ui.modules.AiModulePanel;
import com.omnistrike.ui.modules.DeserModulePanel;
import com.omnistrike.ui.modules.GenericModulePanel;
import com.omnistrike.ui.modules.StepperPanel;
import com.omnistrike.ui.modules.WordlistGeneratorPanel;
import com.omnistrike.framework.wordlist.WordlistGenerator;

import com.omnistrike.framework.OobListener;
import com.omnistrike.framework.CollaboratorManager.OobMode;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.HashMap;
import java.util.List;
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
    private final StepperEngine stepperEngine;
    private final com.omnistrike.framework.tls.TlsAnalyzer tlsAnalyzer;
    private final SharedDataBus dataBus;
    private final PersistenceManager persistence;
    private final MontoyaApi api;
    private final LogPanel logPanel;

    private final JPanel moduleDetailContainer;
    private final CardLayout cardLayout;
    private final Map<String, JPanel> modulePanels = new HashMap<>();
    private final ModuleListPanel moduleListPanel;
    private final JTextField threadField;
    private final JTextField rateLimitField;
    private final JLabel threadStatusLabel;

    // Store timer as a field so it can be stopped on extension unload
    private final Timer updateTimer;

    // Child panels that have timers
    private final FindingsOverviewPanel activeFindingsPanel;
    private final FindingsOverviewPanel passiveFindingsPanel;
    private final RequestResponsePanel requestResponsePanel;

    // Custom module panel for deserializer (exposed for context menu "Send to Deserializer")
    private DeserModulePanel deserModulePanel;

    // Credit label pulse timer — tracked for cleanup on unload
    private Timer creditPulseTimer;

    // Stepper panel (prerequisite request chain)
    private StepperPanel stepperPanel;

    // Wordlist Generator panel
    private WordlistGeneratorPanel wordlistPanel;

    // TLS Analyzer panel
    private com.omnistrike.ui.modules.TlsAnalyzerPanel tlsAnalyzerPanel;

    // Stats bar severity count labels
    private final JLabel critLabel;
    private final JLabel highLabel;
    private final JLabel medLabel;
    private final JLabel lowLabel;
    private final JLabel infoLabel;
    private final JLabel totalLabel;

    // Session keep-alive status label
    private final JLabel sessionStatusLabel;

    // Default border for thread field (saved for resetting after validation)
    private final Border defaultThreadFieldBorder;

    public MainPanel(ModuleRegistry registry, FindingsStore findingsStore, ScopeManager scopeManager,
                     ActiveScanExecutor executor, TrafficInterceptor interceptor,
                     CollaboratorManager collaboratorManager, SessionKeepAlive sessionKeepAlive,
                     StepperEngine stepperEngine,
                     com.omnistrike.framework.tls.TlsAnalyzer tlsAnalyzer,
                     SharedDataBus dataBus, PersistenceManager persistence, MontoyaApi api) {
        this.registry = registry;
        this.findingsStore = findingsStore;
        this.scopeManager = scopeManager;
        this.executor = executor;
        this.interceptor = interceptor;
        this.collaboratorManager = collaboratorManager;
        this.sessionKeepAlive = sessionKeepAlive;
        this.stepperEngine = stepperEngine;
        this.tlsAnalyzer = tlsAnalyzer;
        this.dataBus = dataBus;
        this.persistence = persistence;
        this.api = api;
        this.logPanel = new LogPanel();

        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        // ============ TOP AREA (2 rows + stats bar) ============
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBackground(BG_DARK);
        topContainer.setBorder(new CyberTheme.GlowMatteBorder(0, 0, 1, 0, BORDER));

        // --- Row 1: Threads, Throttle, Theme ---
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        row1.setBackground(BG_DARK);

        JLabel threadsLabel = new JLabel("Threads:");
        threadsLabel.setForeground(NEON_CYAN);
        threadsLabel.setFont(MONO_LABEL);
        row1.add(threadsLabel);
        int savedThreads = persistence.getInt("scan.threads", 5);
        if (savedThreads < 1 || savedThreads > 100) savedThreads = 5;
        // Apply the restored thread count to the shared scan pool immediately.
        executor.resize(savedThreads);
        threadField = new JTextField(String.valueOf(savedThreads), 3);
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

        // ── Throttle mode: No Throttle / Auto / Manual ─────────────────────
        JLabel throttleLabel = new JLabel("Throttle:");
        throttleLabel.setForeground(NEON_CYAN);
        throttleLabel.setFont(MONO_LABEL);
        row1.add(throttleLabel);

        JRadioButton noThrottleRadio = new JRadioButton("None");
        JRadioButton autoThrottleRadio = new JRadioButton("Auto");
        JRadioButton manualThrottleRadio = new JRadioButton("Manual:");
        styleRadioButton(noThrottleRadio);
        styleRadioButton(autoThrottleRadio);
        styleRadioButton(manualThrottleRadio);
        noThrottleRadio.setToolTipText("No delay between requests (fastest, noisiest)");
        autoThrottleRadio.setToolTipText("Automatically backs off when WAF/rate-limiting is detected. Cools down when traffic flows normally.");
        manualThrottleRadio.setToolTipText("Fixed delay between requests in milliseconds");
        noThrottleRadio.setSelected(true); // Default: no throttle

        ButtonGroup throttleGroup = new ButtonGroup();
        throttleGroup.add(noThrottleRadio);
        throttleGroup.add(autoThrottleRadio);
        throttleGroup.add(manualThrottleRadio);

        int savedDelay = persistence.getInt("throttle.manualMs", 500);
        if (savedDelay < 0) savedDelay = 500;
        rateLimitField = new JTextField(String.valueOf(savedDelay), 4);
        styleTextField(rateLimitField);
        rateLimitField.setToolTipText("Delay in milliseconds between each scan request (Manual mode only)");
        rateLimitField.setEnabled(false); // Disabled until Manual is selected

        // Throttle mode change handler
        java.awt.event.ActionListener throttleModeListener = e -> {
            com.omnistrike.framework.ThrottleController tc = executor.getThrottleController();
            if (tc == null) return;
            if (noThrottleRadio.isSelected()) {
                tc.setMode(com.omnistrike.framework.ThrottleController.ThrottleMode.NONE);
                rateLimitField.setEnabled(false);
                persistence.setString("throttle.mode", "NONE");
            } else if (autoThrottleRadio.isSelected()) {
                tc.setMode(com.omnistrike.framework.ThrottleController.ThrottleMode.AUTO);
                rateLimitField.setEnabled(false);
                persistence.setString("throttle.mode", "AUTO");
            } else if (manualThrottleRadio.isSelected()) {
                tc.setMode(com.omnistrike.framework.ThrottleController.ThrottleMode.MANUAL);
                rateLimitField.setEnabled(true);
                applyManualThrottle();
                persistence.setString("throttle.mode", "MANUAL");
            }
        };
        noThrottleRadio.addActionListener(throttleModeListener);
        autoThrottleRadio.addActionListener(throttleModeListener);
        manualThrottleRadio.addActionListener(throttleModeListener);

        // Restore the saved throttle mode + delay (setSelected doesn't fire the
        // listener, so apply to the controller directly).
        com.omnistrike.framework.ThrottleController savedTc = executor.getThrottleController();
        String savedThrottleMode = persistence.getString("throttle.mode", "NONE");
        if (savedTc != null) savedTc.setManualDelay(savedDelay);
        switch (savedThrottleMode) {
            case "AUTO" -> {
                autoThrottleRadio.setSelected(true);
                if (savedTc != null) savedTc.setMode(
                        com.omnistrike.framework.ThrottleController.ThrottleMode.AUTO);
            }
            case "MANUAL" -> {
                manualThrottleRadio.setSelected(true);
                rateLimitField.setEnabled(true);
                if (savedTc != null) savedTc.setMode(
                        com.omnistrike.framework.ThrottleController.ThrottleMode.MANUAL);
            }
            default -> {
                noThrottleRadio.setSelected(true);
                if (savedTc != null) savedTc.setMode(
                        com.omnistrike.framework.ThrottleController.ThrottleMode.NONE);
            }
        }

        // Manual delay field — live-sync to ThrottleController
        rateLimitField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyManualThrottle(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyManualThrottle(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyManualThrottle(); }
        });

        row1.add(noThrottleRadio);
        row1.add(autoThrottleRadio);
        row1.add(manualThrottleRadio);
        row1.add(rateLimitField);
        JLabel msLabel = new JLabel("ms");
        msLabel.setForeground(FG_SECONDARY);
        msLabel.setFont(MONO_LABEL);
        row1.add(msLabel);

        // Theme selector dropdown
        JLabel themeLabel = new JLabel("Theme:");
        themeLabel.setForeground(NEON_CYAN);
        themeLabel.setFont(MONO_LABEL);
        row1.add(themeLabel);

        JComboBox<String> themeCombo = new JComboBox<>(GlobalThemeManager.THEME_NAMES);
        themeCombo.setSelectedIndex(0); // Default
        styleComboBox(themeCombo);
        themeCombo.setToolTipText("Switch OmniStrike theme");
        row1.add(themeCombo);

        // Scope radio buttons: OmniStrike Only vs Apply Globally
        JRadioButton scopeLocalRadio = new JRadioButton("OmniStrike Only");
        JRadioButton scopeGlobalRadio = new JRadioButton("Apply Globally");
        styleRadioButton(scopeLocalRadio);
        styleRadioButton(scopeGlobalRadio);
        scopeLocalRadio.setSelected(true);
        scopeLocalRadio.setToolTipText("Theme applies only to the OmniStrike tab — Burp's own panels stay native");
        scopeGlobalRadio.setToolTipText("Theme applies to the entire Burp Suite application");
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(scopeLocalRadio);
        scopeGroup.add(scopeGlobalRadio);
        // Initially hidden (no theme selected = Default)
        scopeLocalRadio.setVisible(false);
        scopeGlobalRadio.setVisible(false);

        scopeLocalRadio.addActionListener(e -> {
            GlobalThemeManager.changeScope(GlobalThemeManager.ThemeScope.OMNISTRIKE_ONLY);
            persistence.setString("theme.scope", "OMNISTRIKE_ONLY");
            reapplyTheme();
        });
        scopeGlobalRadio.addActionListener(e -> {
            GlobalThemeManager.changeScope(GlobalThemeManager.ThemeScope.GLOBAL);
            persistence.setString("theme.scope", "GLOBAL");
            reapplyTheme();
        });
        row1.add(scopeLocalRadio);
        row1.add(scopeGlobalRadio);

        // Ambient Glow toggle — subtle breathing color overlay
        JCheckBox glowCheckbox = new JCheckBox("Ambient Glow");
        styleCheckBox(glowCheckbox);
        glowCheckbox.setSelected(false);
        glowCheckbox.setToolTipText("Toggle a subtle breathing glow effect on themed UI borders");
        glowCheckbox.addActionListener(e -> {
            if (glowCheckbox.isSelected()) {
                GlobalThemeManager.startBreathing();
            } else {
                GlobalThemeManager.stopBreathing();
            }
            persistence.setBoolean("theme.glow", glowCheckbox.isSelected());
        });
        row1.add(glowCheckbox);

        // Theme combo listener — wired after scope radios and glow checkbox exist
        // Once a theme is selected, "Default" is removed from the dropdown (reload extension to revert).
        final boolean[] defaultRemoved = {false};
        themeCombo.addActionListener(e -> {
            int idx = themeCombo.getSelectedIndex();
            if (idx < 0) return;

            // After "Default" is removed, all indices shift down by 1
            int paletteIdx = defaultRemoved[0] ? idx + 1 : idx;
            if (paletteIdx < 0 || paletteIdx >= GlobalThemeManager.ALL_THEMES.length) return;

            ThemePalette palette = GlobalThemeManager.ALL_THEMES[paletteIdx];

            // First time selecting a real theme — remove "Default" from dropdown
            if (palette != null && !defaultRemoved[0]) {
                defaultRemoved[0] = true;
                themeCombo.removeItemAt(0); // remove "Default"
                // removeItemAt fires another action event, but defaultRemoved is already true
                // so it won't recurse. The selection auto-adjusts.
            }

            if (palette != null) {
                scopeLocalRadio.setVisible(true);
                scopeGlobalRadio.setVisible(true);
                glowCheckbox.setEnabled(true);

                GlobalThemeManager.applyTheme(palette);
                if (paletteIdx >= 0 && paletteIdx < GlobalThemeManager.THEME_NAMES.length) {
                    persistence.setString("theme.name", GlobalThemeManager.THEME_NAMES[paletteIdx]);
                }
                reapplyTheme();
            }
        });

        // Restore a previously-selected theme. setSelectedItem fires the combo
        // listener above, which applies the palette and removes "Default".
        try {
            String savedTheme = persistence.getString("theme.name", "Default");
            if (savedTheme != null && !"Default".equals(savedTheme)) {
                themeCombo.setSelectedItem(savedTheme);
                if ("GLOBAL".equals(persistence.getString("theme.scope", "OMNISTRIKE_ONLY"))) {
                    scopeGlobalRadio.setSelected(true);
                    GlobalThemeManager.changeScope(GlobalThemeManager.ThemeScope.GLOBAL);
                    reapplyTheme();
                }
                if (persistence.getBoolean("theme.glow", false)) {
                    glowCheckbox.setSelected(true);
                    GlobalThemeManager.startBreathing();
                }
            }
        } catch (Exception ignored) {
            // Theme restore is best-effort — never block the UI from loading.
        }

        topContainer.add(row1);

        // --- Row 2: Stop Scans, Time-Based Testing, Thread Status, OOB Status ---
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        row2.setBackground(BG_DARK);

        JButton stopScansBtn = new JButton("Stop Scans");
        stopScansBtn.setBackground(BG_PANEL);
        stopScansBtn.setForeground(NEON_RED);
        stopScansBtn.setFocusPainted(false);
        stopScansBtn.setFont(MONO_BOLD);
        stopScansBtn.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowLineBorder(NEON_RED, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        stopScansBtn.setToolTipText("Stop all scans launched via right-click context menu");
        stopScansBtn.addActionListener(e -> {
            int stopped = interceptor.stopManualScans();
            if (stopped > 0) {
                logPanel.log("INFO", "Framework", "Stopped " + stopped + " scan task(s).");
            } else {
                logPanel.log("INFO", "Framework", "No scans running.");
            }
        });
        row2.add(stopScansBtn);

        // Time-based testing toggle — disabled by default, must be explicitly enabled.
        // Controls ALL time-based blind injection tests (SQLi sleep, CmdI sleep/ping).
        JCheckBox timeBasedCheckbox = new JCheckBox("Time-Based Testing");
        styleCheckBox(timeBasedCheckbox);
        boolean savedTimeBased = persistence.getBoolean("scan.timeBased", false);
        timeBasedCheckbox.setSelected(savedTimeBased);
        TimingLock.setEnabled(savedTimeBased); // apply restored value
        timeBasedCheckbox.setToolTipText(
                "Enable time-based blind injection tests (SQLi SLEEP, CmdI sleep/ping). "
                + "These tests are slow and can cause delays on the target server. "
                + "Disabled by default — tick to enable.");
        timeBasedCheckbox.addActionListener(e -> {
            boolean selected = timeBasedCheckbox.isSelected();
            TimingLock.setEnabled(selected);
            persistence.setBoolean("scan.timeBased", selected);
            logPanel.log("INFO", "Framework",
                    "Time-based blind testing " + (selected ? "ENABLED" : "DISABLED"));
        });
        row2.add(timeBasedCheckbox);

        threadStatusLabel = new JLabel("Threads: 0 active | Queue: 0");
        threadStatusLabel.setForeground(FG_SECONDARY);
        threadStatusLabel.setFont(MONO_SMALL);
        row2.add(threadStatusLabel);

        // OOB mode status (compact indicator in row2)
        JLabel oobStatusLabel = new JLabel("OOB: Initializing...");
        oobStatusLabel.setForeground(FG_DIM);
        oobStatusLabel.setFont(MONO_SMALL);
        row2.add(oobStatusLabel);

        topContainer.add(row2);

        // --- OOB Configuration Row ---
        JPanel oobRow = buildOobConfigRow(oobStatusLabel);
        topContainer.add(oobRow);

        // --- Row 3: Session Keep-Alive controls ---
        JPanel sessionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        sessionRow.setBackground(BG_DARK);

        JCheckBox sessionCheckbox = new JCheckBox("Session Keep-Alive");
        styleCheckBox(sessionCheckbox);
        sessionCheckbox.setSelected(false);
        sessionCheckbox.setToolTipText(
                "Periodically replay an in-memory login request to keep session cookies fresh. "
                + "Right-click any request > 'Set as Session Login Request' to configure.");
        sessionRow.add(sessionCheckbox);

        JLabel intervalLabel = new JLabel("Interval:");
        intervalLabel.setForeground(NEON_CYAN);
        intervalLabel.setFont(MONO_LABEL);
        sessionRow.add(intervalLabel);
        JComboBox<String> intervalCombo = new JComboBox<>(new String[]{
                "1 min", "2 min", "3 min", "5 min", "10 min", "15 min", "30 min"});
        // Reflect the interval restored by SessionKeepAlive.loadPersistedState().
        intervalCombo.setSelectedItem(sessionKeepAlive.getIntervalMinutes() + " min");
        if (intervalCombo.getSelectedItem() == null) intervalCombo.setSelectedItem("5 min");
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
                creditPulseTimer = pulseTimer; // Store reference for cleanup
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

        // Create a detail panel only for modules reachable from the sidebar:
        // AI, passive analyzers, and the framework-backed modules below. Pure active
        // scanners are right-click only and have no sidebar entry, so they need no panel.
        java.util.Set<String> activeFrameworkBacked = java.util.Set.of("deser-scanner", "graphql-tool");
        for (ScanModule module : registry.getAllModules()) {
            JPanel panel;
            if ("ai-vuln-analyzer".equals(module.getId()) && module instanceof AiVulnAnalyzer aiModule) {
                panel = new AiModulePanel(aiModule, findingsStore, registry, api, scopeManager);
            } else if ("deser-scanner".equals(module.getId())) {
                deserModulePanel = new DeserModulePanel(api, findingsStore);
                panel = deserModulePanel;
            } else if ("wordlist-generator".equals(module.getId()) && module instanceof WordlistGenerator wlModule) {
                wordlistPanel = new WordlistGeneratorPanel(wlModule);
                panel = wordlistPanel;
            } else if (!module.isPassive() && !activeFrameworkBacked.contains(module.getId())) {
                continue; // active scanner — right-click only, not shown in sidebar
            } else {
                panel = new GenericModulePanel(module.getId(), module.getName(), findingsStore, api);
            }
            modulePanels.put(module.getId(), panel);
            moduleDetailContainer.add(panel, module.getId());
        }

        // Register Stepper panel as a framework tool
        if (stepperEngine != null) {
            stepperPanel = new StepperPanel(stepperEngine);
            modulePanels.put("stepper", stepperPanel);
            moduleDetailContainer.add(stepperPanel, "stepper");
            moduleListPanel.addFrameworkEntry("stepper", "Stepper",
                    "Prerequisite Request Chain");
        }

        // Register Deserialization as a framework tool — it generates deserialization
        // payloads (active scanning of requests is still available via right-click).
        moduleListPanel.addFrameworkEntry("deser-scanner", "Deserialization Generator",
                "Generate Deserialization Payloads");

        // Register GraphQL Tool as a framework tool
        moduleListPanel.addFrameworkEntry("graphql-tool", "GraphQL Tool",
                "GraphQL Introspection & Security Scanner");

        // Register Wordlist Generator as a framework tool (passive word harvester)
        moduleListPanel.addFrameworkEntry("wordlist-generator", "Wordlist Generator",
                "Passive Word Harvester & Exporter");

        // Register File Payload Generator as a framework tool
        {
            com.omnistrike.ui.modules.FilePayloadPanel filePayloadPanel = new com.omnistrike.ui.modules.FilePayloadPanel();
            modulePanels.put("file-payload-generator", filePayloadPanel);
            moduleDetailContainer.add(filePayloadPanel, "file-payload-generator");
            moduleListPanel.addFrameworkEntry("file-payload-generator", "File Payload Generator",
                    "Generate POC Files & Payloads for Upload Testing");
        }

        // Register TLS Analyzer as a framework tool (manual-trigger, out-of-band probe)
        if (tlsAnalyzer != null) {
            tlsAnalyzerPanel = new com.omnistrike.ui.modules.TlsAnalyzerPanel(tlsAnalyzer);
            modulePanels.put("tls-analyzer", tlsAnalyzerPanel);
            moduleDetailContainer.add(tlsAnalyzerPanel, "tls-analyzer");
            moduleListPanel.addFrameworkEntry("tls-analyzer", "TLS Analyzer",
                    "TLS / SSL Version, Cipher & Certificate Inspection");
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
        bottomTabs.addTab("Attack Surface", new AttackSurfacePanel(findingsStore, scopeManager, dataBus));
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

        // Register this panel as the OmniStrike root for scoped theming
        GlobalThemeManager.setOmniStrikeRoot(this);
    }

    /**
     * Builds the OOB Configuration row with radio buttons, network interface selector,
     * port field, and start/stop listener button.
     */
    private JPanel buildOobConfigRow(JLabel oobStatusLabel) {
        JPanel oobPanel = new JPanel();
        oobPanel.setLayout(new BoxLayout(oobPanel, BoxLayout.Y_AXIS));
        oobPanel.setBackground(BG_DARK);
        CyberTheme.styleTitledBorder(oobPanel, "OOB Configuration", NEON_CYAN);

        // --- Radio buttons row ---
        JPanel radioRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        radioRow.setBackground(BG_DARK);

        JRadioButton burpCollabRadio = new JRadioButton("Burp Collaborator (requires Pro)");
        styleRadioButton(burpCollabRadio);
        JRadioButton customOobRadio = new JRadioButton("Custom OOB Listener (intranet / self-hosted)");
        styleRadioButton(customOobRadio);

        ButtonGroup oobGroup = new ButtonGroup();
        oobGroup.add(burpCollabRadio);
        oobGroup.add(customOobRadio);

        // Restore the saved OOB mode (the listener is never fired by setSelected,
        // so apply it to the manager directly via switchTo* below).
        String savedOobMode = persistence.getString("oob.mode", null);
        if ("CUSTOM".equals(savedOobMode)) {
            collaboratorManager.switchToCustomOob();
        } else if ("BURP".equals(savedOobMode)) {
            collaboratorManager.switchToBurpCollaborator();
        }

        // Default selection based on current mode
        if (collaboratorManager.getMode() == OobMode.CUSTOM_OOB) {
            customOobRadio.setSelected(true);
        } else {
            burpCollabRadio.setSelected(true);
        }

        radioRow.add(burpCollabRadio);
        radioRow.add(customOobRadio);
        oobPanel.add(radioRow);

        // --- Custom OOB controls (hidden when Burp Collaborator is selected) ---
        JPanel customControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        customControls.setBackground(BG_DARK);

        // Network interface dropdown
        JLabel ifaceLabel = new JLabel("Interface:");
        ifaceLabel.setForeground(NEON_CYAN);
        ifaceLabel.setFont(MONO_LABEL);
        customControls.add(ifaceLabel);

        JComboBox<String> ifaceCombo = new JComboBox<>();
        List<String[]> interfaces = OobListener.getNetworkInterfaces();
        for (String[] iface : interfaces) {
            ifaceCombo.addItem(iface[0] + " - " + iface[1]);
        }
        styleComboBox(ifaceCombo);
        ifaceCombo.setToolTipText("IP address the target server will call back to. Must be reachable from the target.");
        // Restore the saved interface selection (indices are stable per machine).
        int savedIface = persistence.getInt("oob.ifaceIndex", -1);
        if (savedIface >= 0 && savedIface < ifaceCombo.getItemCount()) {
            ifaceCombo.setSelectedIndex(savedIface);
        }
        customControls.add(ifaceCombo);

        // HTTP Port field
        JLabel portLabel = new JLabel("HTTP Port:");
        portLabel.setForeground(NEON_CYAN);
        portLabel.setFont(MONO_LABEL);
        customControls.add(portLabel);

        int initialPort = persistence.getInt("oob.httpPort", OobListener.randomAvailablePort());
        JTextField portField = new JTextField(String.valueOf(initialPort), 6);
        styleTextField(portField);
        portField.setToolTipText("Port for the OOB HTTP listener (TCP)");
        customControls.add(portField);

        // DNS Port field
        JLabel dnsPortLabel = new JLabel("DNS Port:");
        dnsPortLabel.setForeground(NEON_CYAN);
        dnsPortLabel.setFont(MONO_LABEL);
        customControls.add(dnsPortLabel);

        int initialDnsPort = persistence.getInt("oob.dnsPort", OobListener.randomAvailableUdpPort());
        JTextField dnsPortField = new JTextField(String.valueOf(initialDnsPort), 6);
        styleTextField(dnsPortField);
        dnsPortField.setToolTipText("Port for the OOB DNS listener (UDP). Default 53 requires root/admin.");
        customControls.add(dnsPortField);

        // LDAP Port field
        JLabel ldapPortLabel = new JLabel("LDAP Port:");
        ldapPortLabel.setForeground(NEON_CYAN);
        ldapPortLabel.setFont(MONO_LABEL);
        customControls.add(ldapPortLabel);

        int initialLdapPort = persistence.getInt("oob.ldapPort", OobListener.randomAvailablePort());
        JTextField ldapPortField = new JTextField(String.valueOf(initialLdapPort), 6);
        styleTextField(ldapPortField);
        ldapPortField.setToolTipText("Port for the OOB LDAP listener (TCP). 0 = disabled. Default 389 requires root/admin.");
        customControls.add(ldapPortField);

        JButton randomizeBtn = new JButton("Randomize");
        styleButton(randomizeBtn, null);
        randomizeBtn.addActionListener(e -> {
            portField.setText(String.valueOf(OobListener.randomAvailablePort()));
            dnsPortField.setText(String.valueOf(OobListener.randomAvailableUdpPort()));
            ldapPortField.setText(String.valueOf(OobListener.randomAvailablePort()));
        });
        customControls.add(randomizeBtn);

        // Start/Stop listener button
        JToggleButton listenerToggle = new JToggleButton("Start Listener");
        listenerToggle.setBackground(BG_PANEL);
        listenerToggle.setForeground(NEON_GREEN);
        listenerToggle.setFocusPainted(false);
        listenerToggle.setFont(MONO_BOLD);
        listenerToggle.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowLineBorder(NEON_GREEN, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        customControls.add(listenerToggle);

        oobPanel.add(customControls);

        // --- Listener status row (separate line so it doesn't get truncated) ---
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusRow.setBackground(BG_DARK);
        JLabel listenerStatusLabel = new JLabel("Status: Not started");
        listenerStatusLabel.setForeground(FG_SECONDARY);
        listenerStatusLabel.setFont(MONO_BOLD);
        statusRow.add(listenerStatusLabel);
        oobPanel.add(statusRow);

        // --- Payload preview label ---
        JPanel previewRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        previewRow.setBackground(BG_DARK);
        JLabel previewLabel = new JLabel("");
        previewLabel.setForeground(FG_DIM);
        previewLabel.setFont(MONO_SMALL);
        previewRow.add(previewLabel);
        oobPanel.add(previewRow);

        // --- Update preview when interface or port changes ---
        Runnable updatePreview = () -> {
            int selectedIdx = ifaceCombo.getSelectedIndex();
            if (selectedIdx >= 0 && selectedIdx < interfaces.size()) {
                String ip = interfaces.get(selectedIdx)[1];
                String httpPortText = portField.getText().trim();
                String dnsPortText  = dnsPortField.getText().trim();
                String ldapPortText = ldapPortField.getText().trim();
                StringBuilder sb = new StringBuilder();
                sb.append("HTTP: http://").append(ip).append(":").append(httpPortText).append("/<id>");
                sb.append("   |   DNS: nslookup <id>.").append(ip).append(" ").append(ip)
                  .append(" (port ").append(dnsPortText).append(")");
                try {
                    int lp = Integer.parseInt(ldapPortText);
                    if (lp > 0) sb.append("   |   LDAP: ldap://").append(ip).append(":").append(ldapPortText).append("/<id>");
                } catch (NumberFormatException ignored) {}
                previewLabel.setText(sb.toString());
            }
        };
        ifaceCombo.addActionListener(e -> {
            updatePreview.run();
            persistence.setInt("oob.ifaceIndex", ifaceCombo.getSelectedIndex());
        });
        // Persist each port field as it changes (best-effort: only when parseable).
        Runnable persistOobPorts = () -> {
            try { persistence.setInt("oob.httpPort", Integer.parseInt(portField.getText().trim())); }
            catch (NumberFormatException ignored) {}
            try { persistence.setInt("oob.dnsPort", Integer.parseInt(dnsPortField.getText().trim())); }
            catch (NumberFormatException ignored) {}
            try { persistence.setInt("oob.ldapPort", Integer.parseInt(ldapPortField.getText().trim())); }
            catch (NumberFormatException ignored) {}
        };
        javax.swing.event.DocumentListener previewDocListener = new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); persistOobPorts.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); persistOobPorts.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); persistOobPorts.run(); }
        };
        portField.getDocument().addDocumentListener(previewDocListener);
        dnsPortField.getDocument().addDocumentListener(previewDocListener);
        ldapPortField.getDocument().addDocumentListener(previewDocListener);
        updatePreview.run();

        // --- Visibility toggle ---
        customControls.setVisible(customOobRadio.isSelected());
        statusRow.setVisible(customOobRadio.isSelected());
        previewRow.setVisible(customOobRadio.isSelected());

        // --- Radio button actions ---
        burpCollabRadio.addActionListener(e -> {
            customControls.setVisible(false);
            statusRow.setVisible(false);
            previewRow.setVisible(false);
            // Stop listener if running
            if (listenerToggle.isSelected()) {
                listenerToggle.doClick(); // triggers stop
            }
            collaboratorManager.switchToBurpCollaborator();
            persistence.setString("oob.mode", "BURP");
            updateOobStatus(oobStatusLabel);
            logPanel.log("INFO", "OOB", "Switched to Burp Collaborator mode");
        });

        customOobRadio.addActionListener(e -> {
            customControls.setVisible(true);
            statusRow.setVisible(true);
            previewRow.setVisible(true);
            collaboratorManager.switchToCustomOob();
            persistence.setString("oob.mode", "CUSTOM");
            updateOobStatus(oobStatusLabel);
            logPanel.log("INFO", "OOB", "Switched to Custom OOB Listener mode");
        });

        // --- Start/Stop listener toggle ---
        listenerToggle.addActionListener(e -> {
            if (listenerToggle.isSelected()) {
                // Start listener
                int selectedIdx = ifaceCombo.getSelectedIndex();
                if (selectedIdx < 0 || selectedIdx >= interfaces.size()) {
                    JOptionPane.showMessageDialog(this, "Please select a network interface.");
                    listenerToggle.setSelected(false);
                    return;
                }
                String ip = interfaces.get(selectedIdx)[1];
                int httpPort;
                try {
                    httpPort = Integer.parseInt(portField.getText().trim());
                    if (httpPort < 1 || httpPort > 65535) throw new NumberFormatException();
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(this, "Invalid HTTP port number (1-65535).");
                    listenerToggle.setSelected(false);
                    return;
                }
                int dnsPort;
                try {
                    dnsPort = Integer.parseInt(dnsPortField.getText().trim());
                    if (dnsPort < 1 || dnsPort > 65535) throw new NumberFormatException();
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(this, "Invalid DNS port number (1-65535).");
                    listenerToggle.setSelected(false);
                    return;
                }

                // LDAP port: 0 = disabled, any valid port starts the listener
                int ldapPort = 0;
                String ldapPortText = ldapPortField.getText().trim();
                if (!ldapPortText.isEmpty() && !ldapPortText.equals("0")) {
                    try {
                        ldapPort = Integer.parseInt(ldapPortText);
                        if (ldapPort < 1 || ldapPort > 65535) throw new NumberFormatException();
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(this, "Invalid LDAP port number (1-65535 or 0 to disable).");
                        listenerToggle.setSelected(false);
                        return;
                    }
                }

                boolean started;
                try {
                    started = collaboratorManager.initializeCustomOob(ip, httpPort, dnsPort, ldapPort);
                } catch (Throwable ex) {
                    listenerToggle.setSelected(false);
                    String errMsg = "CRASH: " + ex.getClass().getSimpleName() + ": " + ex.getMessage();
                    listenerStatusLabel.setText(errMsg);
                    listenerStatusLabel.setForeground(NEON_RED);
                    logPanel.log("ERROR", "OOB", errMsg);
                    return;
                }
                if (started) {
                    listenerToggle.setText("Stop Listener");
                    listenerToggle.setForeground(NEON_RED);
                    listenerToggle.setBorder(BorderFactory.createCompoundBorder(
                            new CyberTheme.GlowLineBorder(NEON_RED, 1),
                            BorderFactory.createEmptyBorder(4, 12, 4, 12)));
                    boolean dnsOk  = collaboratorManager.isCustomDnsRunning();
                    boolean ldapOk = collaboratorManager.isCustomLdapRunning();
                    StringBuilder statusText = new StringBuilder("Started — HTTP on " + ip + ":" + httpPort);
                    if (dnsOk) statusText.append(" | DNS:").append(dnsPort);
                    else        statusText.append(" | DNS FAILED");
                    if (ldapPort > 0) {
                        if (ldapOk) statusText.append(" | LDAP:").append(ldapPort);
                        else         statusText.append(" | LDAP FAILED");
                    }
                    listenerStatusLabel.setText(statusText.toString());
                    listenerStatusLabel.setForeground(NEON_GREEN);
                    ifaceCombo.setEnabled(false);
                    portField.setEnabled(false);
                    dnsPortField.setEnabled(false);
                    ldapPortField.setEnabled(false);
                    randomizeBtn.setEnabled(false);
                    logPanel.log("INFO", "OOB", "Custom OOB Listener started — HTTP:" + httpPort
                            + " DNS:" + (dnsOk ? String.valueOf(dnsPort) : "FAILED")
                            + (ldapPort > 0 ? " LDAP:" + (ldapOk ? String.valueOf(ldapPort) : "FAILED") : ""));
                } else {
                    listenerToggle.setSelected(false);
                    listenerStatusLabel.setText("Failed to start — check Activity Log for details");
                    listenerStatusLabel.setForeground(NEON_RED);
                }
            } else {
                // Stop listener
                collaboratorManager.stopCustomOob();
                listenerToggle.setText("Start Listener");
                listenerToggle.setForeground(NEON_GREEN);
                listenerToggle.setBorder(BorderFactory.createCompoundBorder(
                        new CyberTheme.GlowLineBorder(NEON_GREEN, 1),
                        BorderFactory.createEmptyBorder(4, 12, 4, 12)));
                listenerStatusLabel.setText("Stopped");
                listenerStatusLabel.setForeground(FG_SECONDARY);
                ifaceCombo.setEnabled(true);
                portField.setEnabled(true);
                dnsPortField.setEnabled(true);
                ldapPortField.setEnabled(true);
                randomizeBtn.setEnabled(true);
                logPanel.log("INFO", "OOB", "Custom OOB Listener stopped");
            }
            updateOobStatus(oobStatusLabel);
        });

        // Set initial OOB status
        updateOobStatus(oobStatusLabel);

        return oobPanel;
    }

    /**
     * Updates the compact OOB status label in row2 based on current mode and availability.
     */
    private void updateOobStatus(JLabel oobStatusLabel) {
        SwingUtilities.invokeLater(() -> {
            if (collaboratorManager.getMode() == OobMode.CUSTOM_OOB) {
                if (collaboratorManager.isCustomOobRunning()) {
                    oobStatusLabel.setText("OOB: Custom (" + collaboratorManager.getCustomAddress()
                            + ":" + collaboratorManager.getCustomPort() + ")");
                    oobStatusLabel.setForeground(NEON_GREEN);
                } else {
                    oobStatusLabel.setText("OOB: Custom (not started)");
                    oobStatusLabel.setForeground(NEON_ORANGE);
                }
            } else {
                if (collaboratorManager.isAvailable()) {
                    oobStatusLabel.setText("OOB: Collaborator Active");
                    oobStatusLabel.setForeground(NEON_GREEN);
                } else {
                    oobStatusLabel.setText("OOB: Collaborator N/A");
                    oobStatusLabel.setForeground(FG_DIM);
                }
            }
        });
    }

    /**
     * Applies the manual throttle delay from the UI field to the ThrottleController.
     */
    private void applyManualThrottle() {
        com.omnistrike.framework.ThrottleController tc = executor.getThrottleController();
        if (tc == null) return;
        String text = rateLimitField.getText().trim();
        if (text.isEmpty()) {
            tc.setManualDelay(0);
            return;
        }
        try {
            int value = Integer.parseInt(text);
            tc.setManualDelay(value);
            persistence.setInt("throttle.manualMs", value);
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
                // Apply immediately — right-click scans use this pool (no Start button anymore).
                executor.resize(value);
                persistence.setInt("scan.threads", value);
            } else {
                threadField.setBorder(new CyberTheme.GlowLineBorder(NEON_RED, 2));
                threadField.setToolTipText("Invalid: thread count must be between 1 and 100");
            }
        } catch (NumberFormatException ex) {
            threadField.setBorder(new CyberTheme.GlowLineBorder(NEON_RED, 2));
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
        });
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
        // Stop credit label pulse animation
        if (creditPulseTimer != null) {
            creditPulseTimer.stop();
        }
        // Stop ambient breathing glow if active
        GlobalThemeManager.stopBreathing();
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
            } else if (panel instanceof StepperPanel) {
                ((StepperPanel) panel).stopTimers();
            } else if (panel instanceof WordlistGeneratorPanel) {
                ((WordlistGeneratorPanel) panel).stopTimers();
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
            if (CyberTheme.isNativeMode()) {
                // Strip all custom styling — return to Burp native L&F
                CyberTheme.stripRecursive(this);
                revalidate();
                repaint();
                return;
            }

            // Re-style entire OmniStrike component tree with new CyberTheme colors
            CyberTheme.applyRecursive(this);

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
                new CyberTheme.GlowLineBorder(neonColor, 1),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
    }

    public LogPanel getLogPanel() {
        return logPanel;
    }

    /** Returns the custom DeserModulePanel, or null if not yet created. */
    public DeserModulePanel getDeserModulePanel() {
        return deserModulePanel;
    }

    /** Returns the TLS Analyzer panel, or null if not yet created. */
    public com.omnistrike.ui.modules.TlsAnalyzerPanel getTlsAnalyzerPanel() {
        return tlsAnalyzerPanel;
    }

    /** Programmatically switches to the given module's detail panel. */
    public void selectModule(String moduleId) {
        SwingUtilities.invokeLater(() -> {
            cardLayout.show(moduleDetailContainer, moduleId);
            moduleListPanel.selectModule(moduleId);
        });
    }
}
