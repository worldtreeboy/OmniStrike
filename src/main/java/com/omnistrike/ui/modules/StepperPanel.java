package com.omnistrike.ui.modules;

import com.omnistrike.framework.stepper.*;
import com.omnistrike.ui.CyberTheme;
import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * UI panel for the Stepper module — prerequisite request chain configuration.
 * Shows steps table, extraction rules for the selected step, and current variables.
 */
public class StepperPanel extends JPanel {

    private final StepperEngine engine;

    // Controls
    private final JCheckBox enabledCheckBox;
    private final JTextField cacheTtlField;
    private final JButton runChainBtn;

    // Steps table
    private final DefaultTableModel stepsModel;
    private final JTable stepsTable;

    // Extraction rules table (for selected step)
    private final DefaultTableModel rulesModel;
    private final JTable rulesTable;

    private JCheckBox stopOnFailureBox;
    private JCheckBox perRequestModeBox;
    private JButton pauseBtn;

    // Cookie jar table
    private JCheckBox cookieJarCheckBox;
    private DefaultTableModel cookieModel;
    private JTable cookieTable;

    // Current variables display
    private DefaultTableModel variablesModel;
    private JTable variablesTable;
    private JLabel lastRunLabel;

    // Refresh timer
    private Timer refreshTimer;

    public StepperPanel(StepperEngine engine) {
        this.engine = engine;
        setLayout(new BorderLayout(0, 6));
        setBackground(BG_DARK);
        styleTitledBorder(this, "Stepper — Prerequisite Request Chain", NEON_CYAN);

        // ════════════════════ TOP CONTROLS ════════════════════
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        topPanel.setBackground(BG_DARK);

        enabledCheckBox = new JCheckBox("Stepper Enabled");
        enabledCheckBox.setSelected(engine.isEnabled());
        styleCheckBox(enabledCheckBox);
        enabledCheckBox.setForeground(NEON_GREEN);
        enabledCheckBox.setFont(MONO_BOLD);
        enabledCheckBox.setToolTipText("Enable/disable the Stepper. When disabled, no prerequisite chains run and 'Send to Stepper' is hidden.");
        enabledCheckBox.addActionListener(e -> {
            engine.setEnabled(enabledCheckBox.isSelected());
            updateControlStates();
        });
        topPanel.add(enabledCheckBox);

        topPanel.add(Box.createHorizontalStrut(20));

        JLabel ttlLabel = new JLabel("Cache TTL:");
        ttlLabel.setForeground(FG_PRIMARY);
        ttlLabel.setFont(MONO_FONT);
        topPanel.add(ttlLabel);

        cacheTtlField = new JTextField(String.valueOf(engine.getCacheTtlSeconds()), 4);
        styleTextField(cacheTtlField);
        cacheTtlField.setToolTipText("Seconds to cache extracted variables before re-running the chain (0 = always re-run)");
        cacheTtlField.addActionListener(e -> applyCacheTtl());
        topPanel.add(cacheTtlField);

        JLabel secLabel = new JLabel("sec");
        secLabel.setForeground(FG_SECONDARY);
        secLabel.setFont(MONO_SMALL);
        topPanel.add(secLabel);

        topPanel.add(Box.createHorizontalStrut(20));

        runChainBtn = new JButton("Run Chain");
        styleButton(runChainBtn, NEON_GREEN);
        runChainBtn.setToolTipText("Manually execute all prerequisite steps now");
        runChainBtn.addActionListener(e -> {
            applyCacheTtl();
            runChainBtn.setEnabled(false);
            runChainBtn.setText("Running...");
            new SwingWorker<Boolean, Void>() {
                @Override
                protected Boolean doInBackground() {
                    return engine.runChainManually();
                }
                @Override
                protected void done() {
                    try {
                        boolean ok = get();
                        runChainBtn.setText(ok ? "Run Chain" : "Run Chain (failed)");
                    } catch (Exception ex) {
                        runChainBtn.setText("Run Chain (error)");
                    }
                    runChainBtn.setEnabled(true);
                    refreshVariablesDisplay();
                }
            }.execute();
        });
        topPanel.add(runChainBtn);

        JButton invalidateBtn = new JButton("Invalidate Cache");
        styleButton(invalidateBtn, NEON_ORANGE);
        invalidateBtn.setToolTipText("Force the next outgoing request to re-run the chain");
        invalidateBtn.addActionListener(e -> engine.invalidateCache());
        topPanel.add(invalidateBtn);

        pauseBtn = new JButton(engine.isPaused() ? "Resume" : "Pause Now");
        styleButton(pauseBtn, NEON_RED);
        pauseBtn.setToolTipText(
                "<html>Pause Stepper — new requests bypass the engine and in-flight chains abort at the next step.<br>"
                + "Auto-set when OmniStrike's scan is stopped. Use this manually when pausing Burp's built-in scanner<br>"
                + "(Burp doesn't notify extensions of pause/stop, so you have to hit this yourself).</html>");
        pauseBtn.addActionListener(e -> {
            engine.setPaused(!engine.isPaused());
            pauseBtn.setText(engine.isPaused() ? "Resume" : "Pause Now");
        });
        topPanel.add(pauseBtn);

        topPanel.add(Box.createHorizontalStrut(20));

        stopOnFailureBox = new JCheckBox("Stop on Failure");
        stopOnFailureBox.setSelected(engine.isStopOnFailure());
        styleCheckBox(stopOnFailureBox);
        stopOnFailureBox.setForeground(NEON_RED);
        stopOnFailureBox.setFont(MONO_FONT);
        stopOnFailureBox.setToolTipText("Abort the chain immediately if any step returns no response (connection error or timeout)");
        stopOnFailureBox.addActionListener(e -> engine.setStopOnFailure(stopOnFailureBox.isSelected()));
        topPanel.add(stopOnFailureBox);

        perRequestModeBox = new JCheckBox("Per-Request Mode");
        perRequestModeBox.setSelected(engine.isPerRequestMode());
        styleCheckBox(perRequestModeBox);
        perRequestModeBox.setForeground(NEON_MAGENTA);
        perRequestModeBox.setFont(MONO_BOLD);
        perRequestModeBox.setToolTipText(
                "<html>Run the chain BEFORE every outgoing request (no cache, no global lock).<br>"
                + "Required when prereq steps produce single-use tokens (CSRF nonces) that the target burns per request.<br>"
                + "Each Burp scanner thread runs its own A->B->C->D pipeline in parallel.<br><br>"
                + "<b>WARNING:</b> multiplies auth-server load by scanner concurrency. Some servers will rate-limit or lock the account.</html>");
        perRequestModeBox.addActionListener(e -> {
            engine.setPerRequestMode(perRequestModeBox.isSelected());
            updateControlStates();
        });
        topPanel.add(perRequestModeBox);

        // ════════════════════ EXPLANATION BANNER (collapsible) ════════════════════
        JPanel bannerPanel = new JPanel(new BorderLayout(0, 0));
        bannerPanel.setBackground(BG_SURFACE);
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowMatteBorder(1, 0, 1, 0, BORDER),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)));

        JTextArea helpText = new JTextArea(
                "HOW TO USE (auto-extraction):\n"
                + "  1. Enable Stepper (checkbox above)\n"
                + "  2. Right-click requests in Proxy/Repeater -> 'Send to Stepper' to add prerequisite steps\n"
                + "  3. In a later step or target request, write {{name}} anywhere — URL path, header, cookie, body.\n"
                + "     Stepper auto-finds 'name' in earlier responses (JSON key, header, cookie, or key=value pair).\n"
                + "     Example: response has {\"id\":\"abc\"} -> next request /api/{{id}}/xyz becomes /api/abc/xyz.\n"
                + "  4. Click 'Run Chain' to test, or just send a request — Stepper runs automatically.\n"
                + "  5. (Optional) Add an explicit Extraction Rule only if auto-resolve picks the wrong value\n"
                + "     (e.g. duplicate keys at different nesting levels — JSON_PATH 'data.id' lets you target one).");
        helpText.setEditable(false);
        helpText.setLineWrap(true);
        helpText.setWrapStyleWord(true);
        helpText.setBackground(BG_SURFACE);
        helpText.setForeground(FG_SECONDARY);
        helpText.setFont(MONO_SMALL);
        bannerPanel.add(helpText, BorderLayout.CENTER);

        // Toggle button to show/hide the help banner
        JButton helpToggle = new JButton("? Help");
        styleButton(helpToggle, NEON_CYAN);
        helpToggle.setMargin(new Insets(2, 8, 2, 8));
        bannerPanel.setVisible(false); // Collapsed by default
        helpToggle.addActionListener(e -> {
            bannerPanel.setVisible(!bannerPanel.isVisible());
            helpToggle.setText(bannerPanel.isVisible() ? "? Hide Help" : "? Help");
            revalidate();
        });
        topPanel.add(helpToggle);

        JPanel northWrapper = new JPanel();
        northWrapper.setLayout(new BoxLayout(northWrapper, BoxLayout.Y_AXIS));
        northWrapper.setBackground(BG_DARK);
        northWrapper.add(topPanel);
        northWrapper.add(bannerPanel);

        add(northWrapper, BorderLayout.NORTH);

        // ════════════════════ CENTER: Steps + Rules ════════════════════
        JPanel centerPanel = new JPanel(new BorderLayout(0, 6));
        centerPanel.setBackground(BG_DARK);

        // ── Steps Table ──
        JPanel stepsPanel = new JPanel(new BorderLayout(0, 4));
        stepsPanel.setBackground(BG_DARK);
        styleTitledBorder(stepsPanel, "Prerequisite Steps", NEON_CYAN);

        stepsModel = new DefaultTableModel(new String[]{"#", "Name", "URL", "Enabled"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        stepsTable = new JTable(stepsModel);
        styleTable(stepsTable);
        stepsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        stepsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        stepsTable.getColumnModel().getColumn(0).setMaxWidth(40);
        stepsTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        stepsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        stepsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        stepsTable.getColumnModel().getColumn(3).setMaxWidth(70);
        stepsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) refreshRulesTable();
        });

        JScrollPane stepsScroll = new JScrollPane(stepsTable);
        styleScrollPane(stepsScroll);
        stepsScroll.setPreferredSize(new Dimension(0, 160));
        stepsPanel.add(stepsScroll, BorderLayout.CENTER);

        // Steps buttons
        JPanel stepsBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        stepsBtnPanel.setBackground(BG_DARK);

        JButton upBtn = new JButton("\u25B2 Up");
        styleButton(upBtn, NEON_CYAN);
        upBtn.setMargin(new Insets(2, 8, 2, 8));
        upBtn.addActionListener(e -> {
            int sel = stepsTable.getSelectedRow();
            if (sel > 0) {
                engine.moveStepUp(sel);
                refreshStepsTable();
                stepsTable.setRowSelectionInterval(sel - 1, sel - 1);
            }
        });
        stepsBtnPanel.add(upBtn);

        JButton downBtn = new JButton("\u25BC Down");
        styleButton(downBtn, NEON_CYAN);
        downBtn.setMargin(new Insets(2, 8, 2, 8));
        downBtn.addActionListener(e -> {
            int sel = stepsTable.getSelectedRow();
            if (sel >= 0 && sel < stepsModel.getRowCount() - 1) {
                engine.moveStepDown(sel);
                refreshStepsTable();
                stepsTable.setRowSelectionInterval(sel + 1, sel + 1);
            }
        });
        stepsBtnPanel.add(downBtn);

        JButton toggleBtn = new JButton("Toggle");
        styleButton(toggleBtn, NEON_ORANGE);
        toggleBtn.setMargin(new Insets(2, 8, 2, 8));
        toggleBtn.setToolTipText("Enable/disable the selected step");
        toggleBtn.addActionListener(e -> {
            int sel = stepsTable.getSelectedRow();
            if (sel >= 0) {
                List<StepperStep> steps = engine.getSteps();
                if (sel < steps.size()) {
                    StepperStep step = steps.get(sel);
                    step.setEnabled(!step.isEnabled());
                    refreshStepsTable();
                    stepsTable.setRowSelectionInterval(sel, sel);
                }
            }
        });
        stepsBtnPanel.add(toggleBtn);

        JButton editBtn = new JButton("Edit Request");
        styleButton(editBtn, NEON_MAGENTA);
        editBtn.setMargin(new Insets(2, 8, 2, 8));
        editBtn.setToolTipText("Edit the raw HTTP request for this step. Insert {{varName}} placeholders to substitute values extracted from earlier steps.");
        editBtn.addActionListener(e -> {
            int sel = stepsTable.getSelectedRow();
            if (sel >= 0) {
                List<StepperStep> steps = engine.getSteps();
                if (sel < steps.size()) {
                    showEditRequestDialog(steps.get(sel));
                }
            }
        });
        stepsBtnPanel.add(editBtn);

        JButton removeBtn = new JButton("\u2715 Remove");
        styleButton(removeBtn, NEON_RED);
        removeBtn.setMargin(new Insets(2, 8, 2, 8));
        removeBtn.addActionListener(e -> {
            int sel = stepsTable.getSelectedRow();
            if (sel >= 0) {
                engine.removeStep(sel);
                refreshStepsTable();
            }
        });
        stepsBtnPanel.add(removeBtn);

        JButton clearBtn = new JButton("Clear All");
        styleButton(clearBtn, NEON_RED);
        clearBtn.setMargin(new Insets(2, 8, 2, 8));
        clearBtn.addActionListener(e -> {
            if (engine.getStepCount() > 0) {
                int confirm = JOptionPane.showConfirmDialog(this,
                        "Remove all " + engine.getStepCount() + " steps?",
                        "Clear Stepper", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    engine.clearSteps();
                    refreshStepsTable();
                    refreshRulesTable();
                    refreshVariablesDisplay();
                }
            }
        });
        stepsBtnPanel.add(clearBtn);

        stepsPanel.add(stepsBtnPanel, BorderLayout.SOUTH);

        // ── Extraction Rules Table ──
        JPanel rulesPanel = new JPanel(new BorderLayout(0, 4));
        rulesPanel.setBackground(BG_DARK);
        styleTitledBorder(rulesPanel, "Extraction Rules (for selected step)", NEON_MAGENTA);

        rulesModel = new DefaultTableModel(new String[]{"Variable", "Type", "Pattern", "Last Value"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        rulesTable = new JTable(rulesModel);
        styleTable(rulesTable);
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        rulesTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        rulesTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        rulesTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        rulesTable.getColumnModel().getColumn(3).setPreferredWidth(150);

        JScrollPane rulesScroll = new JScrollPane(rulesTable);
        styleScrollPane(rulesScroll);
        rulesScroll.setPreferredSize(new Dimension(0, 120));
        rulesPanel.add(rulesScroll, BorderLayout.CENTER);

        // Rules buttons
        JPanel rulesBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        rulesBtnPanel.setBackground(BG_DARK);

        JButton addRuleBtn = new JButton("+ Add Rule");
        styleButton(addRuleBtn, NEON_GREEN);
        addRuleBtn.setMargin(new Insets(2, 8, 2, 8));
        addRuleBtn.addActionListener(e -> showAddRuleDialog());
        rulesBtnPanel.add(addRuleBtn);

        JButton removeRuleBtn = new JButton("- Remove Rule");
        styleButton(removeRuleBtn, NEON_RED);
        removeRuleBtn.setMargin(new Insets(2, 8, 2, 8));
        removeRuleBtn.addActionListener(e -> {
            int stepIdx = stepsTable.getSelectedRow();
            int ruleIdx = rulesTable.getSelectedRow();
            if (stepIdx >= 0 && ruleIdx >= 0) {
                List<StepperStep> steps = engine.getSteps();
                if (stepIdx < steps.size()) {
                    steps.get(stepIdx).removeExtractionRule(ruleIdx);
                    refreshRulesTable();
                }
            }
        });
        rulesBtnPanel.add(removeRuleBtn);

        rulesPanel.add(rulesBtnPanel, BorderLayout.SOUTH);

        // Split steps and rules vertically
        JSplitPane stepRuleSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, stepsPanel, rulesPanel);
        stepRuleSplit.setDividerLocation(200);
        styleSplitPane(stepRuleSplit);
        stepRuleSplit.setDividerSize(8);
        centerPanel.add(stepRuleSplit, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        // ════════════════════ BOTTOM: Cookie Jar + Variables ════════════════════
        JPanel bottomPanel = new JPanel(new BorderLayout(0, 4));
        bottomPanel.setBackground(BG_DARK);

        // ── Cookie Jar Table ──
        JPanel cookiePanel = new JPanel(new BorderLayout(0, 4));
        cookiePanel.setBackground(BG_DARK);
        styleTitledBorder(cookiePanel, "Cookie Jar (auto-collected)", NEON_ORANGE);

        // Cookie jar toggle + buttons at top
        JPanel cookieTopPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        cookieTopPanel.setBackground(BG_DARK);

        cookieJarCheckBox = new JCheckBox("Auto Cookie Jar");
        cookieJarCheckBox.setSelected(engine.isCookieJarEnabled());
        styleCheckBox(cookieJarCheckBox);
        cookieJarCheckBox.setForeground(NEON_ORANGE);
        cookieJarCheckBox.setFont(MONO_BOLD);
        cookieJarCheckBox.setToolTipText("Automatically collect Set-Cookie from chain responses and inject into outgoing requests");
        cookieJarCheckBox.addActionListener(e -> engine.setCookieJarEnabled(cookieJarCheckBox.isSelected()));
        cookieTopPanel.add(cookieJarCheckBox);

        JButton addCookieBtn = new JButton("+ Add");
        styleButton(addCookieBtn, NEON_GREEN);
        addCookieBtn.setMargin(new Insets(2, 8, 2, 8));
        addCookieBtn.setToolTipText("Manually add a cookie to the jar");
        addCookieBtn.addActionListener(e -> showAddCookieDialog());
        cookieTopPanel.add(addCookieBtn);

        JButton removeCookieBtn = new JButton("- Remove");
        styleButton(removeCookieBtn, NEON_RED);
        removeCookieBtn.setMargin(new Insets(2, 8, 2, 8));
        removeCookieBtn.addActionListener(e -> {
            int sel = cookieTable.getSelectedRow();
            if (sel >= 0) {
                String name = (String) cookieModel.getValueAt(sel, 0);
                engine.removeCookie(name);
                refreshCookieTable();
            }
        });
        cookieTopPanel.add(removeCookieBtn);

        JButton clearCookieBtn = new JButton("Clear");
        styleButton(clearCookieBtn, NEON_RED);
        clearCookieBtn.setMargin(new Insets(2, 8, 2, 8));
        clearCookieBtn.addActionListener(e -> {
            engine.clearCookieJar();
            refreshCookieTable();
        });
        cookieTopPanel.add(clearCookieBtn);

        cookiePanel.add(cookieTopPanel, BorderLayout.NORTH);

        cookieModel = new DefaultTableModel(new String[]{"Cookie Name", "Value"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        cookieTable = new JTable(cookieModel);
        styleTable(cookieTable);
        cookieTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        cookieTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        cookieTable.getColumnModel().getColumn(1).setPreferredWidth(300);

        JScrollPane cookieScroll = new JScrollPane(cookieTable);
        styleScrollPane(cookieScroll);
        cookiePanel.add(cookieScroll, BorderLayout.CENTER);

        // ── Current Variables ──
        JPanel varPanel = new JPanel(new BorderLayout(0, 4));
        varPanel.setBackground(BG_DARK);
        styleTitledBorder(varPanel, "Current Variables", NEON_GREEN);

        // Top button row: +Add / -Remove / Clear
        JPanel varTopPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        varTopPanel.setBackground(BG_DARK);

        JButton addVarBtn = new JButton("+ Add");
        styleButton(addVarBtn, NEON_GREEN);
        addVarBtn.setMargin(new Insets(2, 8, 2, 8));
        addVarBtn.setToolTipText("Manually set or override a variable. Pinned vars survive chain re-runs and win over auto-extracted values.");
        addVarBtn.addActionListener(e -> showAddVariableDialog());
        varTopPanel.add(addVarBtn);

        JButton removeVarBtn = new JButton("- Remove");
        styleButton(removeVarBtn, NEON_RED);
        removeVarBtn.setMargin(new Insets(2, 8, 2, 8));
        removeVarBtn.addActionListener(e -> {
            int sel = variablesTable.getSelectedRow();
            if (sel >= 0) {
                String name = (String) variablesModel.getValueAt(sel, 0);
                // Strip the {{ }} wrapper
                if (name.startsWith("{{") && name.endsWith("}}")) {
                    name = name.substring(2, name.length() - 2);
                }
                engine.removeVariable(name);
                refreshVariablesDisplay();
            }
        });
        varTopPanel.add(removeVarBtn);

        JButton clearVarBtn = new JButton("Clear Pinned");
        styleButton(clearVarBtn, NEON_RED);
        clearVarBtn.setMargin(new Insets(2, 8, 2, 8));
        clearVarBtn.setToolTipText("Remove all manually-pinned variables. Auto-extracted vars stay until the next chain run.");
        clearVarBtn.addActionListener(e -> {
            engine.clearPinnedVariables();
            refreshVariablesDisplay();
        });
        varTopPanel.add(clearVarBtn);

        varPanel.add(varTopPanel, BorderLayout.NORTH);

        variablesModel = new DefaultTableModel(new String[]{"Variable", "Value", "Source"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        variablesTable = new JTable(variablesModel);
        styleTable(variablesTable);
        variablesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        variablesTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        variablesTable.getColumnModel().getColumn(1).setPreferredWidth(220);
        variablesTable.getColumnModel().getColumn(2).setPreferredWidth(80);

        JScrollPane varScroll = new JScrollPane(variablesTable);
        styleScrollPane(varScroll);
        varPanel.add(varScroll, BorderLayout.CENTER);

        // Status label at bottom — "Last chain run" info
        lastRunLabel = new JLabel(" ");
        lastRunLabel.setForeground(FG_SECONDARY);
        lastRunLabel.setFont(MONO_SMALL);
        lastRunLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        varPanel.add(lastRunLabel, BorderLayout.SOUTH);

        // Split cookie jar and variables side by side
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, cookiePanel, varPanel);
        bottomSplit.setDividerLocation(450);
        styleSplitPane(bottomSplit);
        bottomSplit.setDividerSize(8);
        bottomPanel.add(bottomSplit, BorderLayout.CENTER);

        add(bottomPanel, BorderLayout.SOUTH);
        bottomPanel.setPreferredSize(new Dimension(0, 160));

        // ════════════════════ Refresh Timer ════════════════════
        refreshTimer = new Timer(3000, e -> {
            refreshVariablesDisplay();
            refreshStepsTable();
            refreshCookieTable();
            // Sync the pause button label — engine may have been paused externally
            // (e.g. when OmniStrike's scan stop fired TrafficInterceptor.setPaused(true)).
            if (pauseBtn != null) {
                String desired = engine.isPaused() ? "Resume" : "Pause Now";
                if (!desired.equals(pauseBtn.getText())) pauseBtn.setText(desired);
            }
        });
        refreshTimer.start();

        updateControlStates();
    }

    // ── Table Refresh ────────────────────────────────────────────────────────

    public void refreshStepsTable() {
        SwingUtilities.invokeLater(() -> {
            int sel = stepsTable.getSelectedRow();
            stepsModel.setRowCount(0);
            List<StepperStep> steps = engine.getSteps();
            for (int i = 0; i < steps.size(); i++) {
                StepperStep step = steps.get(i);
                stepsModel.addRow(new Object[]{
                        i + 1,
                        step.getName(),
                        step.getUrlSummary(),
                        step.isEnabled() ? "\u2713" : "\u2717"
                });
            }
            if (sel >= 0 && sel < stepsModel.getRowCount()) {
                stepsTable.setRowSelectionInterval(sel, sel);
            }
        });
    }

    private void refreshRulesTable() {
        SwingUtilities.invokeLater(() -> {
            rulesModel.setRowCount(0);
            int stepIdx = stepsTable.getSelectedRow();
            if (stepIdx < 0) return;

            List<StepperStep> steps = engine.getSteps();
            if (stepIdx >= steps.size()) return;

            StepperStep step = steps.get(stepIdx);
            for (ExtractionRule rule : step.getExtractionRules()) {
                String lastValue = engine.getVariableStore().get(rule.getVariableName());
                rulesModel.addRow(new Object[]{
                        "{{" + rule.getVariableName() + "}}",
                        rule.getType().name(),
                        rule.getPattern(),
                        lastValue != null ? truncate(lastValue, 40) : "(none)"
                });
            }
        });
    }

    private void refreshVariablesDisplay() {
        SwingUtilities.invokeLater(() -> {
            int sel = variablesTable.getSelectedRow();
            variablesModel.setRowCount(0);
            Map<String, String> vars = engine.getVariableStore().getAll();
            Map<String, String> pinned = engine.getPinnedVariables();
            for (Map.Entry<String, String> entry : vars.entrySet()) {
                String source = pinned.containsKey(entry.getKey()) ? "pinned" : "extracted";
                variablesModel.addRow(new Object[]{
                        "{{" + entry.getKey() + "}}",
                        truncate(entry.getValue(), 120),
                        source
                });
            }
            if (sel >= 0 && sel < variablesModel.getRowCount()) {
                variablesTable.setRowSelectionInterval(sel, sel);
            }

            long lastRun = engine.getLastChainRunTime();
            StringBuilder status = new StringBuilder();
            if (lastRun > 0) {
                long ageMs = System.currentTimeMillis() - lastRun;
                long ageSec = ageMs / 1000;
                int ttl = engine.getCacheTtlSeconds();
                String timeStr = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date(lastRun));
                status.append("Last chain run: ").append(timeStr);
                if (ttl > 0 && !engine.isPerRequestMode()) {
                    long remaining = ttl - ageSec;
                    if (remaining > 0) status.append(" (cached for ").append(remaining).append("s)");
                    else                status.append(" (cache expired)");
                } else if (engine.isPerRequestMode()) {
                    status.append(" (per-request mode — no cache)");
                }
            } else {
                status.append("Chain has not run yet.");
            }
            lastRunLabel.setText(status.toString());
        });
    }

    private void showEditRequestDialog(StepperStep step) {
        burp.api.montoya.http.message.requests.HttpRequest current = step.getOriginalRequest();
        if (current == null) {
            JOptionPane.showMessageDialog(this, "Step has no request.", "Edit Request",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show the raw HTTP request as text. Body included.
        String rawText;
        try {
            rawText = current.toString();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Could not render request: " + ex.getMessage(),
                    "Edit Request", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JTextArea editor = new JTextArea(rawText, 24, 80);
        editor.setFont(MONO_FONT);
        styleTextArea(editor);
        editor.setEditable(true);
        editor.setLineWrap(false);
        JScrollPane scroll = new JScrollPane(editor);
        styleScrollPane(scroll);
        scroll.setPreferredSize(new Dimension(800, 480));

        JLabel hint = new JLabel(
                "<html><b>Insert {{name}} anywhere</b> (path, headers, body) to substitute "
                + "values extracted from earlier steps.<br>"
                + "Service: " + current.httpService().secure() + "://"
                + current.httpService().host() + ":" + current.httpService().port() + " (preserved)</html>");
        hint.setForeground(FG_SECONDARY);
        hint.setFont(MONO_SMALL);
        hint.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel dialogPanel = new JPanel(new BorderLayout(0, 4));
        dialogPanel.setBackground(BG_DARK);
        dialogPanel.add(hint, BorderLayout.NORTH);
        dialogPanel.add(scroll, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(this, dialogPanel,
                "Edit Step: " + step.getName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result != JOptionPane.OK_OPTION) return;

        String edited = editor.getText();
        // Normalize line endings — HTTP wants CRLF but text editors often produce LF.
        // Re-CRLF the whole thing; Burp's parser tolerates both but is stricter for headers.
        String normalized = edited.replace("\r\n", "\n").replace("\n", "\r\n");

        try {
            burp.api.montoya.core.ByteArray bytes =
                    burp.api.montoya.core.ByteArray.byteArray(normalized);
            burp.api.montoya.http.message.requests.HttpRequest parsed =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            current.httpService(), bytes);
            step.setOriginalRequest(parsed);
            engine.invalidateCache();
            refreshStepsTable();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Could not parse edited request:\n" + ex.getMessage()
                            + "\n\nThe step was not modified.",
                    "Edit Request — Parse Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showAddVariableDialog() {
        JPanel dialogPanel = new JPanel(new GridLayout(2, 2, 8, 6));
        dialogPanel.setBackground(BG_DARK);

        JLabel nameLabel = new JLabel("Variable Name:");
        nameLabel.setForeground(FG_PRIMARY);
        nameLabel.setFont(MONO_FONT);
        dialogPanel.add(nameLabel);
        JTextField nameField = new JTextField(15);
        styleTextField(nameField);
        nameField.setToolTipText("Reference as {{name}} in step templates. Don't include the braces here.");
        dialogPanel.add(nameField);

        JLabel valLabel = new JLabel("Value:");
        valLabel.setForeground(FG_PRIMARY);
        valLabel.setFont(MONO_FONT);
        dialogPanel.add(valLabel);
        JTextField valField = new JTextField(20);
        styleTextField(valField);
        dialogPanel.add(valField);

        int result = JOptionPane.showConfirmDialog(this, dialogPanel,
                "Add / Override Variable", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            // Tolerate users pasting "{{name}}" — strip the braces
            if (name.startsWith("{{") && name.endsWith("}}")) {
                name = name.substring(2, name.length() - 2).trim();
            }
            String value = valField.getText();
            if (!name.isEmpty()) {
                engine.setVariable(name, value);
                refreshVariablesDisplay();
            }
        }
    }

    private void refreshCookieTable() {
        SwingUtilities.invokeLater(() -> {
            int sel = cookieTable.getSelectedRow();
            cookieModel.setRowCount(0);
            Map<String, String> cookies = engine.getCookieJar();
            for (Map.Entry<String, String> entry : cookies.entrySet()) {
                cookieModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
            }
            if (sel >= 0 && sel < cookieModel.getRowCount()) {
                cookieTable.setRowSelectionInterval(sel, sel);
            }
        });
    }

    private void showAddCookieDialog() {
        JPanel dialogPanel = new JPanel(new GridLayout(2, 2, 8, 6));
        dialogPanel.setBackground(BG_DARK);

        JLabel nameLabel = new JLabel("Cookie Name:");
        nameLabel.setForeground(FG_PRIMARY);
        nameLabel.setFont(MONO_FONT);
        dialogPanel.add(nameLabel);
        JTextField nameField = new JTextField(15);
        styleTextField(nameField);
        dialogPanel.add(nameField);

        JLabel valLabel = new JLabel("Value:");
        valLabel.setForeground(FG_PRIMARY);
        valLabel.setFont(MONO_FONT);
        dialogPanel.add(valLabel);
        JTextField valField = new JTextField(20);
        styleTextField(valField);
        dialogPanel.add(valField);

        int result = JOptionPane.showConfirmDialog(this, dialogPanel,
                "Add Cookie", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String value = valField.getText().trim();
            if (!name.isEmpty()) {
                engine.setCookie(name, value);
                refreshCookieTable();
            }
        }
    }

    private void updateControlStates() {
        boolean on = enabledCheckBox.isSelected();
        boolean perReq = perRequestModeBox != null && perRequestModeBox.isSelected();
        // Cache TTL is meaningless in per-request mode (chain always re-runs)
        cacheTtlField.setEnabled(on && !perReq);
        runChainBtn.setEnabled(on);
        stopOnFailureBox.setEnabled(on);
        if (perRequestModeBox != null) perRequestModeBox.setEnabled(on);
        stepsTable.setEnabled(on);
        rulesTable.setEnabled(on);
        enabledCheckBox.setForeground(on ? NEON_GREEN : NEON_RED);
    }

    // ── Add Rule Dialog ──────────────────────────────────────────────────────

    private void showAddRuleDialog() {
        int stepIdx = stepsTable.getSelectedRow();
        if (stepIdx < 0) {
            JOptionPane.showMessageDialog(this,
                    "Select a step first, then add an extraction rule.",
                    "No Step Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<StepperStep> steps = engine.getSteps();
        if (stepIdx >= steps.size()) return;

        JPanel dialogPanel = new JPanel(new GridLayout(3, 2, 8, 6));
        dialogPanel.setBackground(BG_DARK);

        JLabel varLabel = new JLabel("Variable Name:");
        varLabel.setForeground(FG_PRIMARY);
        varLabel.setFont(MONO_FONT);
        dialogPanel.add(varLabel);
        JTextField varField = new JTextField(15);
        styleTextField(varField);
        dialogPanel.add(varField);

        JLabel typeLabel = new JLabel("Type:");
        typeLabel.setForeground(FG_PRIMARY);
        typeLabel.setFont(MONO_FONT);
        dialogPanel.add(typeLabel);
        JComboBox<ExtractionType> typeCombo = new JComboBox<>(ExtractionType.values());
        styleComboBox(typeCombo);
        dialogPanel.add(typeCombo);

        JLabel patLabel = new JLabel("Pattern:");
        patLabel.setForeground(FG_PRIMARY);
        patLabel.setFont(MONO_FONT);
        dialogPanel.add(patLabel);
        JTextField patField = new JTextField(20);
        styleTextField(patField);
        patField.setToolTipText("BODY_REGEX: regex (group 1) | HEADER: header name | COOKIE: cookie name | JSON_PATH: dot.path");
        dialogPanel.add(patField);

        int result = JOptionPane.showConfirmDialog(this, dialogPanel,
                "Add Extraction Rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String varName = varField.getText().trim();
            String pattern = patField.getText().trim();
            ExtractionType type = (ExtractionType) typeCombo.getSelectedItem();

            if (varName.isEmpty() || pattern.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Variable name and pattern are required.",
                        "Invalid Rule", JOptionPane.WARNING_MESSAGE);
                return;
            }

            steps.get(stepIdx).addExtractionRule(new ExtractionRule(varName, type, pattern));
            refreshRulesTable();
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void applyCacheTtl() {
        try {
            int ttl = Integer.parseInt(cacheTtlField.getText().trim());
            engine.setCacheTtlSeconds(ttl);
        } catch (NumberFormatException ignored) {
            cacheTtlField.setText(String.valueOf(engine.getCacheTtlSeconds()));
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /** Stop the refresh timer. Called during extension unload. */
    public void stopTimers() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
}
