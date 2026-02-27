package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.omnistrike.modules.exploit.omnimap.OmniMapConfig;
import com.omnistrike.modules.exploit.omnimap.dbms.DbmsDetector;
import com.omnistrike.modules.exploit.omnimap.tamper.TamperEngine;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.*;
import java.util.List;

import static com.omnistrike.ui.CyberTheme.*;

/**
 * OmniMap configuration dialog — pops up when the user right-clicks
 * "Send to OmniMap" from the context menu.
 *
 * Allows selecting the target parameter, techniques, DBMS, action,
 * and advanced options before starting exploitation.
 */
public class OmniMapConfigDialog extends JDialog {

    private boolean confirmed = false;
    private OmniMapConfig config;
    private final HttpRequestResponse requestResponse;

    // Form fields
    private JComboBox<String> paramCombo;
    private final Map<String, String> paramTypeMap = new LinkedHashMap<>(); // display → type
    // Techniques section removed — only Boolean Blind is used
    private JComboBox<String> dbmsCombo;
    private JComboBox<String> actionCombo;
    private JTextField targetDbField;
    private JTextField targetTableField;
    private JTextField targetColumnsField;
    private JSpinner levelSpinner;
    private JSpinner riskSpinner;
    private JSpinner threadsSpinner;
    // timeDelaySpinner removed — time-based technique removed
    private JTextField prefixField;
    private JTextField suffixField;
    private JTextField trueStringField;
    private JTextField falseStringField;
    private JSpinner dumpLimitSpinner;
    private final Map<String, JCheckBox> tamperChecks = new LinkedHashMap<>();

    public OmniMapConfigDialog(Frame parent, HttpRequestResponse reqResp, MontoyaApi api) {
        super(parent, "OmniMap \u2014 SQL Injection Exploiter", true);
        this.requestResponse = reqResp;

        setSize(650, 750);
        setLocationRelativeTo(parent);
        setResizable(true);

        // Use a vertical panel inside a scroll pane
        JPanel content = new JPanel();
        content.setLayout(new GridBagLayout());
        content.setBackground(BG_DARK);
        content.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15));

        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 1.0;
        gc.insets = new Insets(3, 0, 3, 0);
        int row = 0;

        // === Header ===
        JLabel header = new JLabel("OmniMap \u2014 High-Speed sqlmap Variant");
        header.setForeground(NEON_CYAN);
        header.setFont(MONO_BOLD.deriveFont(16f));
        gc.gridy = row++;
        content.add(header, gc);

        JLabel subtitle = new JLabel("Parallel extraction \u2022 Adaptive bisection \u2022 Predictive optimization");
        subtitle.setForeground(FG_SECONDARY);
        subtitle.setFont(MONO_SMALL);
        gc.gridy = row++;
        gc.insets = new Insets(0, 0, 2, 0);
        content.add(subtitle, gc);

        JLabel techNote = new JLabel("Technique: Boolean blind (content-based conditional responses)");
        techNote.setForeground(FG_DIM);
        techNote.setFont(MONO_SMALL);
        gc.gridy = row++;
        gc.insets = new Insets(0, 0, 8, 0);
        content.add(techNote, gc);
        gc.insets = new Insets(3, 0, 3, 0);

        // === Parameter Selection ===
        paramCombo = new JComboBox<>();
        styleComboBox(paramCombo);
        populateParameters(reqResp);
        gc.gridy = row++;
        content.add(wrapSection("Target Parameter", paramCombo), gc);

        // === DBMS + Action (side by side) ===
        JPanel dbmsActionRow = new JPanel(new GridLayout(1, 2, 10, 0));
        dbmsActionRow.setOpaque(false);

        // DBMS
        JPanel dbmsInner = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        dbmsInner.setOpaque(false);
        String[] dbmsOptions = new String[DbmsDetector.getAvailableDbms().length + 1];
        dbmsOptions[0] = "Auto-detect";
        System.arraycopy(DbmsDetector.getAvailableDbms(), 0, dbmsOptions, 1, DbmsDetector.getAvailableDbms().length);
        dbmsCombo = new JComboBox<>(dbmsOptions);
        styleComboBox(dbmsCombo);
        dbmsInner.add(styledLabel("DBMS:"));
        dbmsInner.add(dbmsCombo);

        // Action
        JPanel actionInner = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        actionInner.setOpaque(false);
        actionCombo = new JComboBox<>(new String[]{"List Databases", "List Tables", "List Columns", "Dump Data"});
        styleComboBox(actionCombo);
        actionInner.add(styledLabel("Extract:"));
        actionInner.add(actionCombo);

        dbmsActionRow.add(wrapSection("DBMS", dbmsInner));
        dbmsActionRow.add(wrapSection("Action", actionInner));
        gc.gridy = row++;
        content.add(dbmsActionRow, gc);

        // === Target (Database / Table / Columns) ===
        JPanel targetInner = new JPanel(new GridBagLayout());
        targetInner.setOpaque(false);
        GridBagConstraints tg = new GridBagConstraints();
        tg.insets = new Insets(2, 4, 2, 4);
        tg.anchor = GridBagConstraints.WEST;
        tg.gridy = 0;

        tg.gridx = 0; targetInner.add(styledLabel("Database:"), tg);
        tg.gridx = 1; tg.fill = GridBagConstraints.HORIZONTAL; tg.weightx = 1.0;
        targetDbField = new JTextField(12);
        styleTextField(targetDbField);
        setPlaceholder(targetDbField, "e.g. mysql");
        targetDbField.setToolTipText("Target database (required for tables/columns/dump)");
        targetInner.add(targetDbField, tg);

        tg.gridx = 2; tg.fill = GridBagConstraints.NONE; tg.weightx = 0;
        targetInner.add(styledLabel("Table:"), tg);
        tg.gridx = 3; tg.fill = GridBagConstraints.HORIZONTAL; tg.weightx = 1.0;
        targetTableField = new JTextField(12);
        styleTextField(targetTableField);
        setPlaceholder(targetTableField, "e.g. users");
        targetTableField.setToolTipText("Target table (required for columns/dump)");
        targetInner.add(targetTableField, tg);

        tg.gridx = 4; tg.fill = GridBagConstraints.NONE; tg.weightx = 0;
        targetInner.add(styledLabel("Columns:"), tg);
        tg.gridx = 5; tg.fill = GridBagConstraints.HORIZONTAL; tg.weightx = 1.0;
        targetColumnsField = new JTextField(12);
        styleTextField(targetColumnsField);
        setPlaceholder(targetColumnsField, "e.g. id, username, password");
        targetColumnsField.setToolTipText("Comma-separated column names (optional, leave empty for all)");
        targetInner.add(targetColumnsField, tg);

        gc.gridy = row++;
        content.add(wrapSection("Target Scope (for Tables / Columns / Dump)", targetInner), gc);

        // === Advanced Options ===
        JPanel advInner = new JPanel(new GridBagLayout());
        advInner.setOpaque(false);
        GridBagConstraints ag = new GridBagConstraints();
        ag.insets = new Insets(3, 5, 3, 5);
        ag.anchor = GridBagConstraints.WEST;

        // Row 0: Level, Risk, Threads, Time Delay
        ag.gridy = 0;
        ag.gridx = 0; advInner.add(styledLabel("Level:"), ag);
        ag.gridx = 1; levelSpinner = makeSpinner(1, 1, 5); advInner.add(levelSpinner, ag);
        ag.gridx = 2; advInner.add(styledLabel("Risk:"), ag);
        ag.gridx = 3; riskSpinner = makeSpinner(1, 1, 3); advInner.add(riskSpinner, ag);
        ag.gridx = 4; advInner.add(styledLabel("Threads:"), ag);
        ag.gridx = 5; threadsSpinner = makeSpinner(5, 1, 10); advInner.add(threadsSpinner, ag);

        // Row 1: Prefix, Suffix
        ag.gridy = 1;
        ag.gridx = 0; advInner.add(styledLabel("Prefix:"), ag);
        ag.gridx = 1; ag.gridwidth = 3; ag.fill = GridBagConstraints.HORIZONTAL;
        prefixField = new JTextField(15); styleTextField(prefixField);
        setPlaceholder(prefixField, "e.g. ')");
        prefixField.setToolTipText("Custom injection prefix");
        advInner.add(prefixField, ag);
        ag.gridwidth = 1; ag.fill = GridBagConstraints.NONE;
        ag.gridx = 4; advInner.add(styledLabel("Suffix:"), ag);
        ag.gridx = 5; ag.gridwidth = 3; ag.fill = GridBagConstraints.HORIZONTAL;
        suffixField = new JTextField(15); styleTextField(suffixField);
        setPlaceholder(suffixField, "e.g. -- -");
        suffixField.setToolTipText("Custom injection suffix");
        advInner.add(suffixField, ag);
        ag.gridwidth = 1; ag.fill = GridBagConstraints.NONE;

        // Row 2: True/False strings
        ag.gridy = 2;
        ag.gridx = 0; advInner.add(styledLabel("True string:"), ag);
        ag.gridx = 1; ag.gridwidth = 3; ag.fill = GridBagConstraints.HORIZONTAL;
        trueStringField = new JTextField(15); styleTextField(trueStringField);
        setPlaceholder(trueStringField, "e.g. Welcome");
        trueStringField.setToolTipText("String that appears when condition is TRUE");
        advInner.add(trueStringField, ag);
        ag.gridwidth = 1; ag.fill = GridBagConstraints.NONE;
        ag.gridx = 4; advInner.add(styledLabel("False string:"), ag);
        ag.gridx = 5; ag.gridwidth = 3; ag.fill = GridBagConstraints.HORIZONTAL;
        falseStringField = new JTextField(15); styleTextField(falseStringField);
        setPlaceholder(falseStringField, "e.g. Error");
        falseStringField.setToolTipText("String that appears when condition is FALSE");
        advInner.add(falseStringField, ag);
        ag.gridwidth = 1; ag.fill = GridBagConstraints.NONE;

        // Row 3: Dump limit
        ag.gridy = 3;
        ag.gridx = 0; advInner.add(styledLabel("Dump limit:"), ag);
        ag.gridx = 1; dumpLimitSpinner = makeSpinner(0, 0, 10000);
        advInner.add(dumpLimitSpinner, ag);
        ag.gridx = 2; ag.gridwidth = 6;
        JLabel limitHint = new JLabel("(0 = dump all rows)");
        limitHint.setForeground(FG_DIM);
        limitHint.setFont(MONO_SMALL);
        advInner.add(limitHint, ag);
        ag.gridwidth = 1;

        gc.gridy = row++;
        content.add(wrapSection("Advanced Options", advInner), gc);

        // === Tamper Scripts ===
        JPanel tamperInner = new JPanel(new GridLayout(0, 3, 5, 2));
        tamperInner.setOpaque(false);
        for (String tamper : TamperEngine.getAvailableTampers()) {
            JCheckBox cb = new JCheckBox(tamper, false);
            styleCheckBox(cb);
            cb.setToolTipText(TamperEngine.getDescription(tamper));
            tamperChecks.put(tamper, cb);
            tamperInner.add(cb);
        }
        gc.gridy = row++;
        content.add(wrapSection("WAF Bypass (Tamper Scripts)", tamperInner), gc);

        // === Buttons ===
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        btnPanel.setOpaque(false);

        JButton cancelBtn = new JButton("Cancel");
        styleButton(cancelBtn, NEON_RED);
        cancelBtn.addActionListener(e -> dispose());
        btnPanel.add(cancelBtn);

        JButton exploitBtn = new JButton("Exploit");
        styleButton(exploitBtn, NEON_GREEN);
        exploitBtn.setFont(MONO_BOLD.deriveFont(14f));
        exploitBtn.addActionListener(e -> {
            confirmed = true;
            config = buildConfig();
            dispose();
        });
        btnPanel.add(exploitBtn);

        gc.gridy = row++;
        gc.weighty = 1.0; // push buttons to bottom of remaining space
        gc.anchor = GridBagConstraints.SOUTH;
        content.add(btnPanel, gc);

        // Scrollable content
        JScrollPane scroll = new JScrollPane(content,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        styleScrollPane(scroll);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        setContentPane(scroll);
        getContentPane().setBackground(BG_DARK);
    }

    /**
     * Populate the parameter dropdown from the request.
     */
    private void populateParameters(HttpRequestResponse reqResp) {
        if (reqResp == null || reqResp.request() == null) return;

        for (ParsedHttpParameter param : reqResp.request().parameters()) {
            String name = param.name();
            String type = switch (param.type()) {
                case URL -> "url";
                case BODY -> "body";
                case COOKIE -> "cookie";
                default -> "url";
            };
            String display = name + " [" + type.toUpperCase() + "]";
            paramCombo.addItem(display);
            paramTypeMap.put(display, type);
        }

        // Add injectable headers
        Set<String> injectableHeaders = Set.of("referer", "user-agent", "x-forwarded-for",
                "x-forwarded-host", "origin");
        for (var header : reqResp.request().headers()) {
            if (injectableHeaders.contains(header.name().toLowerCase())) {
                String display = header.name() + " [HEADER]";
                paramCombo.addItem(display);
                paramTypeMap.put(display, "header");
            }
        }
    }

    /**
     * Build OmniMapConfig from dialog fields.
     */
    private OmniMapConfig buildConfig() {
        OmniMapConfig c = new OmniMapConfig();

        String selected = (String) paramCombo.getSelectedItem();
        if (selected != null) {
            int bracket = selected.lastIndexOf('[');
            c.setParameterName(bracket > 0 ? selected.substring(0, bracket).trim() : selected);
            c.setParameterType(paramTypeMap.getOrDefault(selected, "url"));
        }

        // Boolean Blind is the only technique — already set by default in OmniMapConfig

        String dbms = (String) dbmsCombo.getSelectedItem();
        c.setDbms("Auto-detect".equals(dbms) ? null : dbms);

        String action = (String) actionCombo.getSelectedItem();
        c.setAction(switch (action) {
            case "List Databases" -> "databases";
            case "List Tables" -> "tables";
            case "List Columns" -> "columns";
            case "Dump Data" -> "dump";
            default -> "databases";
        });

        c.setTargetDatabase(emptyToNull(getFieldText(targetDbField, "e.g. mysql")));
        c.setTargetTable(emptyToNull(getFieldText(targetTableField, "e.g. users")));

        String cols = getFieldText(targetColumnsField, "e.g. id, username, password");
        if (!cols.isEmpty()) {
            c.setTargetColumns(Arrays.asList(cols.split("\\s*,\\s*")));
        }

        c.setLevel((int) levelSpinner.getValue());
        c.setRisk((int) riskSpinner.getValue());
        c.setThreads((int) threadsSpinner.getValue());
        c.setPrefix(getFieldText(prefixField, "e.g. ')"));
        c.setSuffix(getFieldText(suffixField, "e.g. -- -"));
        c.setTrueString(getFieldText(trueStringField, "e.g. Welcome"));
        c.setFalseString(getFieldText(falseStringField, "e.g. Error"));
        c.setDumpLimit((int) dumpLimitSpinner.getValue());

        List<String> selectedTampers = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : tamperChecks.entrySet()) {
            if (entry.getValue().isSelected()) selectedTampers.add(entry.getKey());
        }
        c.setTampers(selectedTampers);

        return c;
    }

    public boolean isConfirmed() { return confirmed; }
    public OmniMapConfig getConfig() { return config; }

    // ---- Helpers ----

    /** Wrap inner content in a titled, styled section panel. */
    private JPanel wrapSection(String title, JComponent inner) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_PANEL);
        TitledBorder border = BorderFactory.createTitledBorder(
                new CyberTheme.GlowLineBorder(BORDER, 1), title);
        border.setTitleColor(NEON_CYAN);
        border.setTitleFont(MONO_BOLD);
        panel.setBorder(BorderFactory.createCompoundBorder(border,
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        panel.add(inner, BorderLayout.CENTER);
        return panel;
    }

    private JLabel styledLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(FG_PRIMARY);
        l.setFont(MONO_SMALL);
        return l;
    }

    private JSpinner makeSpinner(int value, int min, int max) {
        JSpinner s = new JSpinner(new SpinnerNumberModel(value, min, max, 1));
        s.setPreferredSize(new Dimension(65, 25));
        s.setBackground(BG_INPUT);
        s.setForeground(FG_PRIMARY);
        s.setFont(MONO_FONT);
        return s;
    }

    /** Add ghost placeholder text to a JTextField (disappears on focus, reappears when empty). */
    private void setPlaceholder(JTextField field, String placeholder) {
        field.setText(placeholder);
        field.setForeground(FG_DIM);
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(FG_PRIMARY);
                }
            }
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (field.getText().isEmpty()) {
                    field.setText(placeholder);
                    field.setForeground(FG_DIM);
                }
            }
        });
    }

    /** Get text from a field, treating placeholder ghost text as empty. */
    private String getFieldText(JTextField field, String placeholder) {
        String text = field.getText().trim();
        return text.equals(placeholder) ? "" : text;
    }

    private static String emptyToNull(String s) {
        return (s == null || s.trim().isEmpty()) ? null : s.trim();
    }
}
