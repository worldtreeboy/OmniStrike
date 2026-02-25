package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnistrike.framework.ModuleRegistry;
import com.omnistrike.framework.OmniStrikeScanCheck;
import com.omnistrike.framework.TrafficInterceptor;
import com.omnistrike.model.ModuleCategory;
import com.omnistrike.model.ModuleConfig;
import com.omnistrike.model.ScanModule;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Custom scan configuration dialog.
 * Left panel: module checkboxes grouped by category (AI Analysis, Active Scanners, Passive Analyzers).
 * Right panel: dynamic config keys for the currently highlighted module.
 * OK starts scanning with checked modules using configured settings. Cancel aborts.
 * Dark theme to match Burp's look.
 */
public class ScanConfigDialog extends JDialog {

    // Dark theme colors
    private static final Color BG_DARK = new Color(43, 43, 43);
    private static final Color BG_PANEL = new Color(50, 50, 50);
    private static final Color BG_INPUT = new Color(60, 60, 60);
    private static final Color BG_LIST = new Color(55, 55, 55);
    private static final Color BG_SELECTED = new Color(75, 110, 175);
    private static final Color FG_NORMAL = new Color(187, 187, 187);
    private static final Color FG_HEADER = new Color(220, 220, 220);
    private static final Color FG_KEY = new Color(152, 195, 121);
    private static final Color FG_DEFAULT = new Color(120, 120, 120);
    private static final Color BORDER_COLOR = new Color(80, 80, 80);
    private static final Color ACCENT = new Color(86, 156, 214);

    private final ModuleRegistry registry;
    private final MontoyaApi api;
    private final HttpRequestResponse reqResp;
    private final TrafficInterceptor interceptor;
    private final OmniStrikeScanCheck scanCheck;

    // Module checkboxes: moduleId -> JCheckBox
    private final Map<String, JCheckBox> moduleCheckboxes = new LinkedHashMap<>();

    // Currently displayed config editors: key -> component
    private final Map<String, JComponent> configEditors = new LinkedHashMap<>();

    // The module whose config is currently shown on the right panel
    private String selectedModuleId = null;

    // Right panel container
    private final JPanel configPanel;
    private final JLabel configTitleLabel;

    private boolean confirmed = false;

    // ==================== KNOWN CONFIG DEFAULTS ====================
    // Defines all known config keys per module so they appear even before being set.
    // Format: moduleId -> list of ConfigEntry(key, type, defaultValueString)

    private static final Map<String, List<ConfigEntry>> KNOWN_CONFIGS = new LinkedHashMap<>();

    static {
        // SQLi Detector
        KNOWN_CONFIGS.put("sqli-detector", List.of(
                boolEntry("sqli.authBypass.enabled", true),
                boolEntry("sqli.error.enabled", true),
                boolEntry("sqli.union.enabled", true),
                boolEntry("sqli.time.enabled", true),
                boolEntry("sqli.boolean.enabled", true),
                boolEntry("sqli.oob.enabled", true),
                intEntry("sqli.union.maxColumns", 30),
                intEntry("sqli.union.anomalyThreshold", 50),
                intEntry("sqli.time.threshold", 4000),
                intEntry("sqli.perHostDelay", 500)
        ));

        // SSTI Scanner
        KNOWN_CONFIGS.put("ssti-scanner", List.of(
                boolEntry("ssti.aggressive", false),
                intEntry("ssti.perHostDelay", 500)
        ));

        // SSRF Scanner
        KNOWN_CONFIGS.put("ssrf-scanner", List.of(
                boolEntry("ssrf.aggressive", false),
                boolEntry("ssrf.metadata.enabled", true),
                boolEntry("ssrf.localhost.enabled", true),
                boolEntry("ssrf.rebinding.enabled", true),
                boolEntry("ssrf.protocol.enabled", true),
                boolEntry("ssrf.redirect.enabled", true),
                intEntry("ssrf.perHostDelay", 500)
        ));

        // XSS Scanner
        KNOWN_CONFIGS.put("xss-scanner", List.of(
                boolEntry("xss.domAnalysis.enabled", true),
                boolEntry("xss.evasion.enabled", true),
                boolEntry("xss.csti.enabled", true),
                boolEntry("xss.frameworkXss.enabled", true),
                boolEntry("xss.encodingXss.enabled", true),
                boolEntry("xss.blindOob.enabled", true),
                intEntry("xss.perHostDelay", 300)
        ));

        // Command Injection
        KNOWN_CONFIGS.put("cmdi-scanner", List.of(
                boolEntry("cmdi.unix.enabled", true),
                boolEntry("cmdi.windows.enabled", true),
                boolEntry("cmdi.output.enabled", true),
                boolEntry("cmdi.oob.enabled", true),
                intEntry("cmdi.delaySecs", 18),
                intEntry("cmdi.perHostDelay", 500)
        ));

        // Deserialization Scanner
        KNOWN_CONFIGS.put("deser-scanner", List.of(
                intEntry("deser.timeThreshold", 14000),
                intEntry("deser.perHostDelay", 500)
        ));

        // GraphQL Tool
        KNOWN_CONFIGS.put("graphql-tool", List.of(
                boolEntry("graphql.securityTests.enabled", true),
                boolEntry("graphql.injection.enabled", true),
                boolEntry("graphql.injection.sqli.enabled", true),
                boolEntry("graphql.injection.nosqli.enabled", true),
                boolEntry("graphql.injection.cmdi.enabled", true),
                boolEntry("graphql.injection.ssti.enabled", true),
                boolEntry("graphql.authz.enabled", true),
                boolEntry("graphql.authz.idor.enabled", true),
                intEntry("graphql.authz.idor.maxIds", 20),
                boolEntry("graphql.dos.enabled", true),
                boolEntry("graphql.introspection.bypass", true),
                boolEntry("graphql.oob.enabled", true),
                intEntry("graphql.perHostDelay", 500)
        ));

        // XXE Scanner
        KNOWN_CONFIGS.put("xxe-scanner", List.of(
                boolEntry("xxe.classic.enabled", true),
                boolEntry("xxe.oob.enabled", true),
                boolEntry("xxe.xinclude.enabled", true),
                boolEntry("xxe.contentTypeConversion.enabled", true),
                intEntry("xxe.perHostDelay", 500)
        ));

        // CORS Misconfiguration
        KNOWN_CONFIGS.put("cors-scanner", List.of(
                boolEntry("cors.preflight.enabled", true),
                intEntry("cors.perHostDelay", 300)
        ));

        // Cache Poisoning
        KNOWN_CONFIGS.put("cache-poison", List.of(
                boolEntry("cache.headers.enabled", true),
                boolEntry("cache.params.enabled", true),
                boolEntry("cache.confirmPoison", false),
                intEntry("cache.perHostDelay", 500)
        ));

        // Host Header Injection
        KNOWN_CONFIGS.put("host-header", List.of(
                boolEntry("host.oob.enabled", true),
                boolEntry("host.internal.enabled", true),
                intEntry("host.perHostDelay", 500)
        ));

        // Prototype Pollution
        KNOWN_CONFIGS.put("proto-pollution", List.of(
                boolEntry("proto.gadgets.enabled", true),
                boolEntry("proto.cleanupEnabled", true),
                intEntry("proto.perHostDelay", 500)
        ));

        // Path Traversal
        KNOWN_CONFIGS.put("path-traversal", List.of(
                boolEntry("traversal.unix.enabled", true),
                boolEntry("traversal.windows.enabled", true),
                boolEntry("traversal.encodingBypass.enabled", true),
                boolEntry("traversal.phpWrappers.enabled", true),
                intEntry("traversal.maxDepth", 10),
                intEntry("traversal.perHostDelay", 300)
        ));
    }

    public ScanConfigDialog(Frame owner, ModuleRegistry registry, MontoyaApi api,
                             HttpRequestResponse reqResp, TrafficInterceptor interceptor,
                             OmniStrikeScanCheck scanCheck) {
        super(owner, "OmniStrike — Custom Scan", true);
        this.registry = registry;
        this.api = api;
        this.reqResp = reqResp;
        this.interceptor = interceptor;
        this.scanCheck = scanCheck;

        setSize(900, 600);
        setLocationRelativeTo(owner);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        // Root panel
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(BG_DARK);
        root.setBorder(new EmptyBorder(8, 8, 8, 8));

        // ==================== HEADER ====================
        JLabel headerLabel = new JLabel("Custom Scan — " + truncate(reqResp.request().url(), 70));
        headerLabel.setForeground(ACCENT);
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        headerLabel.setBorder(new EmptyBorder(0, 4, 8, 0));
        root.add(headerLabel, BorderLayout.NORTH);

        // ==================== LEFT PANEL: MODULE LIST ====================
        JPanel leftPanel = buildModuleListPanel();

        // ==================== RIGHT PANEL: CONFIG KEYS ====================
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBackground(BG_DARK);

        configTitleLabel = new JLabel("Select a module to configure");
        configTitleLabel.setForeground(FG_HEADER);
        configTitleLabel.setFont(configTitleLabel.getFont().deriveFont(Font.BOLD, 13f));
        configTitleLabel.setBorder(new EmptyBorder(4, 8, 8, 0));
        rightPanel.add(configTitleLabel, BorderLayout.NORTH);

        configPanel = new JPanel();
        configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));
        configPanel.setBackground(BG_DARK);

        JScrollPane configScroll = new JScrollPane(configPanel);
        configScroll.setBackground(BG_DARK);
        configScroll.getViewport().setBackground(BG_DARK);
        configScroll.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
        configScroll.getVerticalScrollBar().setUnitIncrement(16);
        rightPanel.add(configScroll, BorderLayout.CENTER);

        // ==================== SPLIT PANE ====================
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setDividerLocation(300);
        splitPane.setBackground(BG_DARK);
        splitPane.setBorder(null);
        root.add(splitPane, BorderLayout.CENTER);

        // ==================== BUTTON BAR ====================
        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        buttonBar.setBackground(BG_DARK);
        buttonBar.setBorder(new EmptyBorder(8, 0, 0, 0));

        JButton selectAllBtn = createDarkButton("Select All");
        selectAllBtn.addActionListener(e -> setAllChecked(true));
        buttonBar.add(selectAllBtn);

        JButton deselectAllBtn = createDarkButton("Deselect All");
        deselectAllBtn.addActionListener(e -> setAllChecked(false));
        buttonBar.add(deselectAllBtn);

        buttonBar.add(Box.createHorizontalStrut(20));

        JButton cancelBtn = createDarkButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonBar.add(cancelBtn);

        JButton okBtn = createDarkButton("Scan");
        okBtn.setBackground(new Color(40, 100, 60));
        okBtn.setForeground(Color.WHITE);
        okBtn.addActionListener(e -> {
            applyConfigChanges();
            confirmed = true;
            dispose();
        });
        buttonBar.add(okBtn);

        root.add(buttonBar, BorderLayout.SOUTH);

        setContentPane(root);
    }

    // ==================== MODULE LIST PANEL ====================

    private JPanel buildModuleListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);
        panel.setPreferredSize(new Dimension(300, 0));

        JPanel listContent = new JPanel();
        listContent.setLayout(new BoxLayout(listContent, BoxLayout.Y_AXIS));
        listContent.setBackground(BG_DARK);
        listContent.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Group modules by category
        List<ScanModule> aiModules = new ArrayList<>();
        List<ScanModule> activeModules = new ArrayList<>();
        List<ScanModule> passiveModules = new ArrayList<>();

        for (ScanModule m : registry.getAllModules()) {
            if (ModuleRegistry.AI_MODULE_ID.equals(m.getId())) {
                aiModules.add(m);
            } else if (m.isPassive()) {
                passiveModules.add(m);
            } else {
                activeModules.add(m);
            }
        }

        // AI Analysis group
        if (!aiModules.isEmpty()) {
            addGroupLabel(listContent, "AI Analysis");
            for (ScanModule m : aiModules) {
                addModuleCheckbox(listContent, m, registry.isEnabled(m.getId()));
            }
            listContent.add(Box.createVerticalStrut(8));
        }

        // Active Scanners group
        if (!activeModules.isEmpty()) {
            addGroupLabel(listContent, "Active Scanners");
            for (ScanModule m : activeModules) {
                addModuleCheckbox(listContent, m, true);
            }
            listContent.add(Box.createVerticalStrut(8));
        }

        // Passive Analyzers group
        if (!passiveModules.isEmpty()) {
            addGroupLabel(listContent, "Passive Analyzers");
            for (ScanModule m : passiveModules) {
                addModuleCheckbox(listContent, m, true);
            }
        }

        // Filler to push everything to the top
        listContent.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(listContent);
        scroll.setBackground(BG_DARK);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
        scroll.getVerticalScrollBar().setUnitIncrement(16);

        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private void addGroupLabel(JPanel container, String text) {
        JLabel label = new JLabel(text);
        label.setForeground(ACCENT);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        label.setBorder(new EmptyBorder(6, 4, 2, 0));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        container.add(label);
    }

    private void addModuleCheckbox(JPanel container, ScanModule module, boolean defaultChecked) {
        JCheckBox cb = new JCheckBox(module.getName());
        cb.setSelected(defaultChecked);
        cb.setBackground(BG_DARK);
        cb.setForeground(FG_NORMAL);
        cb.setFocusPainted(false);
        cb.setToolTipText(module.getDescription());
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        cb.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        cb.setBorder(new EmptyBorder(1, 16, 1, 0));

        // Click to highlight and show config
        cb.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                showConfigForModule(module.getId());
            }
        });

        moduleCheckboxes.put(module.getId(), cb);
        container.add(cb);
    }

    // ==================== CONFIG PANEL (RIGHT) ====================

    private void showConfigForModule(String moduleId) {
        // Save any pending edits from the previous module
        if (selectedModuleId != null) {
            applyConfigEditsToConfig(selectedModuleId);
        }

        selectedModuleId = moduleId;
        configPanel.removeAll();
        configEditors.clear();

        ScanModule module = registry.getModule(moduleId);
        if (module == null) return;

        configTitleLabel.setText(module.getName() + " — Configuration");

        ModuleConfig currentConfig = registry.getConfig(moduleId);
        List<ConfigEntry> knownEntries = KNOWN_CONFIGS.getOrDefault(moduleId, Collections.emptyList());

        // Merge known defaults with any already-set values in the config
        Map<String, ConfigEntry> merged = new LinkedHashMap<>();
        for (ConfigEntry entry : knownEntries) {
            merged.put(entry.key, entry);
        }
        // Add any entries from the actual config that aren't in the known list
        if (currentConfig != null) {
            for (String k : currentConfig.getBoolKeys()) {
                if (!merged.containsKey(k)) {
                    merged.put(k, new ConfigEntry(k, ConfigType.BOOL, String.valueOf(currentConfig.getBool(k, false))));
                }
            }
            for (String k : currentConfig.getIntKeys()) {
                if (!merged.containsKey(k)) {
                    merged.put(k, new ConfigEntry(k, ConfigType.INT, String.valueOf(currentConfig.getInt(k, 0))));
                }
            }
            for (String k : currentConfig.getStringKeys()) {
                if (!merged.containsKey(k)) {
                    merged.put(k, new ConfigEntry(k, ConfigType.STRING, currentConfig.getString(k, "")));
                }
            }
        }

        if (merged.isEmpty()) {
            JLabel noConfig = new JLabel("  No configurable options for this module");
            noConfig.setForeground(FG_DEFAULT);
            noConfig.setAlignmentX(Component.LEFT_ALIGNMENT);
            configPanel.add(Box.createVerticalStrut(20));
            configPanel.add(noConfig);
        } else {
            configPanel.add(Box.createVerticalStrut(4));

            // Column header row
            JPanel headerRow = createConfigRow("Key", "Value", "Default", true);
            configPanel.add(headerRow);

            configPanel.add(createSeparator());

            for (ConfigEntry entry : merged.values()) {
                JPanel row = buildConfigRow(entry, currentConfig);
                configPanel.add(row);
            }
        }

        // Push everything up
        configPanel.add(Box.createVerticalGlue());
        configPanel.revalidate();
        configPanel.repaint();
    }

    private JPanel buildConfigRow(ConfigEntry entry, ModuleConfig currentConfig) {
        JPanel row = new JPanel(new GridBagLayout());
        row.setBackground(BG_DARK);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        row.setBorder(new EmptyBorder(2, 8, 2, 8));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 4, 0, 4);
        gbc.anchor = GridBagConstraints.WEST;

        // Column 1: Key label (45% width)
        gbc.gridx = 0;
        gbc.weightx = 0.45;
        JLabel keyLabel = new JLabel(entry.key);
        keyLabel.setForeground(FG_KEY);
        keyLabel.setFont(keyLabel.getFont().deriveFont(Font.PLAIN, 12f));
        row.add(keyLabel, gbc);

        // Column 2: Value editor (35% width)
        gbc.gridx = 1;
        gbc.weightx = 0.35;

        if (entry.type == ConfigType.BOOL) {
            boolean currentVal = currentConfig != null
                    ? currentConfig.getBool(entry.key, Boolean.parseBoolean(entry.defaultValue))
                    : Boolean.parseBoolean(entry.defaultValue);
            JCheckBox cb = new JCheckBox();
            cb.setSelected(currentVal);
            cb.setBackground(BG_DARK);
            cb.setForeground(FG_NORMAL);
            cb.setFocusPainted(false);
            row.add(cb, gbc);
            configEditors.put(entry.key, cb);
        } else {
            String currentVal;
            if (entry.type == ConfigType.INT) {
                currentVal = currentConfig != null
                        ? String.valueOf(currentConfig.getInt(entry.key, Integer.parseInt(entry.defaultValue)))
                        : entry.defaultValue;
            } else {
                currentVal = currentConfig != null
                        ? currentConfig.getString(entry.key, entry.defaultValue)
                        : entry.defaultValue;
            }
            JTextField tf = new JTextField(currentVal);
            tf.setBackground(BG_INPUT);
            tf.setForeground(FG_NORMAL);
            tf.setCaretColor(FG_NORMAL);
            tf.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(BORDER_COLOR),
                    new EmptyBorder(2, 4, 2, 4)));
            row.add(tf, gbc);
            configEditors.put(entry.key, tf);
        }

        // Column 3: Default hint (20% width)
        gbc.gridx = 2;
        gbc.weightx = 0.20;
        JLabel defaultLabel = new JLabel("default: " + entry.defaultValue);
        defaultLabel.setForeground(FG_DEFAULT);
        defaultLabel.setFont(defaultLabel.getFont().deriveFont(Font.ITALIC, 11f));
        row.add(defaultLabel, gbc);

        return row;
    }

    private JPanel createConfigRow(String col1, String col2, String col3, boolean isHeader) {
        JPanel row = new JPanel(new GridBagLayout());
        row.setBackground(BG_DARK);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        row.setBorder(new EmptyBorder(2, 8, 2, 8));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 4, 0, 4);
        gbc.anchor = GridBagConstraints.WEST;

        Font font = isHeader
                ? row.getFont().deriveFont(Font.BOLD, 11f)
                : row.getFont().deriveFont(Font.PLAIN, 12f);
        Color fg = isHeader ? FG_HEADER : FG_NORMAL;

        gbc.gridx = 0; gbc.weightx = 0.45;
        JLabel l1 = new JLabel(col1); l1.setForeground(fg); l1.setFont(font); row.add(l1, gbc);

        gbc.gridx = 1; gbc.weightx = 0.35;
        JLabel l2 = new JLabel(col2); l2.setForeground(fg); l2.setFont(font); row.add(l2, gbc);

        gbc.gridx = 2; gbc.weightx = 0.20;
        JLabel l3 = new JLabel(col3); l3.setForeground(fg); l3.setFont(font); row.add(l3, gbc);

        return row;
    }

    private JSeparator createSeparator() {
        JSeparator sep = new JSeparator(JSeparator.HORIZONTAL);
        sep.setForeground(BORDER_COLOR);
        sep.setBackground(BG_DARK);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 2));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        return sep;
    }

    // ==================== CONFIG APPLY ====================

    /**
     * Writes current config editor values into the ModuleConfig for the given module.
     */
    private void applyConfigEditsToConfig(String moduleId) {
        ModuleConfig cfg = registry.getConfig(moduleId);
        if (cfg == null) return;

        List<ConfigEntry> knownEntries = KNOWN_CONFIGS.getOrDefault(moduleId, Collections.emptyList());
        Map<String, ConfigType> typeMap = new HashMap<>();
        for (ConfigEntry entry : knownEntries) {
            typeMap.put(entry.key, entry.type);
        }

        for (Map.Entry<String, JComponent> editorEntry : configEditors.entrySet()) {
            String key = editorEntry.getKey();
            JComponent comp = editorEntry.getValue();
            ConfigType type = typeMap.getOrDefault(key, ConfigType.STRING);

            if (comp instanceof JCheckBox) {
                cfg.setBool(key, ((JCheckBox) comp).isSelected());
            } else if (comp instanceof JTextField) {
                String text = ((JTextField) comp).getText().trim();
                if (type == ConfigType.INT) {
                    try {
                        cfg.setInt(key, Integer.parseInt(text));
                    } catch (NumberFormatException ignored) {}
                } else {
                    cfg.setString(key, text);
                }
            }
        }
    }

    /**
     * Apply all pending config changes (called when OK is pressed).
     */
    private void applyConfigChanges() {
        if (selectedModuleId != null) {
            applyConfigEditsToConfig(selectedModuleId);
        }
    }

    // ==================== RESULTS ====================

    /**
     * Returns the list of module IDs that the user checked (selected for scanning).
     */
    public List<String> getSelectedModuleIds() {
        List<String> ids = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : moduleCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                ids.add(entry.getKey());
            }
        }
        return ids;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    // ==================== HELPERS ====================

    private void setAllChecked(boolean checked) {
        for (JCheckBox cb : moduleCheckboxes.values()) {
            cb.setSelected(checked);
        }
    }

    private JButton createDarkButton(String text) {
        JButton btn = new JButton(text);
        btn.setBackground(BG_PANEL);
        btn.setForeground(FG_NORMAL);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR),
                new EmptyBorder(4, 12, 4, 12)));
        return btn;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    // ==================== CONFIG ENTRY MODEL ====================

    enum ConfigType { BOOL, INT, STRING }

    static class ConfigEntry {
        final String key;
        final ConfigType type;
        final String defaultValue;

        ConfigEntry(String key, ConfigType type, String defaultValue) {
            this.key = key;
            this.type = type;
            this.defaultValue = defaultValue;
        }
    }

    private static ConfigEntry boolEntry(String key, boolean defaultVal) {
        return new ConfigEntry(key, ConfigType.BOOL, String.valueOf(defaultVal));
    }

    private static ConfigEntry intEntry(String key, int defaultVal) {
        return new ConfigEntry(key, ConfigType.INT, String.valueOf(defaultVal));
    }

    private static ConfigEntry stringEntry(String key, String defaultVal) {
        return new ConfigEntry(key, ConfigType.STRING, defaultVal);
    }
}
