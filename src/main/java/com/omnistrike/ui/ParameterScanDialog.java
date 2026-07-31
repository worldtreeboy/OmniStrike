package com.omnistrike.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnistrike.framework.PrivacyManager;
import com.omnistrike.model.ScanModule;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.omnistrike.ui.CyberTheme.*;

/**
 * Parameter + module picker launched from "Send to OmniStrike (All Modules)".
 *
 * <p>Left list: every scannable parameter (query/body/cookie params, injectable
 * headers, URL path segments), grouped by category, each with a tick box.
 * Right list: the modules to run, grouped into Active Scanners and Passive
 * Analyzers. Everything is checked by default.
 *
 * <p>On "Scan", the caller runs the selected active modules against each ticked
 * parameter and the selected passive modules once over the whole request.
 * Cyberpunk/neon theme via {@link CyberTheme}.
 */
public class ParameterScanDialog extends JDialog {

    /** A single scannable parameter target. */
    public static class ParamItem {
        /** Internal name passed to the scanner (e.g. "id" or "path:3:12"). */
        public final String internalName;
        /** Human-friendly label shown in the list. */
        public final String displayName;
        /** Group heading: "Parameters", "Headers", or "Path Segments". */
        public final String category;

        public ParamItem(String internalName, String displayName, String category) {
            this.internalName = internalName;
            this.displayName = displayName;
            this.category = category;
        }
    }

    // internalName -> checkbox
    private final Map<String, JCheckBox> paramCheckboxes = new LinkedHashMap<>();
    // moduleId -> checkbox
    private final Map<String, JCheckBox> activeModuleCheckboxes = new LinkedHashMap<>();
    private final Map<String, JCheckBox> passiveModuleCheckboxes = new LinkedHashMap<>();

    private boolean confirmed = false;

    public ParameterScanDialog(Frame owner, HttpRequestResponse reqResp,
                               List<ParamItem> params,
                               List<ScanModule> activeModules,
                               List<ScanModule> passiveModules) {
        super(owner, "OmniStrike — Select Parameters & Modules", true);

        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBackground(BG_DARK);
        root.setBorder(new EmptyBorder(10, 10, 10, 10));

        // ==================== HEADER ====================
        JLabel headerLabel = new JLabel("<html>Scan target:<br><b>"
                + escape(truncate(PrivacyManager.maskForDisplay(reqResp.request().url()), 90))
                + "</b></html>");
        headerLabel.setForeground(NEON_CYAN);
        headerLabel.setFont(MONO_BOLD);
        headerLabel.setBorder(new EmptyBorder(0, 0, 6, 0));
        root.add(headerLabel, BorderLayout.NORTH);

        // ==================== CENTER: params | modules ====================
        JPanel paramsPanel = buildParamsPanel(params);
        JPanel modulesPanel = buildModulesPanel(activeModules, passiveModules);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, paramsPanel, modulesPanel);
        split.setDividerLocation(320);
        split.setBackground(BG_DARK);
        split.setBorder(null);
        styleSplitPane(split);
        root.add(split, BorderLayout.CENTER);

        // ==================== BUTTON BAR ====================
        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        buttonBar.setBackground(BG_DARK);
        buttonBar.setBorder(new EmptyBorder(8, 0, 0, 0));

        JButton selectAllBtn = darkButton("Select All");
        selectAllBtn.addActionListener(e -> setAllChecked(true));
        buttonBar.add(selectAllBtn);

        JButton deselectAllBtn = darkButton("Deselect All");
        deselectAllBtn.addActionListener(e -> setAllChecked(false));
        buttonBar.add(deselectAllBtn);

        buttonBar.add(Box.createHorizontalStrut(20));

        JButton cancelBtn = darkButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonBar.add(cancelBtn);

        JButton scanBtn = darkButton("Scan");
        CyberTheme.styleFilledButton(scanBtn, NEON_GREEN);
        scanBtn.addActionListener(e -> { confirmed = true; dispose(); });
        buttonBar.add(scanBtn);

        root.add(buttonBar, BorderLayout.SOUTH);

        setContentPane(root);
        setSize(660, 480);
        setLocationRelativeTo(owner);
    }

    // ==================== PARAMETERS PANEL ====================

    private JPanel buildParamsPanel(List<ParamItem> params) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);

        JLabel title = new JLabel("Parameters");
        title.setForeground(NEON_MAGENTA);
        title.setFont(MONO_BOLD);
        title.setBorder(new EmptyBorder(0, 2, 4, 0));
        panel.add(title, BorderLayout.NORTH);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(BG_DARK);
        content.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Render in category order, only showing categories that have items.
        for (String category : new String[]{"Parameters", "Headers", "Path Segments"}) {
            List<ParamItem> inCategory = new ArrayList<>();
            for (ParamItem p : params) {
                if (category.equals(p.category)) inCategory.add(p);
            }
            if (inCategory.isEmpty()) continue;

            addGroupLabel(content, category);
            for (ParamItem p : inCategory) {
                JCheckBox cb = makeCheckbox(p.displayName);
                paramCheckboxes.put(p.internalName, cb);
                content.add(cb);
            }
            content.add(Box.createVerticalStrut(8));
        }

        if (paramCheckboxes.isEmpty()) {
            JLabel none = new JLabel("No scannable parameters");
            none.setForeground(FG_DIM);
            none.setFont(MONO_FONT);
            none.setBorder(new EmptyBorder(6, 4, 0, 0));
            none.setAlignmentX(Component.LEFT_ALIGNMENT);
            content.add(none);
        }

        content.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBackground(BG_DARK);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setBorder(new CyberTheme.GlowLineBorder(BORDER, 1));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    // ==================== MODULES PANEL ====================

    private JPanel buildModulesPanel(List<ScanModule> activeModules, List<ScanModule> passiveModules) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARK);

        JLabel title = new JLabel("Modules");
        title.setForeground(NEON_CYAN);
        title.setFont(MONO_BOLD);
        title.setBorder(new EmptyBorder(0, 2, 4, 0));
        panel.add(title, BorderLayout.NORTH);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(BG_DARK);
        content.setBorder(new EmptyBorder(4, 4, 4, 4));

        if (!activeModules.isEmpty()) {
            addGroupLabel(content, "Active Scanners");
            for (ScanModule m : activeModules) {
                JCheckBox cb = makeCheckbox(m.getName());
                cb.setToolTipText(m.getDescription());
                activeModuleCheckboxes.put(m.getId(), cb);
                content.add(cb);
            }
            content.add(Box.createVerticalStrut(8));
        }

        if (!passiveModules.isEmpty()) {
            addGroupLabel(content, "Passive Analyzers");
            for (ScanModule m : passiveModules) {
                JCheckBox cb = makeCheckbox(m.getName());
                cb.setToolTipText(m.getDescription());
                passiveModuleCheckboxes.put(m.getId(), cb);
                content.add(cb);
            }
        }

        content.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBackground(BG_DARK);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setBorder(new CyberTheme.GlowLineBorder(BORDER, 1));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    // ==================== SHARED UI HELPERS ====================

    private void addGroupLabel(JPanel container, String text) {
        JLabel label = new JLabel(text);
        label.setForeground(NEON_CYAN);
        label.setFont(MONO_BOLD);
        label.setBorder(new EmptyBorder(6, 4, 2, 0));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        container.add(label);
    }

    private JCheckBox makeCheckbox(String label) {
        JCheckBox cb = new JCheckBox(label);
        cb.setSelected(true);
        cb.setBackground(BG_DARK);
        cb.setForeground(FG_PRIMARY);
        cb.setFont(MONO_FONT);
        cb.setFocusPainted(false);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        cb.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        cb.setBorder(new EmptyBorder(1, 16, 1, 0));
        return cb;
    }

    private JButton darkButton(String text) {
        JButton btn = new JButton(text);
        CyberTheme.styleButton(btn, NEON_CYAN);
        return btn;
    }

    private void setAllChecked(boolean checked) {
        for (JCheckBox cb : paramCheckboxes.values()) cb.setSelected(checked);
        for (JCheckBox cb : activeModuleCheckboxes.values()) cb.setSelected(checked);
        for (JCheckBox cb : passiveModuleCheckboxes.values()) cb.setSelected(checked);
    }

    // ==================== RESULTS ====================

    public boolean isConfirmed() {
        return confirmed;
    }

    /** Internal names of the ticked parameters. */
    public List<String> getSelectedParameters() {
        return checkedKeys(paramCheckboxes);
    }

    public List<String> getSelectedActiveModuleIds() {
        return checkedKeys(activeModuleCheckboxes);
    }

    public List<String> getSelectedPassiveModuleIds() {
        return checkedKeys(passiveModuleCheckboxes);
    }

    private static List<String> checkedKeys(Map<String, JCheckBox> map) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> e : map.entrySet()) {
            if (e.getValue().isSelected()) out.add(e.getKey());
        }
        return out;
    }

    // ==================== UTIL ====================

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
