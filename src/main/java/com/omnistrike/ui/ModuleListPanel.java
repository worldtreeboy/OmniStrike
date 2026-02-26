package com.omnistrike.ui;

import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.ModuleRegistry;
import com.omnistrike.model.ScanModule;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Left sidebar panel showing all modules with enable/disable checkboxes.
 * Clicking a module selects it and notifies the main panel to show its detail view.
 */
public class ModuleListPanel extends JPanel {

    private final ModuleRegistry registry;
    private final FindingsStore findingsStore;
    private Consumer<String> onModuleSelected;
    private final Map<String, JPanel> moduleEntries = new HashMap<>();
    private String selectedModuleId;

    // Container panel that holds module entries (inside a scroll pane)
    private final JPanel listContainer;

    public ModuleListPanel(ModuleRegistry registry, FindingsStore findingsStore) {
        this.registry = registry;
        this.findingsStore = findingsStore;
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Modules"));
        setPreferredSize(new Dimension(250, 0));

        // Select All / Deselect All buttons at the top
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.setToolTipText("Enable all scan modules");
        selectAllBtn.setMargin(new Insets(2, 6, 2, 6));
        selectAllBtn.addActionListener(e -> {
            for (ScanModule module : registry.getAllModules()) {
                registry.setEnabled(module.getId(), true);
            }
            rebuildModuleList();
        });
        buttonPanel.add(selectAllBtn);

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.setToolTipText("Disable all scan modules");
        deselectAllBtn.setMargin(new Insets(2, 6, 2, 6));
        deselectAllBtn.addActionListener(e -> {
            for (ScanModule module : registry.getAllModules()) {
                registry.setEnabled(module.getId(), false);
            }
            rebuildModuleList();
        });
        buttonPanel.add(deselectAllBtn);

        add(buttonPanel, BorderLayout.NORTH);

        // Scrollable container for module entries
        listContainer = new JPanel();
        listContainer.setLayout(new BoxLayout(listContainer, BoxLayout.Y_AXIS));
        JScrollPane scrollPane = new JScrollPane(listContainer);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);

        buildModuleList();
    }

    public void setOnModuleSelected(Consumer<String> callback) {
        this.onModuleSelected = callback;
    }

    /**
     * Public method to rebuild the module list (e.g., after Select All / Deselect All).
     */
    public void rebuildModuleList() {
        buildModuleList();
    }

    private void buildModuleList() {
        listContainer.removeAll();
        moduleEntries.clear();

        // Group modules into categories: Active Scanners, Passive Analyzers, AI
        java.util.List<ScanModule> activeModules = new java.util.ArrayList<>();
        java.util.List<ScanModule> passiveModules = new java.util.ArrayList<>();
        ScanModule aiModule = null;

        for (ScanModule module : registry.getAllModules()) {
            if (ModuleRegistry.AI_MODULE_ID.equals(module.getId())) {
                aiModule = module;
            } else if (module.isPassive()) {
                passiveModules.add(module);
            } else {
                activeModules.add(module);
            }
        }

        // --- AI section (top of the list) ---
        if (aiModule != null) {
            listContainer.add(createSectionHeader("AI Analysis"));
            listContainer.add(createModuleEntry(aiModule));
        }

        // --- Active Scanners section ---
        if (!activeModules.isEmpty()) {
            listContainer.add(createSectionSeparator());
            listContainer.add(createSectionHeader("Active Scanners"));
            for (ScanModule module : activeModules) {
                listContainer.add(createModuleEntry(module));
            }
        }

        // --- Passive Analyzers section ---
        if (!passiveModules.isEmpty()) {
            listContainer.add(createSectionSeparator());
            listContainer.add(createSectionHeader("Passive Analyzers"));
            for (ScanModule module : passiveModules) {
                listContainer.add(createModuleEntry(module));
            }
        }

        listContainer.add(Box.createVerticalGlue());
        listContainer.revalidate();
        listContainer.repaint();
    }

    /**
     * Creates a section header label for the module list sidebar.
     */
    private JPanel createSectionHeader(String title) {
        JPanel header = new JPanel(new BorderLayout());
        header.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        header.setPreferredSize(new Dimension(250, 24));
        header.setBorder(BorderFactory.createEmptyBorder(4, 8, 2, 4));
        header.setOpaque(false);

        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        label.setForeground(new Color(100, 100, 100));
        header.add(label, BorderLayout.WEST);

        return header;
    }

    /**
     * Creates a thin separator line between sections.
     */
    private JPanel createSectionSeparator() {
        JPanel sep = new JPanel();
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 6));
        sep.setPreferredSize(new Dimension(250, 6));
        sep.setOpaque(false);
        sep.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(200, 200, 200)));
        return sep;
    }

    /**
     * Creates a module entry row with checkbox, name, description, and finding count.
     */
    private JPanel createModuleEntry(ScanModule module) {
        JPanel entry = new JPanel(new BorderLayout(5, 0));

        // Calculate height from font metrics instead of hard-coded 45px
        FontMetrics fm = entry.getFontMetrics(entry.getFont().deriveFont(Font.BOLD, 12f));
        int lineHeight = fm.getHeight();
        // Two lines of text + padding
        int entryHeight = (lineHeight * 2) + 16;
        entry.setMaximumSize(new Dimension(Integer.MAX_VALUE, entryHeight));
        entry.setPreferredSize(new Dimension(250, entryHeight));

        entry.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        entry.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        JCheckBox enableBox = new JCheckBox();
        enableBox.setSelected(registry.isEnabled(module.getId()));
        enableBox.setToolTipText("Enable/disable " + module.getName());
        enableBox.addActionListener(e -> registry.setEnabled(module.getId(), enableBox.isSelected()));

        JPanel textPanel = new JPanel(new GridLayout(2, 1));
        textPanel.setOpaque(false);

        JLabel nameLabel = new JLabel(module.getName());
        nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD, 12f));

        String tag = module.getCategory().name();
        String type = module.isPassive() ? "Passive" : "Active";
        String suffix = ModuleRegistry.AI_MODULE_ID.equals(module.getId()) ? " | Optional" : "";
        JLabel descLabel = new JLabel(tag + " | " + type + suffix);
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 10f));
        descLabel.setForeground(Color.GRAY);

        textPanel.add(nameLabel);
        textPanel.add(descLabel);

        JLabel countLabel = new JLabel("0");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD));
        countLabel.setForeground(new Color(100, 100, 100));

        entry.add(enableBox, BorderLayout.WEST);
        entry.add(textPanel, BorderLayout.CENTER);
        entry.add(countLabel, BorderLayout.EAST);

        // Tooltip on the whole module entry
        entry.setToolTipText(module.getDescription() != null ? module.getDescription()
                : module.getName() + " (" + tag + ", " + type + ")");

        // Click to select
        entry.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                selectModule(module.getId());
            }
        });

        // Restore selection highlight if this module was previously selected
        if (module.getId().equals(selectedModuleId)) {
            entry.setBackground(new Color(200, 220, 240));
            entry.setOpaque(true);
        }

        moduleEntries.put(module.getId(), entry);
        return entry;
    }

    public void selectModule(String moduleId) {
        selectedModuleId = moduleId;

        // Update visual selection
        for (Map.Entry<String, JPanel> entry : moduleEntries.entrySet()) {
            if (entry.getKey().equals(moduleId)) {
                entry.getValue().setBackground(new Color(200, 220, 240));
                entry.getValue().setOpaque(true);
            } else {
                entry.getValue().setOpaque(false);
                entry.getValue().setBackground(null);
            }
            entry.getValue().repaint();
        }

        if (onModuleSelected != null) {
            onModuleSelected.accept(moduleId);
        }
    }

    public void updateFindingsCounts() {
        SwingUtilities.invokeLater(() -> {
            for (ScanModule module : registry.getAllModules()) {
                JPanel entry = moduleEntries.get(module.getId());
                if (entry != null) {
                    Component eastComp = ((BorderLayout) entry.getLayout()).getLayoutComponent(BorderLayout.EAST);
                    if (eastComp instanceof JLabel) {
                        int count = findingsStore.getCountByModule(module.getId());
                        ((JLabel) eastComp).setText(String.valueOf(count));
                        if (count > 0) {
                            ((JLabel) eastComp).setForeground(new Color(200, 50, 50));
                        }
                    }
                }
            }
        });
    }
}
