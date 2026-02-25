package com.omnistrike.ui;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Predicate;

/**
 * Global findings table aggregating results from all modules.
 */
public class FindingsOverviewPanel extends JPanel {

    private final FindingsStore findingsStore;
    private MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea detailArea;
    private final TableRowSorter<DefaultTableModel> rowSorter;

    // Parallel list of findings matching table model rows for correct index-based lookup
    private final List<Finding> findingsList = new ArrayList<>();
    private final Predicate<Finding> filter;

    // Reusable date formatter (avoid creating per-row)
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    // Filter controls
    private final JComboBox<String> severityFilter;
    private final JComboBox<String> moduleFilter;
    private final JTextField searchField;

    private static final String[] COLUMNS = {
            "Module", "Severity", "Confidence", "Title", "URL", "Parameter", "Timestamp"
    };

    public FindingsOverviewPanel(FindingsStore findingsStore) {
        this(findingsStore, f -> true);
    }

    public FindingsOverviewPanel(FindingsStore findingsStore, Predicate<Finding> filter) {
        this.findingsStore = findingsStore;
        this.filter = filter;
        setLayout(new BorderLayout());

        // ============ TABLE ============
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        table = new JTable(tableModel);
        rowSorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(rowSorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(70);
        table.getColumnModel().getColumn(3).setPreferredWidth(300);
        table.getColumnModel().getColumn(4).setPreferredWidth(250);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        table.getColumnModel().getColumn(6).setPreferredWidth(120);

        table.getColumnModel().getColumn(1).setCellRenderer(createSeverityRenderer());

        // Detail pane at bottom
        detailArea = new JTextArea(8, 80);
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedFindingDetail();
            }
        });

        // Right-click context menu
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> sendSelectedToRepeater());
        popupMenu.add(sendToRepeaterItem);

        popupMenu.addSeparator();

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> copySelectedUrl());
        popupMenu.add(copyUrlItem);

        JMenuItem copyFindingItem = new JMenuItem("Copy Finding as Text");
        copyFindingItem.addActionListener(e -> copySelectedFindingAsText());
        popupMenu.add(copyFindingItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                    }
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(detailArea));
        splitPane.setDividerLocation(300);
        add(splitPane, BorderLayout.CENTER);

        // ============ TOP AREA: controls + filter row ============
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));

        // Controls row
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshTable());
        controls.add(refreshBtn);

        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportCsv());
        controls.add(exportCsvBtn);

        JButton exportMdBtn = new JButton("Export Markdown");
        exportMdBtn.addActionListener(e -> exportMarkdown());
        controls.add(exportMdBtn);

        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to clear all findings? This cannot be undone.",
                    "Confirm Clear All",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.YES_OPTION) {
                findingsStore.clear();
                refreshTable();
            }
        });
        controls.add(clearBtn);

        JLabel countLabel = new JLabel("Findings: 0");
        controls.add(Box.createHorizontalStrut(20));
        controls.add(countLabel);

        topPanel.add(controls);

        // Filter row
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filters"));

        filterPanel.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(new String[]{"All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"});
        severityFilter.setToolTipText("Filter findings by severity level");
        severityFilter.addActionListener(e -> applyFilters());
        filterPanel.add(severityFilter);

        filterPanel.add(Box.createHorizontalStrut(10));
        filterPanel.add(new JLabel("Module:"));
        moduleFilter = new JComboBox<>(new String[]{"All"});
        moduleFilter.setToolTipText("Filter findings by scan module");
        moduleFilter.addActionListener(e -> applyFilters());
        filterPanel.add(moduleFilter);

        filterPanel.add(Box.createHorizontalStrut(10));
        filterPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.setToolTipText("Search across all fields (title, URL, parameter, etc.)");
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        filterPanel.add(searchField);

        JButton clearFiltersBtn = new JButton("Clear Filters");
        clearFiltersBtn.addActionListener(e -> {
            severityFilter.setSelectedIndex(0);
            moduleFilter.setSelectedIndex(0);
            searchField.setText("");
        });
        filterPanel.add(clearFiltersBtn);

        topPanel.add(filterPanel);
        add(topPanel, BorderLayout.NORTH);

        // Listen for new findings using addListener (not deprecated setListener)
        findingsStore.addListener(finding -> {
            SwingUtilities.invokeLater(() -> {
                if (filter.test(finding)) {
                    addFindingRow(finding);
                    countLabel.setText("Findings: " + findingsList.size());
                    updateModuleFilterOptions();
                }
            });
        });

        // Load any findings that were added before this listener was registered.
        // This handles the race condition where TrafficInterceptor processes requests
        // (and modules add findings to FindingsStore) before the UI panel is created.
        SwingUtilities.invokeLater(() -> {
            for (Finding f : findingsStore.getAllFindings()) {
                if (filter.test(f) && !findingsList.contains(f)) {
                    addFindingRow(f);
                }
            }
            if (!findingsList.isEmpty()) {
                countLabel.setText("Findings: " + findingsList.size());
                updateModuleFilterOptions();
            }
        });
    }

    /**
     * Applies severity, module, and text search filters to the table via RowFilter.
     */
    private void applyFilters() {
        List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();

        // Severity filter
        String selectedSeverity = (String) severityFilter.getSelectedItem();
        if (selectedSeverity != null && !"All".equals(selectedSeverity)) {
            filters.add(RowFilter.regexFilter("^" + selectedSeverity + "$", 1));
        }

        // Module filter
        String selectedModule = (String) moduleFilter.getSelectedItem();
        if (selectedModule != null && !"All".equals(selectedModule)) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(selectedModule) + "$", 0));
        }

        // Text search filter (across all columns)
        String searchText = searchField.getText().trim();
        if (!searchText.isEmpty()) {
            try {
                filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(searchText)));
            } catch (java.util.regex.PatternSyntaxException ex) {
                // Ignore invalid regex
            }
        }

        if (filters.isEmpty()) {
            rowSorter.setRowFilter(null);
        } else {
            rowSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    /**
     * Updates the module filter dropdown with all unique module IDs from current findings.
     */
    private void updateModuleFilterOptions() {
        String currentSelection = (String) moduleFilter.getSelectedItem();
        java.util.Set<String> modules = new java.util.LinkedHashSet<>();
        for (Finding f : findingsList) {
            if (f.getModuleId() != null) {
                modules.add(f.getModuleId());
            }
        }
        moduleFilter.removeAllItems();
        moduleFilter.addItem("All");
        for (String m : modules) {
            moduleFilter.addItem(m);
        }
        if (currentSelection != null) {
            moduleFilter.setSelectedItem(currentSelection);
        }
    }

    public void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            for (Finding f : findingsStore.getAllFindings()) {
                if (filter.test(f)) {
                    addFindingRow(f);
                }
            }
            updateModuleFilterOptions();
        });
    }

    private void addFindingRow(Finding f) {
        findingsList.add(f);
        tableModel.addRow(new Object[]{
                f.getModuleId() != null ? f.getModuleId() : "",
                f.getSeverity() != null ? f.getSeverity().name() : "",
                f.getConfidence() != null ? f.getConfidence().name() : "",
                f.getTitle() != null ? f.getTitle() : "",
                f.getUrl() != null ? f.getUrl() : "",
                f.getParameter() != null ? f.getParameter() : "",
                dateFormat.format(new Date(f.getTimestamp()))
        });
    }

    private void showSelectedFindingDetail() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);

        if (modelRow < 0 || modelRow >= findingsList.size()) return;
        Finding f = findingsList.get(modelRow);

        StringBuilder sb = new StringBuilder();
        sb.append("Title: ").append(f.getTitle() != null ? f.getTitle() : "N/A").append("\n");
        sb.append("Module: ").append(f.getModuleId() != null ? f.getModuleId() : "N/A").append("\n");
        sb.append("Severity: ").append(f.getSeverity()).append(" | Confidence: ").append(f.getConfidence()).append("\n");
        sb.append("URL: ").append(f.getUrl() != null ? f.getUrl() : "N/A").append("\n");
        sb.append("Parameter: ").append(f.getParameter() != null && !f.getParameter().isEmpty() ? f.getParameter() : "N/A").append("\n\n");
        sb.append("Description:\n").append(f.getDescription() != null ? f.getDescription() : "(none)").append("\n\n");
        sb.append("Remediation:\n").append(f.getRemediation() != null ? f.getRemediation() : "(none)").append("\n\n");
        sb.append("Evidence:\n").append(f.getEvidence() != null ? f.getEvidence() : "(none)").append("\n");

        // Show full HTTP request/response with the payload
        if (f.getRequestResponse() != null) {
            sb.append("\n").append("=".repeat(80)).append("\n");
            sb.append("REQUEST (with payload):\n");
            sb.append("=".repeat(80)).append("\n");
            sb.append(formatRequest(f.getRequestResponse().request()));
            sb.append("\n\n").append("=".repeat(80)).append("\n");
            sb.append("RESPONSE:\n");
            sb.append("=".repeat(80)).append("\n");
            sb.append(formatResponse(f.getRequestResponse().response()));
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private String formatRequest(burp.api.montoya.http.message.requests.HttpRequest req) {
        if (req == null) return "(no request data)\n";
        StringBuilder sb = new StringBuilder();
        try {
            var headers = req.headers();
            if (!headers.isEmpty()) {
                sb.append(headers.get(0).toString()).append("\n");
                for (int i = 1; i < headers.size(); i++) {
                    sb.append(headers.get(i).name()).append(": ").append(headers.get(i).value()).append("\n");
                }
            }
            sb.append("\n");
            String body = req.bodyToString();
            if (body != null && !body.isEmpty()) {
                sb.append(body);
            }
        } catch (Exception e) {
            sb.append("[Error formatting request: ").append(e.getMessage()).append("]");
        }
        return sb.toString();
    }

    private String formatResponse(burp.api.montoya.http.message.responses.HttpResponse resp) {
        if (resp == null) return "(no response data)\n";
        StringBuilder sb = new StringBuilder();
        try {
            var headers = resp.headers();
            if (!headers.isEmpty()) {
                sb.append(headers.get(0).toString()).append("\n");
                for (int i = 1; i < headers.size(); i++) {
                    sb.append(headers.get(i).name()).append(": ").append(headers.get(i).value()).append("\n");
                }
            }
            sb.append("\n");
            String body = resp.bodyToString();
            if (body != null && !body.isEmpty()) {
                if (body.length() > 50000) {
                    sb.append(body, 0, 50000);
                    sb.append("\n\n--- [Truncated: ").append(body.length()).append(" bytes total] ---");
                } else {
                    sb.append(body);
                }
            }
        } catch (Exception e) {
            sb.append("[Error formatting response: ").append(e.getMessage()).append("]");
        }
        return sb.toString();
    }

    /** Sets the Montoya API reference for Send to Repeater integration. */
    public void setApi(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Sends the selected finding's request to Burp Repeater.
     */
    private void sendSelectedToRepeater() {
        Finding f = getSelectedFinding();
        if (f == null) return;
        if (f.getRequestResponse() == null || f.getRequestResponse().request() == null) {
            JOptionPane.showMessageDialog(this, "No request data available for this finding.",
                    "Cannot Send", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (api != null) {
            String tabName = f.getModuleId() + ": " + truncateStr(f.getTitle(), 30);
            api.repeater().sendToRepeater(f.getRequestResponse().request(), tabName);
        } else {
            JOptionPane.showMessageDialog(this, "Repeater integration not available.",
                    "Unavailable", JOptionPane.WARNING_MESSAGE);
        }
    }

    private static String truncateStr(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /**
     * Copies the URL of the selected finding to the system clipboard.
     */
    private void copySelectedUrl() {
        Finding f = getSelectedFinding();
        if (f != null && f.getUrl() != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(f.getUrl()), null);
        }
    }

    /**
     * Copies the selected finding as a text summary to the system clipboard.
     */
    private void copySelectedFindingAsText() {
        Finding f = getSelectedFinding();
        if (f == null) return;

        StringBuilder sb = new StringBuilder();
        sb.append("Title: ").append(f.getTitle() != null ? f.getTitle() : "N/A").append("\n");
        sb.append("Module: ").append(f.getModuleId() != null ? f.getModuleId() : "N/A").append("\n");
        sb.append("Severity: ").append(f.getSeverity()).append("\n");
        sb.append("Confidence: ").append(f.getConfidence()).append("\n");
        sb.append("URL: ").append(f.getUrl() != null ? f.getUrl() : "N/A").append("\n");
        sb.append("Parameter: ").append(f.getParameter() != null && !f.getParameter().isEmpty() ? f.getParameter() : "N/A").append("\n");
        sb.append("Description: ").append(f.getDescription() != null ? f.getDescription() : "(none)").append("\n");
        sb.append("Evidence: ").append(f.getEvidence() != null ? f.getEvidence() : "(none)").append("\n");
        sb.append("Remediation: ").append(f.getRemediation() != null ? f.getRemediation() : "(none)").append("\n");

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                new StringSelection(sb.toString()), null);
    }

    /**
     * Returns the Finding corresponding to the currently selected table row, or null.
     */
    private Finding getSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= findingsList.size()) return null;
        return findingsList.get(modelRow);
    }

    /**
     * Properly escapes a CSV field: wraps in quotes, escapes internal quotes,
     * and handles newlines and commas.
     */
    private String escapeCsvField(String value) {
        if (value == null) return "\"\"";
        // Always wrap in quotes; double any existing quotes
        String escaped = value.replace("\"", "\"\"");
        // Replace newlines with spaces for CSV safety
        escaped = escaped.replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
        return "\"" + escaped + "\"";
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("findings.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                pw.println("Module,Severity,Confidence,Title,URL,Parameter,Evidence,Description,Remediation");
                for (Finding f : findingsStore.getAllFindings()) {
                    if (!filter.test(f)) continue;
                    pw.println(
                            escapeCsvField(f.getModuleId()) + ","
                            + escapeCsvField(f.getSeverity() != null ? f.getSeverity().name() : "") + ","
                            + escapeCsvField(f.getConfidence() != null ? f.getConfidence().name() : "") + ","
                            + escapeCsvField(f.getTitle()) + ","
                            + escapeCsvField(f.getUrl()) + ","
                            + escapeCsvField(f.getParameter()) + ","
                            + escapeCsvField(f.getEvidence()) + ","
                            + escapeCsvField(f.getDescription()) + ","
                            + escapeCsvField(f.getRemediation())
                    );
                }
                JOptionPane.showMessageDialog(this, "Exported to " + fc.getSelectedFile().getName());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
            }
        }
    }

    private DefaultTableCellRenderer createSeverityRenderer() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected && value != null) {
                    String sev = value.toString();
                    switch (sev) {
                        case "CRITICAL" -> { c.setBackground(new Color(180, 30, 30)); c.setForeground(Color.WHITE); }
                        case "HIGH" -> { c.setBackground(new Color(220, 80, 40)); c.setForeground(Color.WHITE); }
                        case "MEDIUM" -> { c.setBackground(new Color(230, 160, 30)); c.setForeground(Color.BLACK); }
                        case "LOW" -> { c.setBackground(new Color(70, 140, 200)); c.setForeground(Color.WHITE); }
                        case "INFO" -> { c.setBackground(new Color(130, 130, 130)); c.setForeground(Color.WHITE); }
                        default -> { c.setBackground(table.getBackground()); c.setForeground(table.getForeground()); }
                    }
                } else if (!isSelected) {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                }
                setHorizontalAlignment(SwingConstants.CENTER);
                return c;
            }
        };
    }

    private void exportMarkdown() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("findings.md"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                pw.println("# OmniStrike Findings Report\n");
                pw.println("Generated: " + dateFormat.format(new Date()));
                pw.println("\n| # | Severity | Module | Title | URL | Parameter |");
                pw.println("|---|----------|--------|-------|-----|-----------|");
                int i = 1;
                for (Finding f : findingsStore.getAllFindings()) {
                    if (!filter.test(f)) continue;
                    pw.printf("| %d | %s | %s | %s | %s | %s |%n",
                            i++,
                            f.getSeverity() != null ? f.getSeverity() : "",
                            f.getModuleId() != null ? f.getModuleId() : "",
                            f.getTitle() != null ? f.getTitle() : "",
                            f.getUrl() != null ? f.getUrl() : "",
                            f.getParameter() != null ? f.getParameter() : "");
                }
                pw.println("\n## Details\n");
                i = 1;
                for (Finding f : findingsStore.getAllFindings()) {
                    if (!filter.test(f)) continue;
                    pw.println("### " + i++ + ". " + (f.getTitle() != null ? f.getTitle() : "N/A"));
                    pw.println("- **Severity**: " + f.getSeverity() + " | **Confidence**: " + f.getConfidence());
                    pw.println("- **URL**: " + (f.getUrl() != null ? f.getUrl() : "N/A"));
                    pw.println("- **Parameter**: " + (f.getParameter() != null && !f.getParameter().isEmpty() ? f.getParameter() : "N/A"));
                    pw.println("- **Evidence**: " + (f.getEvidence() != null ? f.getEvidence() : "N/A"));
                    pw.println("- **Remediation**: " + (f.getRemediation() != null ? f.getRemediation() : "N/A"));
                    pw.println("\n" + (f.getDescription() != null ? f.getDescription() : "(no description)") + "\n");
                }
                JOptionPane.showMessageDialog(this, "Exported to " + fc.getSelectedFile().getName());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
            }
        }
    }

}
