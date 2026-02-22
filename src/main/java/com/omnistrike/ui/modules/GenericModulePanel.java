package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Generic module detail panel showing findings for a specific module.
 * Used as the default detail view for modules that don't have a custom panel.
 */
public class GenericModulePanel extends JPanel {

    private final String moduleId;
    private final String moduleName;
    private final FindingsStore findingsStore;
    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea detailArea;

    // Parallel list of findings for correct index-based lookup
    private final List<Finding> findingsList = new ArrayList<>();

    // Reusable date formatter
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    // Auto-refresh timer stored as a field so it can be stopped
    private final Timer autoRefreshTimer;

    // Track last known finding count to avoid unnecessary table rebuilds
    private int lastKnownCount = 0;

    private static final String[] COLUMNS = {
            "Severity", "Confidence", "Title", "URL", "Parameter", "Time"
    };

    /** Legacy constructor for backwards compatibility (no Repeater support). */
    public GenericModulePanel(String moduleId, String moduleName, FindingsStore findingsStore) {
        this(moduleId, moduleName, findingsStore, null);
    }

    public GenericModulePanel(String moduleId, String moduleName, FindingsStore findingsStore, MontoyaApi api) {
        this.moduleId = moduleId;
        this.moduleName = moduleName;
        this.findingsStore = findingsStore;
        this.api = api;
        setLayout(new BorderLayout());

        // Header
        JLabel header = new JLabel(moduleName + " Findings");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 14f));
        header.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // Table
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setCellRenderer(createSeverityRenderer());

        // Right-click context menu on the table
        setupTableContextMenu();

        // Detail area
        detailArea = new JTextArea(6, 80);
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < findingsList.size()) {
                        Finding f = findingsList.get(modelRow);
                        StringBuilder sb = new StringBuilder();
                        sb.append("Evidence:\n").append(f.getEvidence() != null ? f.getEvidence() : "(none)");
                        sb.append("\n\nDescription:\n").append(f.getDescription() != null ? f.getDescription() : "(none)");
                        sb.append("\n\nRemediation:\n").append(f.getRemediation() != null ? f.getRemediation() : "(none)");

                        // Show full HTTP request/response with the payload
                        if (f.getRequestResponse() != null) {
                            sb.append("\n\n").append("=".repeat(80)).append("\n");
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
                }
            }
        });

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(detailArea));
        splitPane.setDividerLocation(250);

        // Controls
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshTable());
        controls.add(refreshBtn);

        JButton exportBtn = new JButton("Export");
        exportBtn.addActionListener(e -> exportFindings());
        controls.add(exportBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to clear all findings for " + moduleName + "? This cannot be undone.",
                    "Confirm Clear",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.YES_OPTION) {
                findingsStore.clearModule(moduleId);
                refreshTable();
            }
        });
        controls.add(clearBtn);

        add(header, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(controls, BorderLayout.SOUTH);

        // Auto-refresh timer (3 second interval)
        autoRefreshTimer = new Timer(3000, e -> autoRefresh());
        autoRefreshTimer.start();
    }

    /**
     * Sets up right-click context menu on the findings table.
     * Provides "Send to Repeater" and "Copy URL" actions.
     */
    private void setupTableContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            Finding f = getSelectedFinding();
            if (f == null) return;
            if (f.getRequestResponse() == null || f.getRequestResponse().request() == null) {
                JOptionPane.showMessageDialog(this, "No request data available for this finding.",
                        "Cannot Send", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (api != null) {
                String tabName = moduleName + ": " + truncate(f.getTitle(), 30);
                api.repeater().sendToRepeater(f.getRequestResponse().request(), tabName);
            } else {
                JOptionPane.showMessageDialog(this, "Repeater integration not available.",
                        "Unavailable", JOptionPane.WARNING_MESSAGE);
            }
        });
        popup.add(sendToRepeater);

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            Finding f = getSelectedFinding();
            if (f != null && f.getUrl() != null && !f.getUrl().isEmpty()) {
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(f.getUrl()), null);
            }
        });
        popup.add(copyUrl);

        table.setComponentPopupMenu(popup);

        // Also select the row under the cursor on right-click
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    /**
     * Returns the Finding for the currently selected table row, or null.
     */
    private Finding getSelectedFinding() {
        int row = table.getSelectedRow();
        if (row < 0) return null;
        int modelRow = table.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= findingsList.size()) return null;
        return findingsList.get(modelRow);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /**
     * Auto-refresh: only rebuilds the table when the finding count actually changes.
     * This avoids visual flickering and wasted CPU from rebuilding every 3 seconds.
     */
    private void autoRefresh() {
        SwingUtilities.invokeLater(() -> {
            List<Finding> currentFindings = findingsStore.getFindingsByModule(moduleId);
            if (currentFindings.size() != lastKnownCount) {
                lastKnownCount = currentFindings.size();
                tableModel.setRowCount(0);
                findingsList.clear();
                for (Finding f : currentFindings) {
                    findingsList.add(f);
                    addFindingRow(f);
                }
            }
        });
    }

    public void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            List<Finding> current = findingsStore.getFindingsByModule(moduleId);
            lastKnownCount = current.size();
            for (Finding f : current) {
                findingsList.add(f);
                addFindingRow(f);
            }
        });
    }

    private void addFindingRow(Finding f) {
        tableModel.addRow(new Object[]{
                f.getSeverity() != null ? f.getSeverity().name() : "",
                f.getConfidence() != null ? f.getConfidence().name() : "",
                f.getTitle() != null ? f.getTitle() : "",
                f.getUrl() != null ? f.getUrl() : "",
                f.getParameter() != null ? f.getParameter() : "",
                timeFormat.format(new Date(f.getTimestamp()))
        });
    }

    /**
     * Properly escapes a CSV field: wraps in quotes, escapes internal quotes,
     * and handles newlines and commas.
     */
    private String escapeCsvField(String value) {
        if (value == null) return "\"\"";
        String escaped = value.replace("\"", "\"\"");
        escaped = escaped.replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
        return "\"" + escaped + "\"";
    }

    private void exportFindings() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(moduleId + "_findings.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                pw.println("Severity,Confidence,Title,URL,Parameter,Evidence,Description,Remediation");
                for (Finding f : findingsStore.getFindingsByModule(moduleId)) {
                    pw.println(
                            escapeCsvField(f.getSeverity() != null ? f.getSeverity().name() : "") + ","
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

    /**
     * Stops the auto-refresh timer. Call this from the extension unload handler.
     */
    public void stopTimers() {
        if (autoRefreshTimer != null) {
            autoRefreshTimer.stop();
        }
    }
}
