package com.omnistrike.ui;

import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Panel showing the HTTP request and response for findings.
 * When requestResponse is available, shows the full HTTP exchange.
 * When not (e.g., OOB/Collaborator findings), shows evidence and payload details.
 */
public class RequestResponsePanel extends JPanel {

    private final FindingsStore findingsStore;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private final JLabel countLabel;

    // Parallel list of findings for correct index-based lookup
    private final List<Finding> findingsList = new ArrayList<>();

    // Reusable date formatter
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    // Store refresh timer as a field so it can be stopped
    private final Timer refreshTimer;

    private static final String[] COLUMNS = {
            "Severity", "Confidence", "Module", "Title", "URL", "Parameter", "Time"
    };

    public RequestResponsePanel(FindingsStore findingsStore) {
        this.findingsStore = findingsStore;
        setLayout(new BorderLayout());

        // Top controls
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshTable());
        controls.add(refreshBtn);

        countLabel = new JLabel("Entries: 0");
        controls.add(Box.createHorizontalStrut(10));
        controls.add(countLabel);
        add(controls, BorderLayout.NORTH);

        // Findings table -- shows ALL findings
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(250);
        table.getColumnModel().getColumn(4).setPreferredWidth(220);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        table.getColumnModel().getColumn(6).setPreferredWidth(70);
        table.getColumnModel().getColumn(0).setCellRenderer(createSeverityRenderer());

        // Request area (left)
        requestArea = new JTextArea();
        requestArea.setEditable(false);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setLineWrap(true);
        requestArea.setWrapStyleWord(true);

        // Response area (right)
        responseArea = new JTextArea();
        responseArea.setEditable(false);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);

        // Labels for request/response panes
        JPanel requestPanel = new JPanel(new BorderLayout());
        JLabel reqLabel = new JLabel("  Request / Evidence");
        reqLabel.setFont(reqLabel.getFont().deriveFont(Font.BOLD));
        reqLabel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        requestPanel.add(reqLabel, BorderLayout.NORTH);
        requestPanel.add(new JScrollPane(requestArea), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        JLabel respLabel = new JLabel("  Response / Details");
        respLabel.setFont(respLabel.getFont().deriveFont(Font.BOLD));
        respLabel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        responsePanel.add(respLabel, BorderLayout.NORTH);
        responsePanel.add(new JScrollPane(responseArea), BorderLayout.CENTER);

        // Side-by-side split pane
        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestPanel, responsePanel);
        reqRespSplit.setResizeWeight(0.5);

        // Fix setDividerLocation(0.5) - must be set after the component is laid out
        reqRespSplit.addComponentListener(new ComponentAdapter() {
            private boolean initialized = false;

            @Override
            public void componentResized(ComponentEvent e) {
                if (!initialized && reqRespSplit.getWidth() > 0) {
                    initialized = true;
                    reqRespSplit.setDividerLocation(0.5);
                }
            }
        });

        // Table on top, request/response below
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), reqRespSplit);
        mainSplit.setDividerLocation(150);

        add(mainSplit, BorderLayout.CENTER);

        // Selection listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });

        // Auto-refresh every 3 seconds (store timer as a field)
        refreshTimer = new Timer(3000, e -> autoRefresh());
        refreshTimer.start();
    }

    private void autoRefresh() {
        // Wrap in invokeLater for EDT safety
        SwingUtilities.invokeLater(() -> {
            List<Finding> all = findingsStore.getAllFindings();
            if (all.size() != findingsList.size()) {
                for (int i = findingsList.size(); i < all.size(); i++) {
                    Finding f = all.get(i);
                    findingsList.add(f);
                    addFindingRow(f);
                }
                countLabel.setText("Entries: " + findingsList.size());
            }
        });
    }

    public void refreshTable() {
        // Wrap in invokeLater for EDT safety
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            List<Finding> all = findingsStore.getAllFindings();
            for (Finding f : all) {
                findingsList.add(f);
                addFindingRow(f);
            }
            countLabel.setText("Entries: " + findingsList.size());
            requestArea.setText("");
            responseArea.setText("");
        });
    }

    private void addFindingRow(Finding f) {
        tableModel.addRow(new Object[]{
                f.getSeverity() != null ? f.getSeverity().name() : "",
                f.getConfidence() != null ? f.getConfidence().name() : "",
                f.getModuleId() != null ? f.getModuleId() : "",
                f.getTitle() != null ? f.getTitle() : "",
                f.getUrl() != null ? f.getUrl() : "",
                f.getParameter() != null ? f.getParameter() : "",
                timeFormat.format(new Date(f.getTimestamp()))
        });
    }

    private void showSelectedDetail() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            requestArea.setText("");
            responseArea.setText("");
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= findingsList.size()) return;

        Finding f = findingsList.get(modelRow);

        if (f.getRequestResponse() != null) {
            // Has full HTTP request/response -- show it
            showHttpDetail(f);
        } else {
            // No HTTP data (e.g., OOB/Collaborator finding) -- show evidence
            showEvidenceDetail(f);
        }
    }

    private void showHttpDetail(Finding f) {
        try {
            var reqResp = f.getRequestResponse();

            if (reqResp.request() != null) {
                requestArea.setText(formatRequest(reqResp.request()));
            } else {
                requestArea.setText("(no request data)");
            }
            requestArea.setCaretPosition(0);

            if (reqResp.response() != null) {
                responseArea.setText(formatResponse(reqResp.response()));
            } else {
                responseArea.setText("(no response data)");
            }
            responseArea.setCaretPosition(0);
        } catch (Exception e) {
            requestArea.setText("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            responseArea.setText("");
        }
    }

    private void showEvidenceDetail(Finding f) {
        // Left pane: finding info + evidence (contains the payload details)
        StringBuilder left = new StringBuilder();
        left.append("=== FINDING DETAILS ===\n\n");
        left.append("Title:      ").append(f.getTitle() != null ? f.getTitle() : "N/A").append("\n");
        left.append("Module:     ").append(f.getModuleId() != null ? f.getModuleId() : "N/A").append("\n");
        left.append("Severity:   ").append(f.getSeverity()).append("\n");
        left.append("Confidence: ").append(f.getConfidence()).append("\n");
        left.append("URL:        ").append(f.getUrl() != null ? f.getUrl() : "N/A").append("\n");
        left.append("Parameter:  ").append(f.getParameter() != null && !f.getParameter().isEmpty() ? f.getParameter() : "N/A").append("\n");
        left.append("\n=== EVIDENCE ===\n\n");
        left.append(f.getEvidence() != null ? f.getEvidence() : "(none)");
        requestArea.setText(left.toString());
        requestArea.setCaretPosition(0);

        // Right pane: description + remediation
        StringBuilder right = new StringBuilder();
        right.append("=== DESCRIPTION ===\n\n");
        right.append(f.getDescription() != null ? f.getDescription() : "(none)");
        right.append("\n\n=== REMEDIATION ===\n\n");
        right.append(f.getRemediation() != null ? f.getRemediation() : "(none)");
        right.append("\n\n=== NOTE ===\n\n");
        right.append("This finding was detected via out-of-band (OOB) callback.\n");
        right.append("The HTTP request/response is not available because the\n");
        right.append("confirmation came asynchronously via Burp Collaborator.\n");
        right.append("Check the evidence field for payload details.");
        responseArea.setText(right.toString());
        responseArea.setCaretPosition(0);
    }

    private String formatRequest(burp.api.montoya.http.message.requests.HttpRequest req) {
        StringBuilder sb = new StringBuilder();
        try {
            var headers = req.headers();
            if (!headers.isEmpty()) {
                // First header in Montoya is the request line (e.g., "GET /path HTTP/1.1")
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
        StringBuilder sb = new StringBuilder();
        try {
            var headers = resp.headers();
            if (!headers.isEmpty()) {
                // First header in Montoya is the status line (e.g., "HTTP/1.1 200 OK")
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
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
}
