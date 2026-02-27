package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;
import com.omnistrike.modules.exploit.omnimap.OmniMapModule;
import com.omnistrike.modules.exploit.omnimap.OmniMapResult;
import com.omnistrike.ui.CyberTheme;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;

import static com.omnistrike.ui.CyberTheme.*;

/**
 * OmniMap results panel — real-time display of SQL injection exploitation.
 *
 * Layout:
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ [PRIORITY] OmniMap is running — other scans paused              │
 * │ Status: [DBMS: MySQL] [Technique: UNION] [Requests: 142]       │
 * │ Progress: ████████░░░ 73%                               [Stop] │
 * ├──────────────┬───────────────────────────────────────────────────┤
 * │  DB Tree     │  Data Table                                      │
 * │  ├─ mydb     │  ┌────────┬──────────┬──────────┐               │
 * │  │  ├─ users │  │ id     │ username │ password │               │
 * │  │  └─ posts │  ├────────┼──────────┼──────────┤               │
 * │  └─ testdb   │  │ 1      │ admin    │ hash...  │               │
 * ├──────────────┴───────────────────────────────────────────────────┤
 * │ Tabs: [Request Log] [Findings]                                  │
 * │  #  │ Technique │ Payload          │ Status │ Time │ Notes      │
 * ├──────────────────────────────────────────────────────────────────┤
 * │ [Copy Table] [Export CSV] [Clear]                               │
 * └──────────────────────────────────────────────────────────────────┘
 */
public class OmniMapPanel extends JPanel {

    private final OmniMapModule module;
    private final FindingsStore findingsStore;
    private final MontoyaApi api;

    // Status bar
    private final JLabel priorityBanner;
    private final JLabel dbmsLabel;
    private final JLabel techniqueLabel;
    private final JLabel requestCountLabel;
    private final JProgressBar progressBar;
    private final JLabel statusLabel;
    private final JButton stopButton;
    private final JLabel livePayloadLabel;
    private final JTabbedPane bottomTabs;

    // DB tree
    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final JTree dbTree;

    // Data table (for dumped rows)
    private final DefaultTableModel dataTableModel;
    private final JTable dataTable;

    // Request log
    private final DefaultTableModel requestLogModel;
    private final JTable requestLogTable;
    private int requestLogCount = 0;
    private final List<HttpRequest> requestLogEntries = new ArrayList<>();

    // Findings table
    private final DefaultTableModel findingsModel;
    private final JTable findingsTable;
    private final List<Finding> findingsList = new ArrayList<>();
    private int lastKnownFindingsCount = 0;

    // Auto-refresh timer
    private final javax.swing.Timer autoRefreshTimer;

    // Track tree nodes for incremental updates
    private final Map<String, DefaultMutableTreeNode> dbNodes = new LinkedHashMap<>();
    private final Map<String, DefaultMutableTreeNode> tableNodes = new LinkedHashMap<>();

    // Per-table data storage so switching tables in the tree shows the right data
    private final Map<String, List<String>> storedColumns = new LinkedHashMap<>();
    private final Map<String, List<Map<String, String>>> storedRows = new LinkedHashMap<>();
    private String currentTableKey = null;

    // Reusable date formatter
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    public OmniMapPanel(OmniMapModule module, FindingsStore findingsStore, MontoyaApi api) {
        this.module = module;
        this.findingsStore = findingsStore;
        this.api = api;

        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        // ============ TOP: Priority Banner + Status Bar ============
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setBackground(BG_DARK);

        // Priority notification banner (visible only during exploitation)
        priorityBanner = new JLabel("  \u26A1 OmniMap is running — other OmniStrike scans are paused for priority  ");
        priorityBanner.setOpaque(true);
        priorityBanner.setBackground(new Color(0xFF, 0x88, 0x00, 40));
        priorityBanner.setForeground(NEON_ORANGE);
        priorityBanner.setFont(MONO_BOLD.deriveFont(12f));
        priorityBanner.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowLineBorder(NEON_ORANGE, 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)));
        priorityBanner.setAlignmentX(Component.LEFT_ALIGNMENT);
        priorityBanner.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        priorityBanner.setVisible(false);
        topPanel.add(priorityBanner);

        // Status row
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        statusRow.setBackground(BG_DARK);
        statusRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel title = new JLabel("OmniMap");
        title.setForeground(NEON_CYAN);
        title.setFont(MONO_BOLD.deriveFont(14f));
        statusRow.add(title);

        JLabel variantLabel = new JLabel("(sqlmap variant)");
        variantLabel.setForeground(FG_DIM);
        variantLabel.setFont(MONO_SMALL);
        statusRow.add(variantLabel);

        statusRow.add(Box.createHorizontalStrut(10));

        dbmsLabel = createBadge("DBMS: —", NEON_BLUE);
        statusRow.add(dbmsLabel);

        techniqueLabel = createBadge("Technique: —", NEON_GREEN);
        statusRow.add(techniqueLabel);

        requestCountLabel = createBadge("Requests: 0", NEON_MAGENTA);
        statusRow.add(requestCountLabel);

        topPanel.add(statusRow);

        // Progress row
        JPanel progressRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        progressRow.setBackground(BG_DARK);
        progressRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        statusLabel = new JLabel("Ready — right-click a request and select 'Send to OmniMap'");
        statusLabel.setForeground(FG_SECONDARY);
        statusLabel.setFont(MONO_SMALL);
        progressRow.add(statusLabel);

        progressBar = new JProgressBar(0, 100);
        styleProgressBar(progressBar);
        progressBar.setPreferredSize(new Dimension(200, 16));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressRow.add(progressBar);

        stopButton = new JButton("Stop");
        styleButton(stopButton, NEON_RED);
        stopButton.setVisible(false);
        stopButton.addActionListener(e -> {
            module.stopExploit();
            statusLabel.setText("Exploitation stopped by user");
            stopButton.setVisible(false);
            progressBar.setVisible(false);
            priorityBanner.setVisible(false);
        });
        progressRow.add(stopButton);

        topPanel.add(progressRow);

        // Live payload display — always visible, shows the last payload fired
        JPanel liveRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        liveRow.setBackground(BG_DARK);
        liveRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel liveLabel = new JLabel("LIVE:");
        liveLabel.setForeground(NEON_RED);
        liveLabel.setFont(MONO_BOLD.deriveFont(11f));
        liveRow.add(liveLabel);
        livePayloadLabel = new JLabel("Waiting for payloads...");
        livePayloadLabel.setForeground(NEON_ORANGE);
        livePayloadLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        livePayloadLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        liveRow.add(livePayloadLabel);
        topPanel.add(liveRow);

        topPanel.setBorder(new CyberTheme.GlowMatteBorder(0, 0, 1, 0, BORDER));
        add(topPanel, BorderLayout.NORTH);

        // ============ CENTER: DB Tree + Data Table ============
        // Left: Database tree
        rootNode = new DefaultMutableTreeNode("Databases");
        treeModel = new DefaultTreeModel(rootNode);
        dbTree = new JTree(treeModel);
        dbTree.setBackground(BG_PANEL);
        dbTree.setForeground(FG_PRIMARY);
        dbTree.setFont(MONO_FONT);
        dbTree.setRootVisible(true);
        dbTree.setShowsRootHandles(true);

        // Custom tree renderer for neon styling
        DefaultTreeCellRenderer treeCellRenderer = new DefaultTreeCellRenderer();
        treeCellRenderer.setBackgroundNonSelectionColor(BG_PANEL);
        treeCellRenderer.setBackgroundSelectionColor(BG_HOVER);
        treeCellRenderer.setTextNonSelectionColor(FG_PRIMARY);
        treeCellRenderer.setTextSelectionColor(NEON_CYAN);
        treeCellRenderer.setFont(MONO_FONT);
        treeCellRenderer.setBorderSelectionColor(NEON_CYAN);
        dbTree.setCellRenderer(treeCellRenderer);

        JScrollPane treeScroll = new JScrollPane(dbTree);
        styleScrollPane(treeScroll);
        treeScroll.setPreferredSize(new Dimension(200, 300));

        // Right: Data table — cell selection enabled for copy-paste
        dataTableModel = new DefaultTableModel() {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        dataTable = new JTable(dataTableModel);
        dataTable.setAutoCreateRowSorter(true);
        dataTable.setCellSelectionEnabled(true);
        dataTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        styleTable(dataTable);

        // Ctrl+C copies selected cells
        dataTable.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copySelectedCells();
            }
        });
        dataTable.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke("ctrl C"), "copy");

        // Right-click context menu for copy
        JPopupMenu dataPopup = new JPopupMenu();
        JMenuItem copyCell = new JMenuItem("Copy Selected");
        copyCell.addActionListener(e -> copySelectedCells());
        dataPopup.add(copyCell);
        JMenuItem copyAllRows = new JMenuItem("Copy All Rows");
        copyAllRows.addActionListener(e -> copyTableToClipboard());
        dataPopup.add(copyAllRows);
        dataTable.setComponentPopupMenu(dataPopup);

        JScrollPane dataScroll = new JScrollPane(dataTable);
        styleScrollPane(dataScroll);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, dataScroll);
        centerSplit.setDividerLocation(220);
        styleSplitPane(centerSplit);

        // ============ BOTTOM: Tabbed pane with Request Log + Findings ============
        bottomTabs = new JTabbedPane();
        styleTabbedPane(bottomTabs);

        // Request log table
        String[] reqLogCols = {"#", "Technique", "Payload", "Status", "Time (ms)", "Notes"};
        requestLogModel = new DefaultTableModel(reqLogCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        requestLogTable = new JTable(requestLogModel);
        requestLogTable.setAutoCreateRowSorter(true);
        styleTable(requestLogTable);
        requestLogTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        requestLogTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        requestLogTable.getColumnModel().getColumn(2).setPreferredWidth(400);
        requestLogTable.getColumnModel().getColumn(3).setPreferredWidth(50);
        requestLogTable.getColumnModel().getColumn(4).setPreferredWidth(60);

        // Right-click context menu: Send to Repeater
        JPopupMenu reqLogPopup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int[] selectedRows = requestLogTable.getSelectedRows();
            for (int viewRow : selectedRows) {
                int modelRow = requestLogTable.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < requestLogEntries.size()) {
                    HttpRequest req = requestLogEntries.get(modelRow);
                    if (req != null) {
                        api.repeater().sendToRepeater(req, "OmniMap #" + (modelRow + 1));
                    }
                }
            }
        });
        reqLogPopup.add(sendToRepeater);
        requestLogTable.setComponentPopupMenu(reqLogPopup);

        JScrollPane reqLogScroll = new JScrollPane(requestLogTable);
        styleScrollPane(reqLogScroll);
        bottomTabs.addTab("Request Log", reqLogScroll);

        // Findings table
        String[] findingCols = {"Severity", "Title", "URL", "Parameter", "Time"};
        findingsModel = new DefaultTableModel(findingCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setAutoCreateRowSorter(true);
        styleTable(findingsTable);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(CyberTheme.createSeverityRenderer());

        JScrollPane findingsScroll = new JScrollPane(findingsTable);
        styleScrollPane(findingsScroll);
        bottomTabs.addTab("Findings", findingsScroll);

        // Main vertical split: center + bottom
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, centerSplit, bottomTabs);
        mainSplit.setDividerLocation(350);
        mainSplit.setResizeWeight(0.5);
        styleSplitPane(mainSplit);
        add(mainSplit, BorderLayout.CENTER);

        // ============ FOOTER: Action buttons ============
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        footer.setBackground(BG_DARK);
        footer.setBorder(new CyberTheme.GlowMatteBorder(1, 0, 0, 0, BORDER));

        JButton copyBtn = new JButton("Copy Table");
        styleButton(copyBtn, NEON_CYAN);
        copyBtn.addActionListener(e -> copyTableToClipboard());
        footer.add(copyBtn);

        JButton exportBtn = new JButton("Export CSV");
        styleButton(exportBtn, NEON_CYAN);
        exportBtn.addActionListener(e -> exportCsv());
        footer.add(exportBtn);

        JButton clearBtn = new JButton("Clear");
        styleButton(clearBtn, NEON_RED);
        clearBtn.addActionListener(e -> clearAll());
        footer.add(clearBtn);

        add(footer, BorderLayout.SOUTH);

        // Auto-refresh for findings
        autoRefreshTimer = new javax.swing.Timer(3000, e -> refreshFindings());
        autoRefreshTimer.start();

        // Tree selection → load data table
        dbTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) dbTree.getLastSelectedPathComponent();
            if (node == null) return;
            // If a table node is selected, show its dumped data
            loadDataForNode(node);
        });
    }

    // ==================== Engine Callbacks (called from background thread) ====================

    public void updateProgress(String status, int percent) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
            if (percent >= 0) {
                progressBar.setValue(percent);
                progressBar.setVisible(true);
                stopButton.setVisible(true);
                priorityBanner.setVisible(true);
            }
            if (percent >= 100) {
                progressBar.setVisible(false);
                stopButton.setVisible(false);
                priorityBanner.setVisible(false);
            }
        });
    }

    public void setDbms(String dbms) {
        SwingUtilities.invokeLater(() -> dbmsLabel.setText("DBMS: " + dbms));
    }

    public void setTechnique(String technique) {
        SwingUtilities.invokeLater(() -> techniqueLabel.setText("Technique: " + technique));
    }

    public void addDatabases(List<String> databases) {
        SwingUtilities.invokeLater(() -> {
            for (String db : databases) {
                if (!dbNodes.containsKey(db)) {
                    DefaultMutableTreeNode node = new DefaultMutableTreeNode(db);
                    dbNodes.put(db, node);
                    rootNode.add(node);
                }
            }
            treeModel.reload();
            expandAllNodes(dbTree);
        });
    }

    public void addTables(String database, List<String> tables) {
        SwingUtilities.invokeLater(() -> {
            DefaultMutableTreeNode dbNode = dbNodes.get(database);
            if (dbNode == null) {
                dbNode = new DefaultMutableTreeNode(database);
                dbNodes.put(database, dbNode);
                rootNode.add(dbNode);
            }
            for (String table : tables) {
                String key = database + "." + table;
                if (!tableNodes.containsKey(key)) {
                    DefaultMutableTreeNode tableNode = new DefaultMutableTreeNode(table);
                    tableNodes.put(key, tableNode);
                    dbNode.add(tableNode);
                }
            }
            treeModel.reload();
            expandAllNodes(dbTree);
        });
    }

    public void addColumns(String database, String table, List<String> columns) {
        SwingUtilities.invokeLater(() -> {
            String key = database + "." + table;
            DefaultMutableTreeNode tableNode = tableNodes.get(key);
            if (tableNode == null) return;
            for (String col : columns) {
                tableNode.add(new DefaultMutableTreeNode(col));
            }
            treeModel.reload();
            expandAllNodes(dbTree);

            // Store columns per table
            storedColumns.put(key, new ArrayList<>(columns));
            if (!storedRows.containsKey(key)) {
                storedRows.put(key, new ArrayList<>());
            }

            // Show this table's data in the data table
            currentTableKey = key;
            refreshDataTable(key);
        });
    }

    public void addRow(String database, String table, Map<String, String> row) {
        SwingUtilities.invokeLater(() -> {
            String key = database + "." + table;

            // Store row data per table
            storedRows.computeIfAbsent(key, k -> new ArrayList<>()).add(row);

            // Ensure columns are stored
            if (!storedColumns.containsKey(key)) {
                storedColumns.put(key, new ArrayList<>(row.keySet()));
            }

            // Only append to the visible data table if this table is currently displayed
            if (key.equals(currentTableKey)) {
                // Ensure columns exist in model
                if (dataTableModel.getColumnCount() == 0) {
                    List<String> cols = storedColumns.get(key);
                    if (cols != null) {
                        for (String col : cols) dataTableModel.addColumn(col);
                    }
                }
                Object[] rowData = new Object[dataTableModel.getColumnCount()];
                for (int c = 0; c < dataTableModel.getColumnCount(); c++) {
                    String colName = dataTableModel.getColumnName(c);
                    rowData[c] = row.getOrDefault(colName, "");
                }
                dataTableModel.addRow(rowData);
            }
        });
    }

    public void addRequestLog(HttpRequestResponse reqResp, String payload, String technique, long responseTimeMs) {
        // Copy the request immediately (Burp's stream may close later)
        final HttpRequest reqCopy = reqResp.request();
        final int status = reqResp.response() != null ? reqResp.response().statusCode() : 0;
        SwingUtilities.invokeLater(() -> {
            requestLogCount++;
            requestLogEntries.add(reqCopy);

            requestLogModel.addRow(new Object[]{
                    requestLogCount,
                    technique,
                    truncate(payload, 120),
                    status,
                    responseTimeMs + " ms",
                    ""
            });

            requestCountLabel.setText("Requests: " + requestLogCount);

            // Update live payload ticker
            livePayloadLabel.setText("[#" + requestLogCount + " " + technique + "] " + truncate(payload, 90)
                    + "  (" + responseTimeMs + "ms → " + status + ")");

            // Auto-select Request Log tab on first payload
            if (requestLogCount == 1) {
                bottomTabs.setSelectedIndex(0);
            }

            // Auto-scroll to latest
            int lastRow = requestLogTable.getRowCount() - 1;
            if (lastRow >= 0) {
                requestLogTable.scrollRectToVisible(requestLogTable.getCellRect(lastRow, 0, true));
            }
        });
    }

    public void onComplete(OmniMapResult result) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Complete! " + result.getRequestCount() + " requests in " +
                    (result.getElapsedMs() / 1000) + "s — " + result.getDbms() + " via " + result.getTechnique());
            statusLabel.setForeground(NEON_GREEN);
            progressBar.setValue(100);
            progressBar.setVisible(false);
            stopButton.setVisible(false);
            priorityBanner.setVisible(false);
            techniqueLabel.setText("Technique: " + result.getTechnique());
            livePayloadLabel.setText("Done — " + result.getRequestCount() + " requests in " +
                    (result.getElapsedMs() / 1000) + "s");
            livePayloadLabel.setForeground(NEON_GREEN);
        });
    }

    public void onError(String message) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Error: " + message);
            statusLabel.setForeground(NEON_RED);
            progressBar.setVisible(false);
            stopButton.setVisible(false);
            priorityBanner.setVisible(false);
            livePayloadLabel.setText("Error: " + message);
            livePayloadLabel.setForeground(NEON_RED);
        });
    }

    // ==================== UI Helpers ====================

    private void loadDataForNode(DefaultMutableTreeNode node) {
        if (node == null || node == rootNode) return;

        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
        if (parent == null) return;

        // Database node (direct child of root) — show summary
        if (parent == rootNode) {
            String db = node.getUserObject().toString();
            statusLabel.setText("Database: " + db + " (" + node.getChildCount() + " tables)");
            return;
        }

        // Table node (child of a DB node) — load its dumped data
        if (parent.getParent() == rootNode) {
            String db = parent.getUserObject().toString();
            String table = node.getUserObject().toString();
            String key = db + "." + table;
            currentTableKey = key;
            refreshDataTable(key);
            List<Map<String, String>> rows = storedRows.get(key);
            int rowCount = rows != null ? rows.size() : 0;
            statusLabel.setText("Table: " + key + " (" + rowCount + " rows)");
            return;
        }

        // Column node (child of a table node) — keep current table view, show column info
        if (parent.getParent() != null && parent.getParent().getParent() == rootNode) {
            String col = node.getUserObject().toString();
            statusLabel.setText("Column: " + col);
        }
    }

    /**
     * Refresh the data table to show stored data for the given table key.
     */
    private void refreshDataTable(String tableKey) {
        dataTableModel.setRowCount(0);
        dataTableModel.setColumnCount(0);

        List<String> cols = storedColumns.get(tableKey);
        if (cols == null || cols.isEmpty()) return;

        for (String col : cols) {
            dataTableModel.addColumn(col);
        }

        List<Map<String, String>> rows = storedRows.get(tableKey);
        if (rows == null) return;

        for (Map<String, String> row : rows) {
            Object[] rowData = new Object[cols.size()];
            for (int c = 0; c < cols.size(); c++) {
                rowData[c] = row.getOrDefault(cols.get(c), "");
            }
            dataTableModel.addRow(rowData);
        }
    }

    private void refreshFindings() {
        SwingUtilities.invokeLater(() -> {
            List<Finding> current = findingsStore.getFindingsByModule("omnimap-exploiter");
            if (current.size() != lastKnownFindingsCount) {
                lastKnownFindingsCount = current.size();
                findingsModel.setRowCount(0);
                findingsList.clear();
                for (Finding f : current) {
                    findingsList.add(f);
                    findingsModel.addRow(new Object[]{
                            f.getSeverity() != null ? f.getSeverity().name() : "",
                            f.getTitle() != null ? f.getTitle() : "",
                            f.getUrl() != null ? f.getUrl() : "",
                            f.getParameter() != null ? f.getParameter() : "",
                            timeFormat.format(new Date(f.getTimestamp()))
                    });
                }
            }
        });
    }

    private void copySelectedCells() {
        int[] rows = dataTable.getSelectedRows();
        int[] cols = dataTable.getSelectedColumns();
        if (rows.length == 0 || cols.length == 0) return;

        StringBuilder sb = new StringBuilder();
        for (int r : rows) {
            for (int i = 0; i < cols.length; i++) {
                if (i > 0) sb.append("\t");
                Object val = dataTable.getValueAt(r, cols[i]);
                sb.append(val != null ? val.toString() : "");
            }
            sb.append("\n");
        }
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
    }

    private void copyTableToClipboard() {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < dataTableModel.getColumnCount(); c++) {
            if (c > 0) sb.append("\t");
            sb.append(dataTableModel.getColumnName(c));
        }
        sb.append("\n");
        for (int r = 0; r < dataTableModel.getRowCount(); r++) {
            for (int c = 0; c < dataTableModel.getColumnCount(); c++) {
                if (c > 0) sb.append("\t");
                Object val = dataTableModel.getValueAt(r, c);
                sb.append(val != null ? val.toString() : "");
            }
            sb.append("\n");
        }
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("omnimap_dump.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                // Header
                for (int c = 0; c < dataTableModel.getColumnCount(); c++) {
                    if (c > 0) pw.print(",");
                    pw.print(escapeCsv(dataTableModel.getColumnName(c)));
                }
                pw.println();
                // Data
                for (int r = 0; r < dataTableModel.getRowCount(); r++) {
                    for (int c = 0; c < dataTableModel.getColumnCount(); c++) {
                        if (c > 0) pw.print(",");
                        Object val = dataTableModel.getValueAt(r, c);
                        pw.print(escapeCsv(val != null ? val.toString() : ""));
                    }
                    pw.println();
                }
                JOptionPane.showMessageDialog(this, "Exported to " + fc.getSelectedFile().getName());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
            }
        }
    }

    private void clearAll() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Clear all OmniMap data? This cannot be undone.",
                "Confirm Clear", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            rootNode.removeAllChildren();
            dbNodes.clear();
            tableNodes.clear();
            storedColumns.clear();
            storedRows.clear();
            currentTableKey = null;
            treeModel.reload();
            dataTableModel.setRowCount(0);
            dataTableModel.setColumnCount(0);
            requestLogModel.setRowCount(0);
            requestLogCount = 0;
            requestLogEntries.clear();
            requestCountLabel.setText("Requests: 0");
            dbmsLabel.setText("DBMS: —");
            techniqueLabel.setText("Technique: —");
            statusLabel.setText("Cleared");
            statusLabel.setForeground(FG_SECONDARY);
            livePayloadLabel.setText("Waiting for payloads...");
            livePayloadLabel.setForeground(NEON_ORANGE);
            findingsStore.clearModule("omnimap-exploiter");
        }
    }

    private JLabel createBadge(String text, Color neon) {
        return CyberTheme.createSeverityBadge(text, neon);
    }

    private void expandAllNodes(JTree tree) {
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private String escapeCsv(String value) {
        if (value == null) return "\"\"";
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    public void stopTimers() {
        if (autoRefreshTimer != null) autoRefreshTimer.stop();
    }
}
