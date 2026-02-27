package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;
import com.omnistrike.model.WebSocketConnection;
import com.omnistrike.model.WebSocketMessage;
import com.omnistrike.modules.websocket.WebSocketConnectionTracker;
import com.omnistrike.modules.websocket.WebSocketFuzzer;
import com.omnistrike.modules.websocket.WebSocketScanner;
import com.omnistrike.ui.CyberTheme;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Custom UI panel for the WebSocket Scanner module.
 * Shows intercepted WebSocket connections, their messages, and active scan controls.
 */
public class WebSocketScannerPanel extends JPanel {

    private final WebSocketScanner scanner;
    private final FindingsStore findingsStore;
    private final CollaboratorManager collaboratorManager;
    private final MontoyaApi api;

    // UI Components
    private final JComboBox<ConnectionItem> connectionCombo;
    private final JButton scanButton;
    private final JButton stopButton;
    private final DefaultTableModel messageTableModel;
    private final JTable messageTable;
    private final JTextArea messageDetailArea;
    private final JProgressBar progressBar;
    private final JLabel statusLabel;
    private final JLabel findingsCountLabel;
    private final JLabel collabIndicator;

    // Filter buttons
    private final JToggleButton filterAll;
    private final JToggleButton filterClientToServer;
    private final JToggleButton filterServerToClient;
    private final JTextField searchField;

    // Findings sub-table
    private final DefaultTableModel findingsTableModel;
    private final JTable findingsTable;
    private final JTextArea findingsDetailArea;
    private final List<Finding> findingsList = new ArrayList<>();

    // Message list (parallel to table model for index-based lookup)
    private final List<WebSocketMessage> displayedMessages = new ArrayList<>();

    // Timers
    private final Timer refreshTimer;
    private final Timer scanStatusTimer;

    // State
    private String selectedConnectionId = null;
    private int lastMessageCount = 0;
    private int lastFindingsCount = 0;
    private String activeFilter = "ALL";
    private String searchText = "";

    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    private static final String[] MESSAGE_COLUMNS = {"#", "Direction", "Preview", "Timestamp"};
    private static final String[] FINDINGS_COLUMNS = {"Severity", "Confidence", "Title", "Evidence"};

    /**
     * Wraps a WebSocketConnection for display in the JComboBox.
     */
    private static class ConnectionItem {
        final WebSocketConnection connection;

        ConnectionItem(WebSocketConnection connection) {
            this.connection = connection;
        }

        @Override
        public String toString() {
            return connection.getDisplayLabel();
        }
    }

    public WebSocketScannerPanel(WebSocketScanner scanner, FindingsStore findingsStore,
                                  CollaboratorManager collaboratorManager, MontoyaApi api) {
        this.scanner = scanner;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
        this.api = api;

        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        // ============ NORTH: Controls ============
        JPanel northPanel = new JPanel();
        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));
        northPanel.setBackground(BG_DARK);

        // Row 1: Connection selector + Scan/Stop buttons
        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlRow.setBackground(BG_DARK);

        JLabel connLabel = new JLabel("Connection:");
        connLabel.setForeground(NEON_CYAN);
        connLabel.setFont(MONO_LABEL);
        controlRow.add(connLabel);

        connectionCombo = new JComboBox<>();
        connectionCombo.setPreferredSize(new Dimension(450, 26));
        CyberTheme.styleComboBox(connectionCombo);
        connectionCombo.addActionListener(e -> onConnectionSelected());
        controlRow.add(connectionCombo);

        scanButton = new JButton("Scan");
        CyberTheme.styleFilledButton(scanButton, NEON_GREEN);
        scanButton.setToolTipText("Start active fuzzing on the selected WebSocket connection");
        scanButton.addActionListener(e -> startScan());
        controlRow.add(scanButton);

        stopButton = new JButton("Stop");
        CyberTheme.styleFilledButton(stopButton, NEON_RED);
        stopButton.setEnabled(false);
        stopButton.setToolTipText("Stop the current active scan");
        stopButton.addActionListener(e -> stopScan());
        controlRow.add(stopButton);

        // Collaborator status indicator
        boolean collabAvail = collaboratorManager != null && collaboratorManager.isAvailable();
        collabIndicator = new JLabel(collabAvail ? " OOB: Ready" : " OOB: N/A");
        collabIndicator.setForeground(collabAvail ? NEON_GREEN : NEON_RED);
        collabIndicator.setFont(MONO_SMALL);
        controlRow.add(collabIndicator);

        northPanel.add(controlRow);

        // Row 2: Filters and search
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterRow.setBackground(BG_DARK);

        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setForeground(FG_SECONDARY);
        filterLabel.setFont(MONO_SMALL);
        filterRow.add(filterLabel);

        ButtonGroup filterGroup = new ButtonGroup();

        filterAll = new JToggleButton("All", true);
        styleToggle(filterAll);
        filterAll.addActionListener(e -> { activeFilter = "ALL"; refreshMessages(); });
        filterGroup.add(filterAll);
        filterRow.add(filterAll);

        filterClientToServer = new JToggleButton("Client > Server");
        styleToggle(filterClientToServer);
        filterClientToServer.addActionListener(e -> { activeFilter = "C2S"; refreshMessages(); });
        filterGroup.add(filterClientToServer);
        filterRow.add(filterClientToServer);

        filterServerToClient = new JToggleButton("Server > Client");
        styleToggle(filterServerToClient);
        filterServerToClient.addActionListener(e -> { activeFilter = "S2C"; refreshMessages(); });
        filterGroup.add(filterServerToClient);
        filterRow.add(filterServerToClient);

        JLabel searchLabel = new JLabel("  Search:");
        searchLabel.setForeground(FG_SECONDARY);
        searchLabel.setFont(MONO_SMALL);
        filterRow.add(searchLabel);

        searchField = new JTextField(20);
        CyberTheme.styleTextField(searchField);
        searchField.setToolTipText("Filter messages by content (case-insensitive)");
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { onSearchChanged(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { onSearchChanged(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { onSearchChanged(); }
        });
        filterRow.add(searchField);

        northPanel.add(filterRow);
        add(northPanel, BorderLayout.NORTH);

        // ============ CENTER: Message table + detail ============
        // Main vertical split: top (messages) / bottom (findings)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        CyberTheme.styleSplitPane(mainSplit);
        mainSplit.setResizeWeight(0.6);

        // Messages area: table left, detail right
        messageTableModel = new DefaultTableModel(MESSAGE_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        messageTable = new JTable(messageTableModel);
        messageTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        CyberTheme.styleTable(messageTable);
        messageTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        messageTable.getColumnModel().getColumn(0).setMaxWidth(60);
        messageTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        messageTable.getColumnModel().getColumn(1).setMaxWidth(130);
        messageTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        messageTable.getColumnModel().getColumn(3).setMaxWidth(120);

        messageDetailArea = new JTextArea();
        messageDetailArea.setEditable(false);
        CyberTheme.styleTextArea(messageDetailArea);
        messageDetailArea.setLineWrap(true);
        messageDetailArea.setWrapStyleWord(true);

        messageTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = messageTable.getSelectedRow();
                if (row >= 0 && row < displayedMessages.size()) {
                    WebSocketMessage msg = displayedMessages.get(row);
                    if (msg.isText() && msg.getPayload() != null) {
                        messageDetailArea.setText(msg.getPayload());
                    } else if (msg.getBinary() != null) {
                        messageDetailArea.setText("[Binary data: " + msg.getBinary().length + " bytes]");
                    } else {
                        messageDetailArea.setText("[empty]");
                    }
                    messageDetailArea.setCaretPosition(0);
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(messageTable);
        CyberTheme.styleScrollPane(tableScroll);
        JScrollPane detailScroll = new JScrollPane(messageDetailArea);
        CyberTheme.styleScrollPane(detailScroll);

        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detailScroll);
        messageSplit.setDividerLocation(500);
        CyberTheme.styleSplitPane(messageSplit);

        mainSplit.setTopComponent(messageSplit);

        // ============ Findings sub-panel ============
        JPanel findingsPanel = new JPanel(new BorderLayout());
        findingsPanel.setBackground(BG_DARK);

        JLabel findingsHeader = new JLabel("  Findings for Selected Connection");
        findingsHeader.setForeground(NEON_MAGENTA);
        findingsHeader.setFont(MONO_BOLD.deriveFont(12f));
        findingsPanel.add(findingsHeader, BorderLayout.NORTH);

        findingsTableModel = new DefaultTableModel(FINDINGS_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        findingsTable = new JTable(findingsTableModel);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        CyberTheme.styleTable(findingsTable);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(0).setMaxWidth(100);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(CyberTheme.createSeverityRenderer());
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(100);

        findingsDetailArea = new JTextArea(4, 40);
        findingsDetailArea.setEditable(false);
        CyberTheme.styleTextArea(findingsDetailArea);
        findingsDetailArea.setLineWrap(true);

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsTable.getSelectedRow();
                if (row >= 0 && row < findingsList.size()) {
                    Finding f = findingsList.get(row);
                    StringBuilder sb = new StringBuilder();
                    sb.append("Evidence:\n").append(f.getEvidence() != null ? f.getEvidence() : "(none)");
                    sb.append("\n\nDescription:\n").append(f.getDescription() != null ? f.getDescription() : "(none)");
                    sb.append("\n\nRemediation:\n").append(f.getRemediation() != null ? f.getRemediation() : "(none)");
                    findingsDetailArea.setText(sb.toString());
                    findingsDetailArea.setCaretPosition(0);
                }
            }
        });

        JScrollPane findingsTableScroll = new JScrollPane(findingsTable);
        CyberTheme.styleScrollPane(findingsTableScroll);
        JScrollPane findingsDetailScroll = new JScrollPane(findingsDetailArea);
        CyberTheme.styleScrollPane(findingsDetailScroll);

        JSplitPane findingsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, findingsTableScroll, findingsDetailScroll);
        findingsSplit.setDividerLocation(150);
        CyberTheme.styleSplitPane(findingsSplit);

        findingsPanel.add(findingsSplit, BorderLayout.CENTER);
        mainSplit.setBottomComponent(findingsPanel);
        mainSplit.setDividerLocation(350);

        add(mainSplit, BorderLayout.CENTER);

        // ============ SOUTH: Status bar ============
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 3));
        statusBar.setBackground(BG_DARK);
        statusBar.setBorder(new CyberTheme.GlowMatteBorder(1, 0, 0, 0, BORDER));

        progressBar = new JProgressBar();
        CyberTheme.styleProgressBar(progressBar);
        progressBar.setPreferredSize(new Dimension(150, 16));
        progressBar.setVisible(false);
        statusBar.add(progressBar);

        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(FG_SECONDARY);
        statusLabel.setFont(MONO_SMALL);
        statusBar.add(statusLabel);

        findingsCountLabel = new JLabel("Findings: 0");
        findingsCountLabel.setForeground(NEON_MAGENTA);
        findingsCountLabel.setFont(MONO_BOLD.deriveFont(11f));
        statusBar.add(findingsCountLabel);

        add(statusBar, BorderLayout.SOUTH);

        // ============ Timers ============
        // Refresh connections and messages every 2 seconds
        refreshTimer = new Timer(2000, e -> refreshUI());
        refreshTimer.start();

        // Update scan status every 500ms during active scan
        scanStatusTimer = new Timer(500, e -> updateScanStatus());
        scanStatusTimer.start();

        // Listen for new connections to auto-update dropdown
        scanner.getConnectionTracker().addConnectionListener(conn ->
                SwingUtilities.invokeLater(this::refreshConnectionDropdown));
    }

    // ==================== Actions ====================

    private void onConnectionSelected() {
        ConnectionItem item = (ConnectionItem) connectionCombo.getSelectedItem();
        if (item != null) {
            selectedConnectionId = item.connection.getId();
            lastMessageCount = 0; // Force refresh
            refreshMessages();
            refreshFindings();
        } else {
            selectedConnectionId = null;
        }
    }

    private void onSearchChanged() {
        searchText = searchField.getText().trim().toLowerCase();
        refreshMessages();
    }

    private void startScan() {
        ConnectionItem item = (ConnectionItem) connectionCombo.getSelectedItem();
        if (item == null) {
            JOptionPane.showMessageDialog(this, "Select a WebSocket connection first.",
                    "No Connection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        WebSocketConnection conn = item.connection;
        if (conn.getMessages().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No messages captured for this connection.\n" +
                    "Send some WebSocket messages through the proxy first.",
                    "No Messages", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Count client-to-server text messages (what the fuzzer actually uses as templates)
        long clientTextCount = conn.getMessages().stream()
                .filter(m -> m.getDirection() == WebSocketMessage.Direction.CLIENT_TO_SERVER
                        && m.isText() && m.getPayload() != null && !m.getPayload().isEmpty())
                .count();

        String cswhNote = "\n\nNote: CSWSH (Origin validation) test always runs regardless.";
        if (clientTextCount == 0) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "No client-to-server text messages found for this connection.\n" +
                    "The fuzzer uses these as templates to inject payloads into.\n" +
                    "Only the CSWSH (Cross-Site WebSocket Hijacking) test will run.\n\n" +
                    "To get full coverage, interact with the WebSocket app through your\n" +
                    "browser first (send chat messages, make requests, etc.) so the\n" +
                    "proxy captures client messages, then click Scan again.\n\n" +
                    "Run CSWSH-only scan anyway?",
                    "Limited Scan", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        } else {
            // Show confirmation with scan preview
            boolean collabAvail = collaboratorManager != null && collaboratorManager.isAvailable();
            String oobNote = collabAvail
                    ? "OOB (Collaborator): Available — OOB-first strategy active"
                    : "OOB (Collaborator): Unavailable — in-band detection only";
            JOptionPane.showMessageDialog(this,
                    "Starting active scan on: " + truncate(conn.getUpgradeUrl(), 60) + "\n\n" +
                    "Client messages to fuzz: " + clientTextCount + "\n" +
                    oobNote + "\n\n" +
                    "Tests: CSWSH, SQLi, CmdI, SSRF, SSTI, XSS, IDOR, AuthZ Bypass\n" +
                    "Payloads are sent DIRECTLY to the target (not through Burp proxy).\n" +
                    "Results will appear in the Findings table below.",
                    "WebSocket Scan Starting", JOptionPane.INFORMATION_MESSAGE);
        }

        scanButton.setEnabled(false);
        stopButton.setEnabled(true);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        statusLabel.setText("Scanning...");
        statusLabel.setForeground(NEON_GREEN);

        scanner.getFuzzer().startScan(conn);
    }

    private void stopScan() {
        scanner.getFuzzer().stopScan();
        scanButton.setEnabled(true);
        stopButton.setEnabled(false);
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        statusLabel.setText("Scan stopped");
        statusLabel.setForeground(NEON_ORANGE);
    }

    // ==================== Refresh Methods ====================

    private void refreshUI() {
        SwingUtilities.invokeLater(() -> {
            refreshConnectionDropdown();
            if (selectedConnectionId != null) {
                WebSocketConnection conn = scanner.getConnectionTracker().getConnection(selectedConnectionId);
                if (conn != null && conn.getMessageCount() != lastMessageCount) {
                    refreshMessages();
                }
                int currentFindings = findingsStore.getCountByModule("ws-scanner");
                if (currentFindings != lastFindingsCount) {
                    refreshFindings();
                    lastFindingsCount = currentFindings;
                }
            }
            findingsCountLabel.setText("Findings: " + findingsStore.getCountByModule("ws-scanner"));
        });
    }

    private void refreshConnectionDropdown() {
        List<WebSocketConnection> connections = scanner.getConnectionTracker().getAllConnections();
        int currentCount = connections.size();

        // Only rebuild if connection count changed
        if (currentCount != connectionCombo.getItemCount()) {
            ConnectionItem selected = (ConnectionItem) connectionCombo.getSelectedItem();
            String selectedId = selected != null ? selected.connection.getId() : null;

            connectionCombo.removeAllItems();
            ConnectionItem reselect = null;
            for (WebSocketConnection conn : connections) {
                ConnectionItem item = new ConnectionItem(conn);
                connectionCombo.addItem(item);
                if (conn.getId().equals(selectedId)) {
                    reselect = item;
                }
            }

            if (reselect != null) {
                connectionCombo.setSelectedItem(reselect);
            } else if (connectionCombo.getItemCount() > 0) {
                connectionCombo.setSelectedIndex(connectionCombo.getItemCount() - 1);
            }
        }
    }

    private void refreshMessages() {
        if (selectedConnectionId == null) return;

        WebSocketConnection conn = scanner.getConnectionTracker().getConnection(selectedConnectionId);
        if (conn == null) return;

        List<WebSocketMessage> allMessages = conn.getMessages();
        lastMessageCount = allMessages.size();

        messageTableModel.setRowCount(0);
        displayedMessages.clear();

        int index = 1;
        for (WebSocketMessage msg : allMessages) {
            // Apply direction filter
            if ("C2S".equals(activeFilter) && msg.getDirection() != WebSocketMessage.Direction.CLIENT_TO_SERVER) continue;
            if ("S2C".equals(activeFilter) && msg.getDirection() != WebSocketMessage.Direction.SERVER_TO_CLIENT) continue;

            // Apply search filter
            if (!searchText.isEmpty()) {
                String preview = msg.getPreview().toLowerCase();
                if (!preview.contains(searchText)) continue;
            }

            displayedMessages.add(msg);
            String direction = msg.getDirection() == WebSocketMessage.Direction.CLIENT_TO_SERVER
                    ? ">> Client" : "<< Server";
            messageTableModel.addRow(new Object[]{
                    index++,
                    direction,
                    msg.getPreview(),
                    timeFormat.format(new Date(msg.getTimestamp()))
            });
        }
    }

    private void refreshFindings() {
        findingsTableModel.setRowCount(0);
        findingsList.clear();

        List<Finding> allFindings = findingsStore.getFindingsByModule("ws-scanner");

        // Filter to findings for the selected connection URL
        WebSocketConnection conn = selectedConnectionId != null
                ? scanner.getConnectionTracker().getConnection(selectedConnectionId)
                : null;

        for (Finding f : allFindings) {
            if (conn != null && f.getUrl() != null
                    && !f.getUrl().isEmpty()
                    && !f.getUrl().equals(conn.getUpgradeUrl())) {
                continue; // Skip findings for other connections
            }
            findingsList.add(f);
            findingsTableModel.addRow(new Object[]{
                    f.getSeverity() != null ? f.getSeverity().name() : "",
                    f.getConfidence() != null ? f.getConfidence().name() : "",
                    f.getTitle() != null ? f.getTitle() : "",
                    f.getEvidence() != null ? truncate(f.getEvidence(), 100) : ""
            });
        }
    }

    private void updateScanStatus() {
        WebSocketFuzzer fuzzer = scanner.getFuzzer();
        if (fuzzer.isScanning()) {
            statusLabel.setText(fuzzer.getScanStatus()
                    + " | Payloads: " + fuzzer.getPayloadsSent()
                    + " | Findings: " + fuzzer.getFindingsCount());
            statusLabel.setForeground(NEON_GREEN);
            if (!progressBar.isVisible()) {
                progressBar.setIndeterminate(true);
                progressBar.setVisible(true);
            }
        } else if (scanButton != null && !scanButton.isEnabled()) {
            // Scan just finished
            scanButton.setEnabled(true);
            stopButton.setEnabled(false);
            progressBar.setIndeterminate(false);
            progressBar.setVisible(false);
            statusLabel.setText(fuzzer.getScanStatus());
            statusLabel.setForeground(FG_SECONDARY);
            refreshFindings();

            // Show completion dialog so the user knows the scan finished
            int payloads = fuzzer.getPayloadsSent();
            int findings = fuzzer.getFindingsCount();
            String title = findings > 0 ? "Scan Complete — Vulnerabilities Found!" : "Scan Complete";
            int msgType = findings > 0 ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE;
            JOptionPane.showMessageDialog(this,
                    "WebSocket scan finished.\n\n" +
                    "Payloads sent: " + payloads + "\n" +
                    "Findings: " + findings + "\n\n" +
                    (findings > 0
                            ? "Check the Findings table below for details."
                            : (payloads == 0
                                    ? "No payloads were sent. Check the Burp extension output\n" +
                                      "log for error details (Extensions > Output tab)."
                                    : "No vulnerabilities detected.")),
                    title, msgType);
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /**
     * Styles a JToggleButton to match the CyberTheme aesthetic.
     */
    private static void styleToggle(JToggleButton btn) {
        btn.setBackground(BG_PANEL);
        btn.setForeground(NEON_CYAN);
        btn.setFont(MONO_SMALL);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowLineBorder(NEON_CYAN, 1),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
    }

    /**
     * Stops all timers. Call from extension unload handler.
     */
    public void stopTimers() {
        if (refreshTimer != null) refreshTimer.stop();
        if (scanStatusTimer != null) scanStatusTimer.stop();
    }
}
