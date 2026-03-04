package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.modules.injection.BypassUrlParser;
import com.omnistrike.modules.injection.BypassUrlParser.BypassResult;
import com.omnistrike.ui.CyberTheme;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
// Explicitly use javax.swing.Timer (not java.util.Timer)

/**
 * Custom UI panel for the Bypass URL Parser module.
 *
 * Layout:
 *   Top:    Target URL input + Run/Stop + status
 *   Left:   Mode selection checkboxes (13 modes) + config (threads, timeout)
 *   Center: Results table (status, method, content-length, words, lines, mode, description, payload)
 *   Bottom: Detail area (full request/response) + log output
 */
public class BypassUrlParserPanel extends JPanel {

    private final BypassUrlParser module;
    private final FindingsStore findingsStore;
    private final MontoyaApi api;

    // UI components
    private final JTextField urlField;
    private final JButton runBtn;
    private final JButton stopBtn;
    private final JButton exportBtn;
    private final JButton clearBtn;
    private final JLabel statusLabel;
    private final JLabel progressLabel;
    private final JLabel baselineLabel;
    private final JProgressBar progressBar;
    private final JTextField threadsField;
    private final JTextField timeoutField;

    // Mode checkboxes
    private final Map<String, JCheckBox> modeCheckboxes = new LinkedHashMap<>();

    // Results table
    private final DefaultTableModel tableModel;
    private final JTable resultsTable;
    private final List<BypassResult> displayedResults = new ArrayList<>();

    // Detail area
    private final JTextArea detailArea;
    private final JTextArea logArea;

    // Auto-refresh timer
    private final javax.swing.Timer refreshTimer;

    // Track last refresh count to avoid unnecessary rebuilds
    private int lastResultCount = 0;

    private static final String[] COLUMNS = {
            "Status", "Class", "Method", "Length", "Words", "Lines", "Mode", "Description", "Payload"
    };

    /** Mode display names (order matches BypassUrlParser.ALL_MODES) */
    private static final String[][] MODE_INFO = {
            {BypassUrlParser.MODE_MID_PATHS, "Mid Paths", "Insert path tricks between URL segments"},
            {BypassUrlParser.MODE_END_PATHS, "End Paths", "Append suffixes to the path"},
            {BypassUrlParser.MODE_CASE_SUBSTITUTION, "Case Substitution", "Uppercase/lowercase variations"},
            {BypassUrlParser.MODE_CHAR_ENCODE, "Char Encode", "URL-encode chars (single/double/triple/unicode)"},
            {BypassUrlParser.MODE_HTTP_METHODS, "HTTP Methods", "Try alternate HTTP verbs"},
            {BypassUrlParser.MODE_HTTP_VERSIONS, "HTTP Versions", "Try HTTP/0.9, 1.0, 1.1"},
            {BypassUrlParser.MODE_HEADERS_METHOD, "Headers: Method", "Method override (X-HTTP-Method-Override)"},
            {BypassUrlParser.MODE_HEADERS_SCHEME, "Headers: Scheme", "Scheme spoofing (X-Forwarded-Proto)"},
            {BypassUrlParser.MODE_HEADERS_IP, "Headers: IP", "IP spoofing (X-Forwarded-For, X-Real-IP, ...)"},
            {BypassUrlParser.MODE_HEADERS_PORT, "Headers: Port", "Port spoofing (X-Forwarded-Port)"},
            {BypassUrlParser.MODE_HEADERS_URL, "Headers: URL", "URL rewrite (X-Original-URL, X-Rewrite-URL)"},
            {BypassUrlParser.MODE_USER_AGENT, "User Agent", "Rotate User-Agent strings (bots, crawlers)"},
            {BypassUrlParser.MODE_COMBINED_HEADERS, "Combined Headers", "Multi-header combos (IP+Method+Scheme)"},
    };

    public BypassUrlParserPanel(BypassUrlParser module, FindingsStore findingsStore, MontoyaApi api) {
        this.module = module;
        this.findingsStore = findingsStore;
        this.api = api;

        setLayout(new BorderLayout(5, 5));
        setBackground(BG_DARK);

        // ═══════ TOP: Target URL + Controls ═══════
        JPanel topPanel = new JPanel(new BorderLayout(5, 3));
        topPanel.setBackground(BG_DARK);
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Row 1: URL + Run/Stop
        JPanel urlRow = new JPanel(new BorderLayout(5, 0));
        urlRow.setBackground(BG_DARK);

        JLabel urlLabel = new JLabel("Target URL:");
        urlLabel.setForeground(NEON_CYAN);
        urlLabel.setFont(MONO_BOLD);
        urlRow.add(urlLabel, BorderLayout.WEST);

        urlField = new JTextField();
        styleTextField(urlField);
        urlField.setFont(MONO_FONT);
        urlField.putClientProperty("JTextField.placeholderText",
                "http://target.com/admin (enter URL returning 403/401)");
        urlField.setToolTipText("Enter the URL that returns 403 or 401 — the tool will try to bypass it");
        urlRow.add(urlField, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        btnRow.setBackground(BG_DARK);

        runBtn = new JButton("Run Scan");
        CyberTheme.styleButton(runBtn, NEON_GREEN);
        runBtn.setToolTipText("Generate and send all bypass payloads");
        runBtn.addActionListener(e -> startScan());
        btnRow.add(runBtn);

        stopBtn = new JButton("Stop");
        CyberTheme.styleButton(stopBtn, NEON_RED);
        stopBtn.setEnabled(false);
        stopBtn.setToolTipText("Stop the current scan");
        stopBtn.addActionListener(e -> stopScan());
        btnRow.add(stopBtn);

        exportBtn = new JButton("Export JSON");
        CyberTheme.styleButton(exportBtn, NEON_CYAN);
        exportBtn.setToolTipText("Export all results to a JSON file");
        exportBtn.addActionListener(e -> exportResults());
        btnRow.add(exportBtn);

        clearBtn = new JButton("Clear");
        CyberTheme.styleButton(clearBtn, NEON_ORANGE);
        clearBtn.setToolTipText("Clear all results");
        clearBtn.addActionListener(e -> clearResults());
        btnRow.add(clearBtn);

        urlRow.add(btnRow, BorderLayout.EAST);
        topPanel.add(urlRow, BorderLayout.NORTH);

        // Row 2: Status + Progress
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusRow.setBackground(BG_DARK);

        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(FG_SECONDARY);
        statusLabel.setFont(MONO_BOLD);
        statusRow.add(statusLabel);

        baselineLabel = new JLabel("");
        baselineLabel.setForeground(FG_DIM);
        baselineLabel.setFont(MONO_SMALL);
        statusRow.add(baselineLabel);

        progressLabel = new JLabel("");
        progressLabel.setForeground(FG_SECONDARY);
        progressLabel.setFont(MONO_SMALL);
        statusRow.add(progressLabel);

        progressBar = new JProgressBar(0, 100);
        styleProgressBar(progressBar);
        progressBar.setPreferredSize(new Dimension(200, 16));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        statusRow.add(progressBar);

        topPanel.add(statusRow, BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // ═══════ LEFT: Mode Selection + Config ═══════
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setBackground(BG_PANEL);
        leftPanel.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowMatteBorder(0, 0, 0, 1, BORDER),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        leftPanel.setPreferredSize(new Dimension(240, 0));

        // Title
        JLabel modesTitle = new JLabel("Bypass Modes");
        modesTitle.setForeground(NEON_CYAN);
        modesTitle.setFont(MONO_BOLD.deriveFont(13f));
        modesTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftPanel.add(modesTitle);
        leftPanel.add(Box.createVerticalStrut(5));

        // Select All / Deselect All
        JPanel selBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        selBtns.setBackground(BG_PANEL);
        selBtns.setAlignmentX(Component.LEFT_ALIGNMENT);
        selBtns.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));

        JButton selectAll = new JButton("All");
        CyberTheme.styleButton(selectAll, NEON_GREEN);
        selectAll.setFont(MONO_SMALL);
        selectAll.addActionListener(e -> modeCheckboxes.values().forEach(cb -> cb.setSelected(true)));
        selBtns.add(selectAll);

        JButton deselectAll = new JButton("None");
        CyberTheme.styleButton(deselectAll, NEON_ORANGE);
        deselectAll.setFont(MONO_SMALL);
        deselectAll.addActionListener(e -> modeCheckboxes.values().forEach(cb -> cb.setSelected(false)));
        selBtns.add(deselectAll);

        JButton quickPreset = new JButton("Quick");
        CyberTheme.styleButton(quickPreset, NEON_BLUE);
        quickPreset.setFont(MONO_SMALL);
        quickPreset.setToolTipText("Select fast modes only (headers, methods, user-agent)");
        quickPreset.addActionListener(e -> applyQuickPreset());
        selBtns.add(quickPreset);

        leftPanel.add(selBtns);
        leftPanel.add(Box.createVerticalStrut(5));

        // Mode checkboxes
        for (String[] info : MODE_INFO) {
            JCheckBox cb = new JCheckBox(info[1]);
            styleCheckBox(cb);
            cb.setSelected(true); // All modes enabled by default
            cb.setToolTipText(info[2]);
            cb.setAlignmentX(Component.LEFT_ALIGNMENT);
            modeCheckboxes.put(info[0], cb);
            leftPanel.add(cb);
        }

        leftPanel.add(Box.createVerticalStrut(15));

        // Config section
        JLabel configTitle = new JLabel("Configuration");
        configTitle.setForeground(NEON_CYAN);
        configTitle.setFont(MONO_BOLD.deriveFont(13f));
        configTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftPanel.add(configTitle);
        leftPanel.add(Box.createVerticalStrut(5));

        // Threads
        JPanel threadRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        threadRow.setBackground(BG_PANEL);
        threadRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        threadRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JLabel threadLabel = new JLabel("Threads:");
        threadLabel.setForeground(FG_PRIMARY);
        threadLabel.setFont(MONO_SMALL);
        threadRow.add(threadLabel);
        threadsField = new JTextField("10", 4);
        styleTextField(threadsField);
        threadsField.setToolTipText("Concurrent request threads (1-50)");
        threadRow.add(threadsField);
        leftPanel.add(threadRow);

        // Timeout
        JPanel timeoutRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        timeoutRow.setBackground(BG_PANEL);
        timeoutRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        timeoutRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JLabel timeoutLabel = new JLabel("Timeout (s):");
        timeoutLabel.setForeground(FG_PRIMARY);
        timeoutLabel.setFont(MONO_SMALL);
        timeoutRow.add(timeoutLabel);
        timeoutField = new JTextField("10", 4);
        styleTextField(timeoutField);
        timeoutField.setToolTipText("Per-request timeout in seconds");
        timeoutRow.add(timeoutField);
        leftPanel.add(timeoutRow);

        leftPanel.add(Box.createVerticalGlue());

        JScrollPane leftScroll = new JScrollPane(leftPanel);
        leftScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        CyberTheme.styleScrollPane(leftScroll);
        leftScroll.setPreferredSize(new Dimension(240, 0));

        // ═══════ CENTER: Results Table ═══════
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        CyberTheme.styleTable(resultsTable);

        // Custom renderer for Status and Classification columns
        resultsTable.getColumnModel().getColumn(0).setCellRenderer(new StatusCellRenderer());
        resultsTable.getColumnModel().getColumn(1).setCellRenderer(new ClassificationCellRenderer());

        // Set preferred column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // Status
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(70);  // Class
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(55);  // Method
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Length
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(50);  // Words
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(45);  // Lines
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(100); // Mode
        resultsTable.getColumnModel().getColumn(7).setPreferredWidth(200); // Description
        resultsTable.getColumnModel().getColumn(8).setPreferredWidth(300); // Payload

        // Context menu
        setupTableContextMenu();

        // Row selection → detail area
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetail();
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        CyberTheme.styleScrollPane(tableScroll);

        // ═══════ BOTTOM: Detail + Log ═══════
        JTabbedPane bottomTabs = new JTabbedPane();
        styleTabbedPane(bottomTabs);

        detailArea = new JTextArea(8, 80);
        detailArea.setEditable(false);
        CyberTheme.styleTextArea(detailArea);
        detailArea.setLineWrap(false);
        JScrollPane detailScroll = new JScrollPane(detailArea);
        CyberTheme.styleScrollPane(detailScroll);
        bottomTabs.addTab("Request/Response", detailScroll);

        logArea = new JTextArea(6, 80);
        logArea.setEditable(false);
        CyberTheme.styleTextArea(logArea);
        logArea.setLineWrap(true);
        JScrollPane logScroll = new JScrollPane(logArea);
        CyberTheme.styleScrollPane(logScroll);
        bottomTabs.addTab("Scan Log", logScroll);

        // ═══════ ASSEMBLY ═══════
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomTabs);
        rightSplit.setDividerLocation(300);
        rightSplit.setResizeWeight(0.6);
        CyberTheme.styleSplitPane(rightSplit);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightSplit);
        mainSplit.setDividerLocation(240);
        CyberTheme.styleSplitPane(mainSplit);

        add(mainSplit, BorderLayout.CENTER);

        // Auto-refresh timer (1 second interval during scans, checks for new results)
        refreshTimer = new javax.swing.Timer(1000, e -> autoRefresh());
        refreshTimer.start();
    }

    // ═══════════════════════════════════════════════════════════════
    //  ACTIONS
    // ═══════════════════════════════════════════════════════════════

    private void startScan() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter a target URL first.",
                    "Bypass URL Parser", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Collect selected modes
        Set<String> selectedModes = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : modeCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedModes.add(entry.getKey());
            }
        }
        if (selectedModes.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Select at least one bypass mode.",
                    "Bypass URL Parser", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int threads;
        try {
            threads = Integer.parseInt(threadsField.getText().trim());
            threads = Math.max(1, Math.min(50, threads));
        } catch (NumberFormatException e) {
            threads = 10;
        }

        int timeout;
        try {
            timeout = Integer.parseInt(timeoutField.getText().trim());
            timeout = Math.max(1, Math.min(120, timeout));
        } catch (NumberFormatException e) {
            timeout = 10;
        }

        // Clear previous results
        clearResults();

        // Update UI state
        runBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        statusLabel.setText("Scanning...");
        statusLabel.setForeground(NEON_GREEN);
        progressBar.setVisible(true);
        progressBar.setValue(0);

        module.runBypassScan(url, selectedModes, threads, timeout);
    }

    private void stopScan() {
        module.stopScan();
        statusLabel.setText("Stopping...");
        statusLabel.setForeground(NEON_ORANGE);
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        displayedResults.clear();
        lastResultCount = 0;
        detailArea.setText("");
        logArea.setText("");
        baselineLabel.setText("");
        progressLabel.setText("");
        progressBar.setValue(0);
        progressBar.setVisible(false);
    }

    private void exportResults() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("bypass-url-parser-results.json"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            String path = module.exportResultsToFile(fc.getSelectedFile().getAbsolutePath());
            if (path != null) {
                JOptionPane.showMessageDialog(this, "Results exported to:\n" + path,
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Export failed.",
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /** Apply "Quick" preset — header-only modes that are fast */
    private void applyQuickPreset() {
        Set<String> quickModes = Set.of(
                BypassUrlParser.MODE_HEADERS_METHOD, BypassUrlParser.MODE_HEADERS_SCHEME,
                BypassUrlParser.MODE_HEADERS_IP, BypassUrlParser.MODE_HEADERS_PORT,
                BypassUrlParser.MODE_HEADERS_URL, BypassUrlParser.MODE_USER_AGENT,
                BypassUrlParser.MODE_HTTP_METHODS
        );
        for (Map.Entry<String, JCheckBox> entry : modeCheckboxes.entrySet()) {
            entry.getValue().setSelected(quickModes.contains(entry.getKey()));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  PUBLIC METHODS (called from module)
    // ═══════════════════════════════════════════════════════════════

    /** Set the target URL (called from context menu) */
    public void setTargetUrl(String url) {
        urlField.setText(url != null ? url : "");
    }

    /** Set baseline info display */
    public void setBaselineInfo(int statusCode, int contentLength) {
        baselineLabel.setText("Baseline: HTTP " + statusCode + " | " + contentLength + " bytes");
        if (statusCode >= 400) {
            baselineLabel.setForeground(NEON_ORANGE);
        } else {
            baselineLabel.setForeground(NEON_GREEN);
        }
    }

    /** Append a log message */
    public void appendLog(String message) {
        logArea.append("[" + java.time.LocalTime.now().toString().substring(0, 8) + "] " + message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    /** Refresh the results table and status from the module */
    public void refresh() {
        boolean isRunning = module.isRunning();
        int completed = module.getCompletedCount();
        int total = module.getTotalCount();
        int bypasses = module.getBypassCount();

        // Update progress
        if (total > 0) {
            int pct = (int) ((completed * 100.0) / total);
            progressBar.setValue(pct);
            progressBar.setString(pct + "%");
            progressLabel.setText(completed + "/" + total + " requests | " + bypasses + " bypasses");
        }

        // Update status when scan completes
        if (!isRunning && runBtn != null && !runBtn.isEnabled()) {
            runBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            if (completed > 0 && completed >= total) {
                statusLabel.setText("Complete (" + bypasses + " bypasses)");
                statusLabel.setForeground(bypasses > 0 ? NEON_GREEN : FG_SECONDARY);
            } else if (completed > 0) {
                statusLabel.setText("Stopped (" + completed + "/" + total + ")");
                statusLabel.setForeground(NEON_ORANGE);
            } else {
                statusLabel.setText("Ready");
                statusLabel.setForeground(FG_SECONDARY);
            }
        }

        // Refresh table only if new results arrived
        List<BypassResult> currentResults = module.getResults();
        if (currentResults.size() != lastResultCount) {
            rebuildTable(currentResults);
            lastResultCount = currentResults.size();
        }
    }

    /** Stop the auto-refresh timer (called on extension unload) */
    public void stopTimers() {
        if (refreshTimer != null) refreshTimer.stop();
    }

    // ═══════════════════════════════════════════════════════════════
    //  TABLE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════

    private void rebuildTable(List<BypassResult> results) {
        int selectedRow = resultsTable.getSelectedRow();
        tableModel.setRowCount(0);
        displayedResults.clear();

        // Sort: BYPASS first, then POTENTIAL, then DIFFERENT, then SAME, then ERROR
        List<BypassResult> sorted = new ArrayList<>(results);
        sorted.sort((a, b) -> {
            int oa = classOrder(a.classification);
            int ob = classOrder(b.classification);
            if (oa != ob) return oa - ob;
            return Integer.compare(a.statusCode, b.statusCode);
        });

        for (BypassResult r : sorted) {
            displayedResults.add(r);
            tableModel.addRow(new Object[]{
                    r.statusCode,
                    r.classification,
                    r.method,
                    r.contentLength,
                    r.wordCount,
                    r.lineCount,
                    r.mode,
                    r.description,
                    r.payloadUrl
            });
        }

        // Restore selection if possible
        if (selectedRow >= 0 && selectedRow < tableModel.getRowCount()) {
            resultsTable.setRowSelectionInterval(selectedRow, selectedRow);
        }
    }

    private static int classOrder(String classification) {
        return switch (classification) {
            case "BYPASS" -> 0;
            case "POTENTIAL" -> 1;
            case "DIFFERENT" -> 2;
            case "ERROR" -> 3;
            case "SAME" -> 4;
            default -> 5;
        };
    }

    private void showDetail() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = resultsTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= displayedResults.size()) return;

        BypassResult r = displayedResults.get(modelRow);
        StringBuilder sb = new StringBuilder();
        sb.append("=== BYPASS RESULT ===\n");
        sb.append("Classification: ").append(r.classification).append("\n");
        sb.append("Mode: ").append(r.mode).append("\n");
        sb.append("Description: ").append(r.description).append("\n");
        sb.append("Payload URL: ").append(r.payloadUrl).append("\n");
        sb.append("Method: ").append(r.method).append("\n");
        sb.append("Status: ").append(r.statusCode).append("\n");
        sb.append("Content-Length: ").append(r.contentLength).append("\n");
        sb.append("Content-Type: ").append(r.contentType).append("\n");
        sb.append("Words: ").append(r.wordCount).append(" | Lines: ").append(r.lineCount).append("\n");
        if (r.extraHeaders != null && !r.extraHeaders.isEmpty()) {
            sb.append("Extra Headers: ").append(r.extraHeaders).append("\n");
        }

        if (r.requestResponse != null) {
            sb.append("\n").append("=".repeat(80)).append("\n");
            sb.append("REQUEST:\n").append("=".repeat(80)).append("\n");
            try {
                var req = r.requestResponse.request();
                if (req != null) {
                    var headers = req.headers();
                    if (!headers.isEmpty()) {
                        sb.append(headers.get(0).toString()).append("\n");
                        for (int i = 1; i < headers.size(); i++) {
                            sb.append(headers.get(i).name()).append(": ")
                                    .append(headers.get(i).value()).append("\n");
                        }
                    }
                    sb.append("\n");
                    String body = req.bodyToString();
                    if (body != null && !body.isEmpty()) sb.append(body);
                }
            } catch (Exception e) {
                sb.append("[Error reading request]\n");
            }

            sb.append("\n\n").append("=".repeat(80)).append("\n");
            sb.append("RESPONSE:\n").append("=".repeat(80)).append("\n");
            try {
                var resp = r.requestResponse.response();
                if (resp != null) {
                    var headers = resp.headers();
                    if (!headers.isEmpty()) {
                        sb.append(headers.get(0).toString()).append("\n");
                        for (int i = 1; i < headers.size(); i++) {
                            sb.append(headers.get(i).name()).append(": ")
                                    .append(headers.get(i).value()).append("\n");
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
                }
            } catch (Exception e) {
                sb.append("[Error reading response]\n");
            }
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    /** Context menu for the results table */
    private void setupTableContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            BypassResult r = getSelectedResult();
            if (r == null || r.requestResponse == null || r.requestResponse.request() == null) return;
            if (api != null) {
                api.repeater().sendToRepeater(r.requestResponse.request(),
                        "BUP: " + r.mode + " " + r.statusCode);
            }
        });
        popup.add(sendToRepeater);

        JMenuItem copyUrl = new JMenuItem("Copy Payload URL");
        copyUrl.addActionListener(e -> {
            BypassResult r = getSelectedResult();
            if (r != null && r.payloadUrl != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(r.payloadUrl), null);
            }
        });
        popup.add(copyUrl);

        JMenuItem copyCurl = new JMenuItem("Copy as curl");
        copyCurl.addActionListener(e -> {
            BypassResult r = getSelectedResult();
            if (r == null || r.requestResponse == null || r.requestResponse.request() == null) return;
            String curl = buildCurlCommand(r);
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(curl), null);
        });
        popup.add(copyCurl);

        resultsTable.setComponentPopupMenu(popup);
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = resultsTable.rowAtPoint(e.getPoint());
                    if (row >= 0) resultsTable.setRowSelectionInterval(row, row);
                }
            }
        });
    }

    private BypassResult getSelectedResult() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = resultsTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= displayedResults.size()) return null;
        return displayedResults.get(modelRow);
    }

    /** Build a curl command string from a bypass result */
    private String buildCurlCommand(BypassResult r) {
        StringBuilder cmd = new StringBuilder("curl -v --path-as-is");
        if (!"GET".equals(r.method)) {
            cmd.append(" -X ").append(r.method);
        }
        // Extract headers from the request
        if (r.requestResponse != null && r.requestResponse.request() != null) {
            var headers = r.requestResponse.request().headers();
            for (int i = 1; i < headers.size(); i++) { // skip request line
                String name = headers.get(i).name();
                String value = headers.get(i).value();
                if (!"Host".equalsIgnoreCase(name) && !"Connection".equalsIgnoreCase(name)
                        && !"Accept".equalsIgnoreCase(name)) {
                    cmd.append(" -H '").append(name).append(": ").append(value).append("'");
                }
            }
        }
        cmd.append(" '").append(r.payloadUrl).append("'");
        return cmd.toString();
    }

    private void autoRefresh() {
        if (module.isRunning()) {
            refresh();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  CELL RENDERERS
    // ═══════════════════════════════════════════════════════════════

    /** Color-codes HTTP status codes */
    private static class StatusCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (CyberTheme.isNativeMode()) return c;
            if (!isSelected && value instanceof Integer status) {
                c.setBackground(BG_DARK);
                if (status >= 200 && status < 300) {
                    c.setForeground(NEON_GREEN);
                } else if (status >= 300 && status < 400) {
                    c.setForeground(NEON_BLUE);
                } else if (status >= 400 && status < 500) {
                    c.setForeground(NEON_ORANGE);
                } else if (status >= 500) {
                    c.setForeground(NEON_RED);
                } else {
                    c.setForeground(FG_DIM);
                }
                setFont(MONO_BOLD);
            }
            setHorizontalAlignment(CENTER);
            return c;
        }
    }

    /** Color-codes bypass classification */
    private static class ClassificationCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (CyberTheme.isNativeMode()) return c;
            if (!isSelected && value instanceof String cls) {
                c.setBackground(BG_DARK);
                switch (cls) {
                    case "BYPASS" -> { c.setForeground(NEON_GREEN); setFont(MONO_BOLD); }
                    case "POTENTIAL" -> { c.setForeground(NEON_CYAN); setFont(MONO_BOLD); }
                    case "DIFFERENT" -> { c.setForeground(NEON_ORANGE); setFont(MONO_FONT); }
                    case "ERROR" -> { c.setForeground(NEON_RED); setFont(MONO_FONT); }
                    default -> { c.setForeground(FG_DIM); setFont(MONO_FONT); }
                }
            }
            setHorizontalAlignment(CENTER);
            return c;
        }
    }
}
