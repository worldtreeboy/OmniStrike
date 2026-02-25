package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.ModuleRegistry;
import com.omnistrike.framework.ScopeManager;
import com.omnistrike.model.Finding;
import com.omnistrike.modules.ai.AiVulnAnalyzer;
import com.omnistrike.modules.ai.llm.AiConnectionMode;
import com.omnistrike.modules.ai.llm.ApiKeyProvider;
import com.omnistrike.modules.ai.llm.LlmProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Custom Swing panel for the AI Vulnerability Analyzer module.
 * Supports three connection modes via radio buttons (mutually exclusive):
 *   - Off: AI analysis disabled
 *   - CLI Tool: Local CLI providers (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI)
 *   - API Key: Direct HTTP API (Anthropic, OpenAI, Google Gemini)
 */
public class AiModulePanel extends JPanel {

    private final AiVulnAnalyzer analyzer;
    private final FindingsStore findingsStore;
    private final ModuleRegistry registry;
    private final MontoyaApi api;
    private final ScopeManager scopeManager;

    // Connection mode radio buttons
    private JRadioButton offRadio;
    private JRadioButton cliRadio;
    private JRadioButton apiKeyRadio;

    // CardLayout for switching between mode panels
    private JPanel modeCards;
    private CardLayout modeCardLayout;

    // CLI mode fields
    private JComboBox<LlmProvider> cliProviderCombo;
    private JTextField cliBinaryField;
    private JButton cliTestBtn;
    private JLabel cliTestStatusLabel;

    // API Key mode fields
    private JComboBox<ApiKeyProvider> apiProviderCombo;
    private JComboBox<String> apiModelCombo;
    private JPasswordField apiKeyField;
    private JButton apiKeyTestBtn;
    private JLabel apiKeyTestStatusLabel;

    // Settings
    private JTextField maxPayloadsField;

    // Batch scan UI
    private DefaultTableModel batchTableModel;
    private JTable batchTable;
    private JButton runBatchBtn;
    private JButton clearBatchBtn;
    private JLabel batchCountLabel;
    private JLabel batchStatusLabel;
    private int lastBatchQueueSize = 0;

    // Stats & scan control
    private final JLabel statsLabel;
    private JButton cancelScansBtn;

    // Findings table
    private final DefaultTableModel tableModel;
    private final JTable findingsTable;
    private final JTextArea detailArea;
    private final List<Finding> findingsList = new ArrayList<>();

    // Timer
    private final Timer refreshTimer;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    private int lastKnownCount = 0;

    private static final String[] COLUMNS = {
            "Severity", "Confidence", "Title", "URL", "Parameter", "Time"
    };

    // Colors
    private static final Color BANNER_BG = new Color(255, 248, 225);
    private static final Color BANNER_BORDER = new Color(255, 193, 7);
    private static final Color BANNER_TEXT = new Color(102, 77, 3);
    private static final Color ACCENT = new Color(59, 130, 246);
    private static final Color SUCCESS = new Color(34, 139, 34);
    private static final Color ERROR_COLOR = new Color(220, 53, 69);
    private static final Color MUTED = new Color(108, 117, 125);

    // Mode card names
    private static final String CARD_OFF = "off";
    private static final String CARD_CLI = "cli";
    private static final String CARD_API_KEY = "apikey";

    public AiModulePanel(AiVulnAnalyzer analyzer, FindingsStore findingsStore,
                         ModuleRegistry registry, MontoyaApi api, ScopeManager scopeManager) {
        this.analyzer = analyzer;
        this.findingsStore = findingsStore;
        this.registry = registry;
        this.api = api;
        this.scopeManager = scopeManager;
        setLayout(new BorderLayout());

        // ============ TOP: Notice + Mode Selector + Config + Toggles ============
        JPanel topSection = new JPanel();
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));

        // --- Notice Banner ---
        topSection.add(createNoticeBanner());
        topSection.add(Box.createVerticalStrut(8));

        // --- Connection Mode Selector ---
        JPanel modeSelector = createModeSelector();
        topSection.add(modeSelector);
        topSection.add(Box.createVerticalStrut(6));

        // --- Mode-specific config cards ---
        modeCardLayout = new CardLayout();
        modeCards = new JPanel(modeCardLayout);
        modeCards.setAlignmentX(LEFT_ALIGNMENT);
        modeCards.add(createOffCard(), CARD_OFF);
        modeCards.add(createCliCard(), CARD_CLI);
        modeCards.add(createApiKeyCard(), CARD_API_KEY);
        modeCardLayout.show(modeCards, CARD_OFF);
        topSection.add(modeCards);
        topSection.add(Box.createVerticalStrut(6));

        // --- Max Payloads Setting ---
        JPanel settingsPanel = createSettingsSection();
        topSection.add(settingsPanel);
        topSection.add(Box.createVerticalStrut(6));

        // --- Batch Scan Section ---
        JPanel batchPanel = createBatchScanSection();
        topSection.add(batchPanel);
        topSection.add(Box.createVerticalStrut(6));

        // --- Stats + Cancel Bar ---
        JPanel statsBar = new JPanel(new BorderLayout(8, 0));
        statsBar.setBorder(new EmptyBorder(4, 12, 6, 12));
        statsBar.setAlignmentX(LEFT_ALIGNMENT);
        statsBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));

        statsLabel = new JLabel("Running: 0  |  Queued: 0  |  Analyzed: 0  |  Findings: 0  |  Fuzz Requests: 0  |  Errors: 0");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.PLAIN, 12f));
        statsLabel.setForeground(MUTED);
        statsBar.add(statsLabel, BorderLayout.CENTER);

        cancelScansBtn = createStyledButton("Cancel All Scans", ERROR_COLOR);
        cancelScansBtn.setToolTipText("Stop all running and queued AI scans");
        cancelScansBtn.setVisible(false);
        cancelScansBtn.addActionListener(e -> {
            analyzer.cancelAllScans();
            cancelScansBtn.setVisible(false);
        });
        statsBar.add(cancelScansBtn, BorderLayout.EAST);

        topSection.add(statsBar);

        add(topSection, BorderLayout.NORTH);

        // ============ CENTER: Findings Table + Detail ============
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        findingsTable = new JTable(tableModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.setRowHeight(24);
        findingsTable.setShowGrid(false);
        findingsTable.setIntercellSpacing(new Dimension(0, 0));
        findingsTable.getTableHeader().setReorderingAllowed(false);

        setupTableContextMenu();

        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(280);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(250);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(70);

        detailArea = new JTextArea(8, 80);
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setMargin(new Insets(8, 8, 8, 8));

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedDetail();
        });

        JScrollPane tableScroll = new JScrollPane(findingsTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("AI Findings"));

        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Finding Details"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScroll, detailScroll);
        splitPane.setDividerLocation(280);
        splitPane.setResizeWeight(0.6);

        add(splitPane, BorderLayout.CENTER);

        // ============ BOTTOM: Controls ============
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controls.setBorder(new EmptyBorder(2, 4, 4, 4));

        JButton refreshBtn = createStyledButton("Refresh", null);
        refreshBtn.addActionListener(e -> refreshTable());
        controls.add(refreshBtn);

        JButton exportBtn = createStyledButton("Export CSV", null);
        exportBtn.addActionListener(e -> exportFindings());
        controls.add(exportBtn);

        JButton clearBtn = createStyledButton("Clear Findings", null);
        clearBtn.addActionListener(e -> clearFindings());
        controls.add(clearBtn);

        JButton resetDedupBtn = createStyledButton("Reset Dedup", null);
        resetDedupBtn.setToolTipText("Clear the deduplication cache so endpoints can be re-analyzed");
        resetDedupBtn.addActionListener(e -> {
            analyzer.resetDedup();
            JOptionPane.showMessageDialog(this, "Dedup cache cleared. Endpoints will be re-analyzed.",
                    "Reset", JOptionPane.INFORMATION_MESSAGE);
        });
        controls.add(resetDedupBtn);

        add(controls, BorderLayout.SOUTH);

        // ============ Auto-refresh timer ============
        refreshTimer = new Timer(3000, e -> autoRefresh());
        refreshTimer.start();
    }

    // ==================== Connection Mode Selector ====================

    private JPanel createModeSelector() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Connection Mode"),
                new EmptyBorder(4, 8, 4, 8)));
        outer.setAlignmentX(LEFT_ALIGNMENT);
        outer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 4));
        ButtonGroup group = new ButtonGroup();

        offRadio = new JRadioButton("Off");
        offRadio.setSelected(true);
        offRadio.setToolTipText("AI analysis disabled — no LLM calls");
        group.add(offRadio);
        radioPanel.add(offRadio);

        cliRadio = new JRadioButton("CLI Tool");
        cliRadio.setToolTipText("Use local CLI tools (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI)");
        group.add(cliRadio);
        radioPanel.add(cliRadio);

        apiKeyRadio = new JRadioButton("API Key");
        apiKeyRadio.setToolTipText("Use API keys to call Anthropic, OpenAI, or Google Gemini APIs directly over HTTP");
        group.add(apiKeyRadio);
        radioPanel.add(apiKeyRadio);

        offRadio.addActionListener(e -> switchMode(CARD_OFF));
        cliRadio.addActionListener(e -> switchMode(CARD_CLI));
        apiKeyRadio.addActionListener(e -> switchMode(CARD_API_KEY));

        outer.add(radioPanel, BorderLayout.CENTER);
        return outer;
    }

    private void switchMode(String card) {
        AiConnectionMode mode;
        if (CARD_CLI.equals(card)) {
            mode = AiConnectionMode.CLI;
        } else if (CARD_API_KEY.equals(card)) {
            mode = AiConnectionMode.API_KEY;
        } else {
            mode = AiConnectionMode.NONE;
        }
        analyzer.setConnectionMode(mode);
        modeCardLayout.show(modeCards, card);
    }

    // ==================== Mode Cards ====================

    private JPanel createOffCard() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 16));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        JLabel label = new JLabel("AI analysis is disabled. Select CLI Tool or API Key above to enable it.");
        label.setForeground(MUTED);
        label.setFont(label.getFont().deriveFont(Font.ITALIC, 12f));
        panel.add(label);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        return panel;
    }

    private JPanel createCliCard() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("CLI Tool Configuration"),
                new EmptyBorder(6, 8, 6, 8)));
        outer.setAlignmentX(LEFT_ALIGNMENT);
        outer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 140));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 6, 3, 6);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0: CLI Tool selector
        gbc.gridx = 0; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE;
        form.add(createFieldLabel("CLI Tool:"), gbc);

        LlmProvider[] cliProviders = {LlmProvider.CLI_CLAUDE, LlmProvider.CLI_GEMINI,
                LlmProvider.CLI_CODEX, LlmProvider.CLI_OPENCODE};
        cliProviderCombo = new JComboBox<>(cliProviders);
        cliProviderCombo.setPreferredSize(new Dimension(200, 28));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        form.add(cliProviderCombo, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(createFieldLabel("Binary:"), gbc);

        cliBinaryField = new JTextField(20);
        cliBinaryField.setText("claude");
        cliBinaryField.setToolTipText("Path to CLI binary (or just the name if it's on PATH)");
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        form.add(cliBinaryField, gbc);

        // Row 1: Buttons
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(Box.createHorizontalStrut(1), gbc);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton applyBtn = createStyledButton("Apply Settings", ACCENT);
        applyBtn.addActionListener(e -> applyCliConfig());
        btnPanel.add(applyBtn);

        cliTestBtn = createStyledButton("Test Connection", null);
        cliTestBtn.addActionListener(e -> testCliConnection());
        btnPanel.add(cliTestBtn);

        cliTestStatusLabel = new JLabel("");
        cliTestStatusLabel.setFont(cliTestStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        btnPanel.add(cliTestStatusLabel);

        gbc.gridx = 1; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(btnPanel, gbc);
        gbc.gridwidth = 1;

        outer.add(form, BorderLayout.CENTER);

        cliProviderCombo.addActionListener(e -> {
            LlmProvider sel = (LlmProvider) cliProviderCombo.getSelectedItem();
            if (sel != null) cliBinaryField.setText(sel.getCliCommand());
        });

        return outer;
    }

    private JPanel createApiKeyCard() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("API Key Configuration"),
                new EmptyBorder(6, 8, 6, 8)));
        outer.setAlignmentX(LEFT_ALIGNMENT);
        outer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 170));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 6, 3, 6);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0: Provider + Model
        gbc.gridx = 0; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(createFieldLabel("Provider:"), gbc);

        apiProviderCombo = new JComboBox<>(ApiKeyProvider.values());
        apiProviderCombo.setPreferredSize(new Dimension(180, 28));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.4;
        form.add(apiProviderCombo, gbc);

        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(createFieldLabel("Model:"), gbc);

        apiModelCombo = new JComboBox<>();
        apiModelCombo.setPreferredSize(new Dimension(220, 28));
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.6;
        form.add(apiModelCombo, gbc);

        // Row 1: API Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(createFieldLabel("API Key:"), gbc);

        apiKeyField = new JPasswordField(40);
        apiKeyField.setToolTipText("Paste your API key (stored in memory only, not persisted to disk)");
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        form.add(apiKeyField, gbc);
        gbc.gridwidth = 1;

        // Row 2: Buttons + Status
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(Box.createHorizontalStrut(1), gbc);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton applyBtn = createStyledButton("Apply Settings", ACCENT);
        applyBtn.addActionListener(e -> applyApiKeyConfig());
        btnPanel.add(applyBtn);

        apiKeyTestBtn = createStyledButton("Test Connection", null);
        apiKeyTestBtn.addActionListener(e -> testApiKeyConnection());
        btnPanel.add(apiKeyTestBtn);

        apiKeyTestStatusLabel = new JLabel("");
        apiKeyTestStatusLabel.setFont(apiKeyTestStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        btnPanel.add(apiKeyTestStatusLabel);

        gbc.gridx = 1; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(btnPanel, gbc);
        gbc.gridwidth = 1;

        outer.add(form, BorderLayout.CENTER);

        // Populate model combo when provider changes
        apiProviderCombo.addActionListener(e -> {
            ApiKeyProvider sel = (ApiKeyProvider) apiProviderCombo.getSelectedItem();
            if (sel != null) {
                apiModelCombo.removeAllItems();
                for (String m : sel.getModels()) {
                    apiModelCombo.addItem(m);
                }
            }
        });

        // Initialize model combo for default provider
        ApiKeyProvider defaultProvider = (ApiKeyProvider) apiProviderCombo.getSelectedItem();
        if (defaultProvider != null) {
            for (String m : defaultProvider.getModels()) {
                apiModelCombo.addItem(m);
            }
        }

        return outer;
    }

    // ==================== UI Construction Helpers ====================

    private JPanel createNoticeBanner() {
        JPanel banner = new JPanel(new BorderLayout(10, 0));
        banner.setBackground(BANNER_BG);
        banner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 1, 1, 1, BANNER_BORDER),
                new EmptyBorder(10, 14, 10, 14)));
        banner.setAlignmentX(LEFT_ALIGNMENT);

        JLabel icon = new JLabel("  AI  ");
        icon.setFont(icon.getFont().deriveFont(Font.BOLD, 13f));
        icon.setOpaque(true);
        icon.setBackground(BANNER_BORDER);
        icon.setForeground(Color.WHITE);
        icon.setHorizontalAlignment(SwingConstants.CENTER);
        icon.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));

        JLabel text = new JLabel("AI analysis is completely optional. When enabled, "
                + "HTTP request/response data from in-scope traffic will be sent to the configured LLM provider "
                + "(via CLI tool or API key). Data leaves your machine. "
                + "Smart Fuzzing sends active requests \u2014 use responsibly.");
        text.setFont(text.getFont().deriveFont(Font.PLAIN, 12f));
        text.setForeground(BANNER_TEXT);

        banner.add(icon, BorderLayout.WEST);
        banner.add(text, BorderLayout.CENTER);
        banner.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        return banner;
    }

    private JPanel createSettingsSection() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Settings"),
                new EmptyBorder(4, 8, 4, 8)));
        outer.setAlignmentX(LEFT_ALIGNMENT);
        outer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));

        JPanel limitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel limitLabel = createFieldLabel("Max Payloads:");
        limitPanel.add(limitLabel);

        maxPayloadsField = new JTextField("0", 5);
        maxPayloadsField.setToolTipText("Max payloads per AI request (0 = unlimited — AI decides when to stop)");
        limitPanel.add(maxPayloadsField);

        JLabel limitHint = new JLabel("(0 = unlimited)");
        limitHint.setFont(limitHint.getFont().deriveFont(Font.PLAIN, 11f));
        limitHint.setForeground(MUTED);
        limitPanel.add(limitHint);

        JButton applyLimitBtn = createStyledButton("Apply", null);
        applyLimitBtn.addActionListener(e -> {
            try {
                int val = Integer.parseInt(maxPayloadsField.getText().trim());
                analyzer.setMaxPayloadsPerRequest(val);
                limitHint.setText(val == 0 ? "(0 = unlimited)" : "(limit: " + val + ")");
                limitHint.setForeground(SUCCESS);
            } catch (NumberFormatException ex) {
                limitHint.setText("Invalid number");
                limitHint.setForeground(ERROR_COLOR);
            }
        });
        limitPanel.add(applyLimitBtn);

        JLabel note = new JLabel("  AI capabilities (fuzzing, WAF bypass, adaptive) are selected per-scan via right-click context menu.");
        note.setFont(note.getFont().deriveFont(Font.ITALIC, 11f));
        note.setForeground(MUTED);
        limitPanel.add(note);

        outer.add(limitPanel, BorderLayout.CENTER);
        return outer;
    }

    private JPanel createBatchScanSection() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("AI Batch Scan (Cross-File Analysis)"),
                new EmptyBorder(4, 8, 4, 8)));
        outer.setAlignmentX(LEFT_ALIGNMENT);
        outer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));

        // Queue table
        String[] batchColumns = {"#", "URL", "Content-Type", "Size"};
        batchTableModel = new DefaultTableModel(batchColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        batchTable = new JTable(batchTableModel);
        batchTable.setRowHeight(22);
        batchTable.setShowGrid(false);
        batchTable.setIntercellSpacing(new Dimension(0, 0));
        batchTable.getTableHeader().setReorderingAllowed(false);
        batchTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        batchTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        batchTable.getColumnModel().getColumn(0).setMaxWidth(40);
        batchTable.getColumnModel().getColumn(1).setPreferredWidth(350);
        batchTable.getColumnModel().getColumn(2).setPreferredWidth(130);
        batchTable.getColumnModel().getColumn(3).setPreferredWidth(60);

        // Right-click context menu on batch table
        JPopupMenu batchPopup = new JPopupMenu();
        JMenuItem removeItem = new JMenuItem("Remove from queue");
        removeItem.addActionListener(e -> {
            int row = batchTable.getSelectedRow();
            if (row >= 0) {
                analyzer.removeFromBatchQueue(row);
                refreshBatchTable();
            }
        });
        batchPopup.add(removeItem);
        batchTable.setComponentPopupMenu(batchPopup);

        batchTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = batchTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        batchTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        JScrollPane batchScroll = new JScrollPane(batchTable);
        batchScroll.setPreferredSize(new Dimension(0, 120));

        outer.add(batchScroll, BorderLayout.CENTER);

        // Button bar
        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        runBatchBtn = createStyledButton("Run Batch Scan", ACCENT);
        runBatchBtn.setToolTipText("Send all queued files to AI for cross-file analysis");
        runBatchBtn.setEnabled(false);
        runBatchBtn.addActionListener(e -> runBatchScan());
        btnBar.add(runBatchBtn);

        clearBatchBtn = createStyledButton("Clear Queue", null);
        clearBatchBtn.setEnabled(false);
        clearBatchBtn.addActionListener(e -> {
            analyzer.clearBatchQueue();
            refreshBatchTable();
        });
        btnBar.add(clearBatchBtn);

        JButton scrapeSiteMapBtn = createStyledButton("Scrape Site Map", new Color(100, 60, 180));
        scrapeSiteMapBtn.setToolTipText("Scrape Burp's site map for all in-scope JS/HTML files and add them to the batch queue");
        scrapeSiteMapBtn.addActionListener(e -> scrapeSiteMap());
        btnBar.add(scrapeSiteMapBtn);

        batchCountLabel = new JLabel("Queue empty");
        batchCountLabel.setFont(batchCountLabel.getFont().deriveFont(Font.BOLD, 12f));
        batchCountLabel.setForeground(MUTED);
        btnBar.add(batchCountLabel);

        btnBar.add(Box.createHorizontalStrut(16));

        batchStatusLabel = new JLabel("");
        batchStatusLabel.setFont(batchStatusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        batchStatusLabel.setForeground(MUTED);
        btnBar.add(batchStatusLabel);

        outer.add(btnBar, BorderLayout.SOUTH);

        return outer;
    }

    private void refreshBatchTable() {
        SwingUtilities.invokeLater(() -> {
            batchTableModel.setRowCount(0);
            java.util.List<HttpRequestResponse> queue = analyzer.getBatchQueue();
            for (int i = 0; i < queue.size(); i++) {
                HttpRequestResponse rr = queue.get(i);
                String url = rr.request() != null ? truncateStr(rr.request().url(), 80) : "";
                String ct = "";
                String size = "";
                if (rr.response() != null) {
                    for (var h : rr.response().headers()) {
                        if ("content-type".equalsIgnoreCase(h.name())) {
                            ct = h.value();
                            if (ct.contains(";")) ct = ct.substring(0, ct.indexOf(';')).trim();
                            break;
                        }
                    }
                    String body = rr.response().bodyToString();
                    size = body != null ? formatSize(body.length()) : "?";
                } else {
                    size = "(no response)";
                }
                batchTableModel.addRow(new Object[]{i + 1, url, ct, size});
            }

            int queueSize = queue.size();
            lastBatchQueueSize = queueSize;
            boolean hasItems = queueSize > 0;
            boolean aiReady = analyzer.isAiConfigured();
            boolean scanning = analyzer.isBatchScanRunning();

            runBatchBtn.setEnabled(hasItems && aiReady && !scanning);
            clearBatchBtn.setEnabled(hasItems && !scanning);
            batchCountLabel.setText(hasItems ? queueSize + " file(s) queued" : "Queue empty");
            batchCountLabel.setForeground(hasItems ? new Color(55, 65, 81) : MUTED);

            String status = analyzer.getBatchScanStatus();
            batchStatusLabel.setText(status != null ? status : "");
            if (scanning) {
                batchStatusLabel.setForeground(ACCENT);
            } else if (status != null && status.startsWith("Completed")) {
                batchStatusLabel.setForeground(SUCCESS);
            } else if (status != null && status.startsWith("Error")) {
                batchStatusLabel.setForeground(ERROR_COLOR);
            } else {
                batchStatusLabel.setForeground(MUTED);
            }
        });
    }

    private void runBatchScan() {
        runBatchBtn.setEnabled(false);
        clearBatchBtn.setEnabled(false);
        batchStatusLabel.setText("Starting...");
        batchStatusLabel.setForeground(ACCENT);

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                analyzer.runBatchScan();
                // Wait for batch scan to complete
                while (analyzer.isBatchScanRunning()) {
                    try { Thread.sleep(500); } catch (InterruptedException ignored) { break; }
                }
                return null;
            }

            @Override
            protected void done() {
                refreshBatchTable();
            }
        }.execute();
    }

    private void scrapeSiteMap() {
        if (scopeManager.getTargetDomains().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Set target scope first (top bar) so the extension knows which domains to scrape.",
                    "No Scope Configured", JOptionPane.WARNING_MESSAGE);
            return;
        }

        batchStatusLabel.setText("Scraping site map...");
        batchStatusLabel.setForeground(ACCENT);

        new SwingWorker<int[], Void>() {
            @Override
            protected int[] doInBackground() {
                java.util.LinkedHashMap<String, HttpRequestResponse> matches = new java.util.LinkedHashMap<>();
                int totalScanned = 0;

                try {
                    // Query site map per domain using SiteMapFilter.prefixFilter
                    // This returns ALL entries under each domain at every path depth
                    for (String domain : scopeManager.getTargetDomains()) {
                        for (String scheme : new String[]{"https://", "http://"}) {
                            String prefix = scheme + domain;
                            try {
                                var filter = burp.api.montoya.sitemap.SiteMapFilter.prefixFilter(prefix);
                                List<HttpRequestResponse> entries = api.siteMap().requestResponses(filter);
                                api.logging().logToOutput("[Scrape] " + prefix + " → " + entries.size() + " site map entries");

                                for (HttpRequestResponse rr : entries) {
                                    totalScanned++;
                                    if (rr.request() == null) continue;

                                    String url = rr.request().url();
                                    if (url == null) continue;

                                    // If response is null, the entry was discovered but never fetched.
                                    // Actively fetch it if the URL looks like JS/HTML.
                                    if (rr.response() == null) {
                                        if (hasJsOrHtmlExtension(url)) {
                                            try {
                                                rr = api.http().sendRequest(rr.request());
                                                api.logging().logToOutput("[Scrape] Fetched missing response: " + url);
                                            } catch (Exception fetchEx) {
                                                api.logging().logToOutput("[Scrape] Fetch failed: " + url);
                                                continue;
                                            }
                                            if (rr.response() == null) continue;
                                        } else {
                                            continue;
                                        }
                                    }
                                    String body = rr.response().bodyToString();
                                    if (body == null || body.isEmpty()) continue;

                                    // Deduplicate by URL path (strip fragment + query string)
                                    String dedupeKey = stripUrlParams(url);
                                    if (matches.containsKey(dedupeKey)) continue;

                                    if (isJsOrHtmlResponse(url, rr)) {
                                        matches.put(dedupeKey, rr);
                                        api.logging().logToOutput("[Scrape] Matched: " + url);
                                    }
                                }
                            } catch (Exception ex) {
                                api.logging().logToError("[Scrape] Failed for " + prefix + ": " + ex.getMessage());
                            }
                        }
                    }

                    api.logging().logToOutput("[Scrape] Scanned: " + totalScanned + " | Matched JS/HTML: " + matches.size());

                } catch (Exception ex) {
                    api.logging().logToError("Scrape error: " + ex.getMessage());
                }

                if (!matches.isEmpty()) {
                    analyzer.addAllToBatchQueue(new ArrayList<>(matches.values()));
                }
                return new int[]{matches.size(), totalScanned};
            }

            @Override
            protected void done() {
                try {
                    int[] result = get();
                    int found = result[0];
                    int scanned = result[1];
                    if (found == 0) {
                        batchStatusLabel.setText("No JS/HTML found (" + scanned + " site map entries scanned)");
                        batchStatusLabel.setForeground(MUTED);
                    } else {
                        batchStatusLabel.setText("Scraped " + found + " JS/HTML file(s) from site map");
                        batchStatusLabel.setForeground(SUCCESS);
                    }
                    refreshBatchTable();
                } catch (Exception ex) {
                    batchStatusLabel.setText("Scrape failed: " + ex.getMessage());
                    batchStatusLabel.setForeground(ERROR_COLOR);
                }
            }
        }.execute();
    }

    private static String stripUrlParams(String url) {
        int hashIdx = url.indexOf('#');
        if (hashIdx > 0) url = url.substring(0, hashIdx);
        int qIdx = url.indexOf('?');
        if (qIdx > 0) url = url.substring(0, qIdx);
        return url;
    }

    /**
     * Checks whether a site map entry is a JS or HTML response based on Content-Type header,
     * URL path extension, or response body heuristics.
     */
    private static boolean isJsOrHtmlResponse(String url, HttpRequestResponse rr) {
        // 1. Check Content-Type header
        for (var h : rr.response().headers()) {
            if ("content-type".equalsIgnoreCase(h.name())) {
                String ct = h.value().toLowerCase();
                if (ct.contains("javascript") || ct.contains("ecmascript")
                        || ct.contains("html") || ct.contains("xhtml")
                        || ct.contains("application/x-javascript")
                        || ct.contains("text/jsx")) {
                    return true;
                }
                break;
            }
        }

        // 2. Check URL path extension (strip query string, fragment, matrix params)
        String path = url.toLowerCase();
        // Strip fragment
        int hashIdx = path.indexOf('#');
        if (hashIdx > 0) path = path.substring(0, hashIdx);
        // Strip query string
        int qIdx = path.indexOf('?');
        if (qIdx > 0) path = path.substring(0, qIdx);
        // Strip matrix params (;jsessionid=... etc.)
        int semiIdx = path.indexOf(';');
        if (semiIdx > 0) path = path.substring(0, semiIdx);

        if (path.endsWith(".js") || path.endsWith(".jsx") || path.endsWith(".mjs")
                || path.endsWith(".ts") || path.endsWith(".tsx")
                || path.endsWith(".html") || path.endsWith(".htm")
                || path.endsWith(".xhtml") || path.endsWith(".shtml")) {
            return true;
        }

        // 3. Check common JS bundle path patterns (e.g., /chunks/abc123, /static/js/main.deadbeef)
        if (path.matches(".*/(chunk|bundle|vendor|runtime|main|app|polyfill)[s]?[.\\-][a-f0-9]+$")
                || path.contains("/static/js/") || path.contains("/assets/js/")
                || path.contains("/_next/static/") || path.contains("/dist/")) {
            // Verify content looks like JS (not an image or font served from these paths)
            String body = rr.response().bodyToString();
            if (body != null && body.length() > 20) {
                String start = body.substring(0, Math.min(body.length(), 500)).trim();
                if (start.startsWith("<!") || start.startsWith("<html") || start.startsWith("<HTML")
                        || start.contains("function") || start.contains("var ") || start.contains("const ")
                        || start.contains("let ") || start.contains("import ") || start.contains("export ")
                        || start.startsWith("(function") || start.startsWith("!function")
                        || start.startsWith("\"use strict\"") || start.startsWith("'use strict'")
                        || start.startsWith("define(") || start.startsWith("require(")
                        || start.startsWith("self.__next") || start.startsWith("window.")
                        || start.startsWith("(self.webpackChunk") || start.startsWith("(window.webpackJsonp")) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks whether a URL looks like a JS or HTML resource based on file extension
     * or common JS bundle path patterns. Used to decide whether to actively fetch
     * site map entries that were discovered but never proxied (response == null).
     */
    private static boolean hasJsOrHtmlExtension(String url) {
        String path = url.toLowerCase();
        int hashIdx = path.indexOf('#');
        if (hashIdx > 0) path = path.substring(0, hashIdx);
        int qIdx = path.indexOf('?');
        if (qIdx > 0) path = path.substring(0, qIdx);
        int semiIdx = path.indexOf(';');
        if (semiIdx > 0) path = path.substring(0, semiIdx);

        if (path.endsWith(".js") || path.endsWith(".jsx") || path.endsWith(".mjs")
                || path.endsWith(".ts") || path.endsWith(".tsx")
                || path.endsWith(".html") || path.endsWith(".htm")
                || path.endsWith(".xhtml") || path.endsWith(".shtml")) {
            return true;
        }

        return path.contains("/static/js/") || path.contains("/assets/js/")
                || path.contains("/_next/static/") || path.contains("/dist/");
    }

    private static String formatSize(int chars) {
        if (chars < 1024) return chars + " B";
        if (chars < 1024 * 1024) return String.format("%.1f KB", chars / 1024.0);
        return String.format("%.1f MB", chars / (1024.0 * 1024.0));
    }

    private JLabel createFieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        label.setForeground(new Color(55, 65, 81));
        return label;
    }

    private JButton createStyledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setFocusPainted(false);
        btn.setMargin(new Insets(4, 12, 4, 12));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        if (bg != null) {
            btn.setBackground(bg);
            btn.setForeground(Color.WHITE);
            btn.setOpaque(true);
            btn.setBorderPainted(false);
        }
        return btn;
    }

    // ==================== Context Menu ====================

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
                String tabName = "AI: " + truncateStr(f.getTitle(), 30);
                api.repeater().sendToRepeater(f.getRequestResponse().request(), tabName);
            }
        });
        popup.add(sendToRepeater);

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            Finding f = getSelectedFinding();
            if (f != null && f.getUrl() != null && !f.getUrl().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(f.getUrl()), null);
            }
        });
        popup.add(copyUrl);

        // Improvement 11: Exploit This Finding — multi-step AI exploitation
        popup.addSeparator();
        JMenuItem exploitItem = new JMenuItem("Exploit This Finding (AI)");
        exploitItem.setToolTipText("Use AI to perform multi-step exploitation of this confirmed vulnerability");
        exploitItem.addActionListener(e -> {
            Finding f = getSelectedFinding();
            if (f == null) return;
            if (f.getRequestResponse() == null || f.getRequestResponse().request() == null) {
                JOptionPane.showMessageDialog(this, "No request data available for exploitation.",
                        "Cannot Exploit", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!analyzer.isAiConfigured()) {
                JOptionPane.showMessageDialog(this, "AI is not configured. Select CLI or API Key mode first.",
                        "AI Not Configured", JOptionPane.WARNING_MESSAGE);
                return;
            }
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Start multi-step AI exploitation of:\n" + f.getTitle() + "\nat " + f.getUrl() + "?\n\n"
                    + "This will send multiple exploitation payloads to the target.",
                    "Confirm Exploitation", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.OK_OPTION) {
                analyzer.exploitFinding(f, f.getRequestResponse());
            }
        });
        popup.add(exploitItem);

        findingsTable.setComponentPopupMenu(popup);

        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = findingsTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        findingsTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    private Finding getSelectedFinding() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = findingsTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= findingsList.size()) return null;
        return findingsList.get(modelRow);
    }

    private static String truncateStr(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    // ==================== Event Handlers ====================

    private boolean applyCliConfig() {
        LlmProvider selected = (LlmProvider) cliProviderCombo.getSelectedItem();
        if (selected == null) return false;

        String binary = cliBinaryField.getText().trim();
        if (binary.isEmpty()) {
            cliTestStatusLabel.setText("Binary path cannot be empty");
            cliTestStatusLabel.setForeground(ERROR_COLOR);
            return false;
        }

        analyzer.getLlmClient().configureCli(selected, binary);
        analyzer.setConnectionMode(AiConnectionMode.CLI);
        cliTestStatusLabel.setText("Settings applied");
        cliTestStatusLabel.setForeground(SUCCESS);
        return true;
    }

    private void testCliConnection() {
        if (!applyCliConfig()) return;

        cliTestBtn.setEnabled(false);
        cliTestStatusLabel.setText("Testing...");
        cliTestStatusLabel.setForeground(MUTED);

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    return analyzer.getLlmClient().testConnection();
                } catch (Exception e) {
                    return "ERROR: " + e.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result.startsWith("ERROR:")) {
                        cliTestStatusLabel.setText(result);
                        cliTestStatusLabel.setForeground(ERROR_COLOR);
                    } else {
                        cliTestStatusLabel.setText(result);
                        cliTestStatusLabel.setForeground(SUCCESS);
                    }
                } catch (Exception e) {
                    cliTestStatusLabel.setText("Test failed: " + e.getMessage());
                    cliTestStatusLabel.setForeground(ERROR_COLOR);
                }
                cliTestBtn.setEnabled(true);
            }
        }.execute();
    }

    // ==================== API Key Event Handlers ====================

    private boolean applyApiKeyConfig() {
        ApiKeyProvider selected = (ApiKeyProvider) apiProviderCombo.getSelectedItem();
        if (selected == null) return false;

        String model = (String) apiModelCombo.getSelectedItem();
        if (model == null || model.isBlank()) {
            apiKeyTestStatusLabel.setText("No model selected");
            apiKeyTestStatusLabel.setForeground(ERROR_COLOR);
            return false;
        }

        String key = new String(apiKeyField.getPassword()).trim();
        if (key.isEmpty()) {
            apiKeyTestStatusLabel.setText("API key cannot be empty");
            apiKeyTestStatusLabel.setForeground(ERROR_COLOR);
            return false;
        }

        analyzer.getLlmClient().configureApiKey(selected, key, model);
        analyzer.setConnectionMode(AiConnectionMode.API_KEY);
        apiKeyTestStatusLabel.setText("Settings applied");
        apiKeyTestStatusLabel.setForeground(SUCCESS);
        return true;
    }

    private void testApiKeyConnection() {
        if (!applyApiKeyConfig()) return;

        apiKeyTestBtn.setEnabled(false);
        apiKeyTestStatusLabel.setText("Testing...");
        apiKeyTestStatusLabel.setForeground(MUTED);

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    return analyzer.getLlmClient().testConnection();
                } catch (Exception e) {
                    return "ERROR: " + e.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result.startsWith("ERROR:")) {
                        apiKeyTestStatusLabel.setText(result);
                        apiKeyTestStatusLabel.setForeground(ERROR_COLOR);
                    } else {
                        apiKeyTestStatusLabel.setText(result);
                        apiKeyTestStatusLabel.setForeground(SUCCESS);
                    }
                } catch (Exception e) {
                    apiKeyTestStatusLabel.setText("Test failed: " + e.getMessage());
                    apiKeyTestStatusLabel.setForeground(ERROR_COLOR);
                }
                apiKeyTestBtn.setEnabled(true);
            }
        }.execute();
    }

    // ==================== Table Management ====================

    private void autoRefresh() {
        SwingUtilities.invokeLater(() -> {
            int running = analyzer.getActiveScansRunning();
            int queued = analyzer.getQueueSize();
            int errors = analyzer.getErrorCount();

            statsLabel.setText("Running: " + running
                    + "  |  Queued: " + queued
                    + "  |  Analyzed: " + analyzer.getAnalyzedCount()
                    + "  |  Findings: " + analyzer.getFindingsCount()
                    + "  |  Fuzz Requests: " + analyzer.getFuzzRequestsSent()
                    + "  |  Errors: " + errors
                    + "  |  " + analyzer.getCostSummary());

            // Highlight stats when scans are active
            statsLabel.setForeground(running > 0 ? ACCENT : MUTED);

            // Show/hide cancel button
            cancelScansBtn.setVisible(running > 0 || queued > 0);

            List<Finding> current = findingsStore.getFindingsByModule("ai-vuln-analyzer");
            if (current.size() != lastKnownCount) {
                lastKnownCount = current.size();
                tableModel.setRowCount(0);
                findingsList.clear();
                for (Finding f : current) {
                    findingsList.add(f);
                    addFindingRow(f);
                }
            }

            // Refresh batch queue UI when queue size changes or batch scan is running
            int currentBatchSize = analyzer.getBatchQueueSize();
            boolean scanning = analyzer.isBatchScanRunning();
            if (currentBatchSize != lastBatchQueueSize || scanning) {
                refreshBatchTable();
            }
        });
    }

    private void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            List<Finding> current = findingsStore.getFindingsByModule("ai-vuln-analyzer");
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

    private void showSelectedDetail() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = findingsTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= findingsList.size()) return;

        Finding f = findingsList.get(modelRow);
        StringBuilder sb = new StringBuilder();
        sb.append("TITLE: ").append(f.getTitle()).append("\n\n");
        sb.append("SEVERITY: ").append(f.getSeverity()).append("  |  CONFIDENCE: ").append(f.getConfidence()).append("\n\n");

        if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
            sb.append("EVIDENCE:\n").append(f.getEvidence()).append("\n\n");
        }
        if (f.getDescription() != null && !f.getDescription().isEmpty()) {
            sb.append("DESCRIPTION:\n").append(f.getDescription()).append("\n\n");
        }
        if (f.getRemediation() != null && !f.getRemediation().isEmpty()) {
            sb.append("REMEDIATION:\n").append(f.getRemediation()).append("\n\n");
        }
        if (f.getUrl() != null && !f.getUrl().isEmpty()) {
            sb.append("URL: ").append(f.getUrl()).append("\n");
        }
        if (f.getParameter() != null && !f.getParameter().isEmpty()) {
            sb.append("PARAMETER: ").append(f.getParameter()).append("\n");
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private void clearFindings() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Clear all AI analysis findings? This cannot be undone.",
                "Confirm Clear", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            findingsStore.clearModule("ai-vuln-analyzer");
            refreshTable();
        }
    }

    private void exportFindings() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("ai-vuln-analyzer_findings.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (java.io.PrintWriter pw = new java.io.PrintWriter(
                    new java.io.FileWriter(fc.getSelectedFile()))) {
                pw.println("Severity,Confidence,Title,URL,Parameter,Evidence,Description,Remediation");
                for (Finding f : findingsStore.getFindingsByModule("ai-vuln-analyzer")) {
                    pw.println(
                            esc(f.getSeverity() != null ? f.getSeverity().name() : "") + ","
                            + esc(f.getConfidence() != null ? f.getConfidence().name() : "") + ","
                            + esc(f.getTitle()) + "," + esc(f.getUrl()) + ","
                            + esc(f.getParameter()) + "," + esc(f.getEvidence()) + ","
                            + esc(f.getDescription()) + "," + esc(f.getRemediation()));
                }
                JOptionPane.showMessageDialog(this, "Exported to " + fc.getSelectedFile().getName());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
            }
        }
    }

    private String esc(String v) {
        if (v == null) return "\"\"";
        return "\"" + v.replace("\"", "\"\"").replace("\n", " ").replace("\r", "") + "\"";
    }

    /**
     * Stops the auto-refresh timer. Called from extension unload handler.
     */
    public void stopTimers() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
}
