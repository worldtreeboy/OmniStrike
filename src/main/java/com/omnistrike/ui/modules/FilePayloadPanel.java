package com.omnistrike.ui.modules;

import com.omnistrike.framework.FilePayloadGenerator;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.Base64;

/**
 * UI panel for the File Payload Generator tool.
 * Users select a payload type, optionally enter a Collaborator URL,
 * and copy the payload (as text, base64, or raw bytes) to clipboard.
 */
public class FilePayloadPanel extends JPanel {

    private static final Color BG_DARK = new Color(30, 30, 46);
    private static final Color BG_CARD = new Color(40, 42, 58);
    private static final Color ACCENT = new Color(139, 92, 246);
    private static final Color FG = new Color(205, 214, 244);
    private static final Color FG_DIM = new Color(147, 153, 178);

    private final JTextField oobUrlField;
    private final JTextArea payloadPreview;
    private final JLabel statusLabel;
    private final JTable filePayloadTable;
    private final JTable inlinePayloadTable;
    private String lastCanary = "";

    public FilePayloadPanel() {
        setLayout(new BorderLayout(0, 0));
        setBackground(BG_DARK);

        // ── Top: OOB URL config ──
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        topPanel.setBackground(BG_DARK);
        topPanel.setBorder(new EmptyBorder(5, 10, 5, 10));

        JLabel oobLabel = new JLabel("Collaborator / OOB URL:");
        oobLabel.setForeground(FG);
        oobLabel.setFont(oobLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(oobLabel);

        oobUrlField = new JTextField(40);
        oobUrlField.setToolTipText("Enter your Burp Collaborator URL or custom OOB callback URL. Leave empty for no callback.");
        oobUrlField.setText("");
        topPanel.add(oobUrlField);

        JButton refreshBtn = new JButton("Regenerate Canary");
        refreshBtn.addActionListener(e -> refreshAll());
        topPanel.add(refreshBtn);

        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(FG_DIM);
        topPanel.add(statusLabel);

        add(topPanel, BorderLayout.NORTH);

        // ── Center: Split pane with tables + preview ──
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setBackground(BG_DARK);

        // Top half: two tabs — File Payloads + Inline Payloads
        JTabbedPane tabs = new JTabbedPane();

        // File payloads table
        String[] fileCols = {"Type", "Description", "Extension", "MIME Type", "Size"};
        DefaultTableModel fileModel = new DefaultTableModel(fileCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        filePayloadTable = new JTable(fileModel);
        filePayloadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        filePayloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) previewSelectedFilePayload();
        });

        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.add(new JScrollPane(filePayloadTable), BorderLayout.CENTER);

        // File payload buttons
        JPanel fileButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton copyBase64Btn = new JButton("Copy as Base64");
        copyBase64Btn.setToolTipText("Copy the raw file bytes as Base64-encoded string");
        copyBase64Btn.addActionListener(e -> copyFilePayloadBase64());
        fileButtons.add(copyBase64Btn);

        JButton copyTextBtn = new JButton("Copy as Text");
        copyTextBtn.setToolTipText("Copy the payload as UTF-8 text (for text-based formats like PHP, SVG, HTML)");
        copyTextBtn.addActionListener(e -> copyFilePayloadText());
        fileButtons.add(copyTextBtn);

        JButton copyFilenamesBtn = new JButton("Copy PHP Bypass Filenames");
        copyFilenamesBtn.setToolTipText("Copy a list of PHP extension bypass filenames");
        copyFilenamesBtn.addActionListener(e -> {
            String names = String.join("\n", FilePayloadGenerator.phpBypassFilenames());
            copyToClipboard(names);
            statusLabel.setText("Copied " + FilePayloadGenerator.phpBypassFilenames().length + " filenames");
        });
        fileButtons.add(copyFilenamesBtn);

        filePanel.add(fileButtons, BorderLayout.SOUTH);
        tabs.addTab("File Payloads (53)", filePanel);

        // Inline payloads table
        String[] inlineCols = {"Type", "Description", "Notes"};
        DefaultTableModel inlineModel = new DefaultTableModel(inlineCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        inlinePayloadTable = new JTable(inlineModel);
        inlinePayloadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        inlinePayloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) previewSelectedInlinePayload();
        });

        JPanel inlinePanel = new JPanel(new BorderLayout());
        inlinePanel.add(new JScrollPane(inlinePayloadTable), BorderLayout.CENTER);

        JPanel inlineButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton copyInlineBtn = new JButton("Copy Payload");
        copyInlineBtn.setToolTipText("Copy the selected inline payload to clipboard");
        copyInlineBtn.addActionListener(e -> copyInlinePayload());
        inlineButtons.add(copyInlineBtn);

        JButton copyAllInlineBtn = new JButton("Copy All Payloads");
        copyAllInlineBtn.setToolTipText("Copy all inline payloads as a list");
        copyAllInlineBtn.addActionListener(e -> copyAllInlinePayloads());
        inlineButtons.add(copyAllInlineBtn);

        inlinePanel.add(inlineButtons, BorderLayout.SOUTH);
        tabs.addTab("Inline Payloads (31)", inlinePanel);

        mainSplit.setTopComponent(tabs);

        // Bottom half: preview
        JPanel previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT), "Payload Preview",
                0, 0, null, ACCENT));

        payloadPreview = new JTextArea();
        payloadPreview.setEditable(false);
        payloadPreview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadPreview.setLineWrap(true);
        payloadPreview.setWrapStyleWord(false);
        previewPanel.add(new JScrollPane(payloadPreview), BorderLayout.CENTER);

        JPanel previewButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton copyPreviewBtn = new JButton("Copy Preview");
        copyPreviewBtn.addActionListener(e -> {
            String text = payloadPreview.getText();
            if (!text.isEmpty()) {
                copyToClipboard(text);
                statusLabel.setText("Copied preview to clipboard");
            }
        });
        previewButtons.add(copyPreviewBtn);
        previewPanel.add(previewButtons, BorderLayout.SOUTH);

        mainSplit.setBottomComponent(previewPanel);
        add(mainSplit, BorderLayout.CENTER);

        // Initial load
        refreshAll();
    }

    private void refreshAll() {
        lastCanary = FilePayloadGenerator.generateCanary();
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;

        // Populate file payloads table
        DefaultTableModel fileModel = (DefaultTableModel) filePayloadTable.getModel();
        fileModel.setRowCount(0);
        for (String[] type : FilePayloadGenerator.getPayloadTypes()) {
            byte[] payload = FilePayloadGenerator.generate(type[0], lastCanary, oobUrl);
            fileModel.addRow(new Object[]{type[0], type[1], type[2], type[3], payload.length + " bytes"});
        }

        // Populate inline payloads table
        DefaultTableModel inlineModel = (DefaultTableModel) inlinePayloadTable.getModel();
        inlineModel.setRowCount(0);
        for (String[] p : FilePayloadGenerator.getInlinePayloads(lastCanary, oobUrl)) {
            inlineModel.addRow(new Object[]{p[0], p[1], p[3]});
        }

        statusLabel.setText("Canary: " + lastCanary + (oobUrl != null ? " | OOB: " + oobUrl : " | No OOB"));
        payloadPreview.setText("Select a payload from the table above to preview it.\n\nCanary: " + lastCanary);
    }

    private void previewSelectedFilePayload() {
        int row = filePayloadTable.getSelectedRow();
        if (row < 0) return;
        String typeId = (String) filePayloadTable.getValueAt(row, 0);
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;

        byte[] payload = FilePayloadGenerator.generate(typeId, lastCanary, oobUrl);
        String desc = (String) filePayloadTable.getValueAt(row, 1);

        StringBuilder preview = new StringBuilder();
        preview.append("── ").append(desc).append(" ──\n");
        preview.append("Type: ").append(typeId).append("\n");
        preview.append("Size: ").append(payload.length).append(" bytes\n");
        preview.append("Canary: ").append(lastCanary).append("\n\n");

        // Show as text if it's a text-based format
        String text = new String(payload, java.nio.charset.StandardCharsets.UTF_8);
        if (isBinaryPayload(typeId)) {
            preview.append("── Base64 ──\n");
            preview.append(Base64.getEncoder().encodeToString(payload)).append("\n\n");
            preview.append("── Hex (first 200 bytes) ──\n");
            preview.append(bytesToHex(payload, 200));
        } else {
            preview.append("── Content ──\n");
            preview.append(text);
        }

        payloadPreview.setText(preview.toString());
        payloadPreview.setCaretPosition(0);
    }

    private void previewSelectedInlinePayload() {
        int row = inlinePayloadTable.getSelectedRow();
        if (row < 0) return;
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;
        String[][] all = FilePayloadGenerator.getInlinePayloads(lastCanary, oobUrl);
        if (row >= all.length) return;

        String[] p = all[row];
        StringBuilder preview = new StringBuilder();
        preview.append("── ").append(p[1]).append(" ──\n\n");
        preview.append("Payload:\n").append(p[2]).append("\n\n");
        preview.append("Notes:\n").append(p[3]).append("\n\n");
        preview.append("Canary: ").append(lastCanary);

        payloadPreview.setText(preview.toString());
        payloadPreview.setCaretPosition(0);
    }

    private void copyFilePayloadBase64() {
        int row = filePayloadTable.getSelectedRow();
        if (row < 0) { statusLabel.setText("Select a payload first"); return; }
        String typeId = (String) filePayloadTable.getValueAt(row, 0);
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;
        byte[] payload = FilePayloadGenerator.generate(typeId, lastCanary, oobUrl);
        String b64 = Base64.getEncoder().encodeToString(payload);
        copyToClipboard(b64);
        statusLabel.setText("Copied " + typeId + " as Base64 (" + b64.length() + " chars)");
    }

    private void copyFilePayloadText() {
        int row = filePayloadTable.getSelectedRow();
        if (row < 0) { statusLabel.setText("Select a payload first"); return; }
        String typeId = (String) filePayloadTable.getValueAt(row, 0);
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;
        byte[] payload = FilePayloadGenerator.generate(typeId, lastCanary, oobUrl);
        String text = new String(payload, java.nio.charset.StandardCharsets.UTF_8);
        copyToClipboard(text);
        statusLabel.setText("Copied " + typeId + " as text (" + text.length() + " chars)");
    }

    private void copyInlinePayload() {
        int row = inlinePayloadTable.getSelectedRow();
        if (row < 0) { statusLabel.setText("Select a payload first"); return; }
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;
        String[][] all = FilePayloadGenerator.getInlinePayloads(lastCanary, oobUrl);
        if (row >= all.length) return;
        copyToClipboard(all[row][2]);
        statusLabel.setText("Copied: " + all[row][1]);
    }

    private void copyAllInlinePayloads() {
        String oobUrl = oobUrlField.getText().trim();
        if (oobUrl.isEmpty()) oobUrl = null;
        StringBuilder sb = new StringBuilder();
        for (String[] p : FilePayloadGenerator.getInlinePayloads(lastCanary, oobUrl)) {
            sb.append("# ").append(p[1]).append("\n");
            sb.append(p[2]).append("\n\n");
        }
        copyToClipboard(sb.toString());
        statusLabel.setText("Copied all inline payloads");
    }

    private boolean isBinaryPayload(String typeId) {
        return typeId.equals("docx_xxe") || typeId.equals("xlsx_xxe")
                || typeId.equals("polyglot_gif") || typeId.equals("jpeg_exif_xss")
                || typeId.equals("png_text_xss") || typeId.equals("eicar");
    }

    private String bytesToHex(byte[] bytes, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(bytes.length, maxBytes);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X ", bytes[i]));
            if ((i + 1) % 16 == 0) sb.append("\n");
        }
        if (len < bytes.length) sb.append("... (").append(bytes.length - len).append(" more bytes)");
        return sb.toString();
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
    }

    public void stopTimers() {
        // No timers to stop
    }
}
