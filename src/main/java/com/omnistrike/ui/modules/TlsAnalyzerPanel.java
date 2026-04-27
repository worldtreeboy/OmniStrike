package com.omnistrike.ui.modules;

import com.omnistrike.framework.tls.TlsAnalyzer;
import com.omnistrike.framework.tls.TlsResult;
import com.omnistrike.ui.CyberTheme;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Map;

/**
 * UI panel for the TLS Analyzer framework tool.
 *
 * Lets the user enter a host:port and run an out-of-band TLS scan that probes
 * each protocol version, optionally enumerates cipher suites, and inspects the
 * server's certificate chain. Results render in three tables (protocol matrix,
 * cipher suites, certificate chain) plus an issue list.
 *
 * The TLS handshake is performed by the plugin process, not by Burp's
 * forwarder, because the Montoya API does not expose negotiated TLS metadata.
 */
public class TlsAnalyzerPanel extends JPanel {

    private final TlsAnalyzer analyzer;

    private final JTextField hostField;
    private final JTextField portField;
    private final JCheckBox enumerateCiphersBox;
    private final JCheckBox publishFindingsBox;
    private final JButton runBtn;
    private final JButton stopBtn;
    private final JLabel statusLabel;

    private final DefaultTableModel protocolModel;
    private final JTable protocolTable;

    private final DefaultTableModel cipherModel;
    private final JTable cipherTable;

    private final DefaultTableModel certModel;
    private final JTable certTable;

    private final DefaultTableModel issueModel;
    private final JTable issueTable;

    private volatile String currentHost;
    private volatile int currentPort;

    public TlsAnalyzerPanel(TlsAnalyzer analyzer) {
        this.analyzer = analyzer;
        setLayout(new BorderLayout(0, 6));
        setBackground(BG_DARK);
        styleTitledBorder(this, "TLS / SSL Analyzer", NEON_CYAN);

        // ════════════════ TOP CONTROLS ════════════════
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        top.setBackground(BG_DARK);

        JLabel hostLabel = new JLabel("Host:");
        hostLabel.setForeground(NEON_CYAN);
        hostLabel.setFont(MONO_BOLD);
        top.add(hostLabel);

        hostField = new JTextField(22);
        styleTextField(hostField);
        hostField.setToolTipText("Target hostname (no scheme). Example: example.com");
        hostField.putClientProperty("JTextField.placeholderText", "e.g. example.com");
        top.add(hostField);

        JLabel portLabel = new JLabel("Port:");
        portLabel.setForeground(NEON_CYAN);
        portLabel.setFont(MONO_BOLD);
        top.add(portLabel);

        portField = new JTextField("443", 5);
        styleTextField(portField);
        portField.setToolTipText("TLS port (default 443)");
        top.add(portField);

        enumerateCiphersBox = new JCheckBox("Enumerate ciphers");
        styleCheckBox(enumerateCiphersBox);
        enumerateCiphersBox.setForeground(NEON_GREEN);
        enumerateCiphersBox.setFont(MONO_FONT);
        enumerateCiphersBox.setToolTipText("Probe each cipher suite individually (slower but complete weak-cipher list)");
        enumerateCiphersBox.setSelected(false);
        top.add(enumerateCiphersBox);

        publishFindingsBox = new JCheckBox("Publish findings");
        styleCheckBox(publishFindingsBox);
        publishFindingsBox.setForeground(NEON_BLUE);
        publishFindingsBox.setFont(MONO_FONT);
        publishFindingsBox.setToolTipText("Send detected issues into the FindingsStore so they appear in the Dashboard and OmniStrike Findings tab");
        publishFindingsBox.setSelected(true);
        top.add(publishFindingsBox);

        runBtn = new JButton("Run Scan");
        styleButton(runBtn, NEON_GREEN);
        runBtn.setToolTipText("Probe the target's TLS configuration. Runs from the plugin process (not Burp's forwarder).");
        runBtn.addActionListener(e -> runScan());
        top.add(runBtn);

        stopBtn = new JButton("Stop");
        styleButton(stopBtn, NEON_RED);
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopScan());
        top.add(stopBtn);

        JButton clearBtn = new JButton("Clear");
        styleButton(clearBtn, NEON_ORANGE);
        clearBtn.setToolTipText("Clear results and the cached scan for this target");
        clearBtn.addActionListener(e -> clearResults());
        top.add(clearBtn);

        JButton exportBtn = new JButton("Export TXT");
        styleButton(exportBtn, NEON_CYAN);
        exportBtn.setToolTipText("Save the current scan results to a .txt file");
        exportBtn.addActionListener(e -> exportToFile());
        top.add(exportBtn);

        JButton copyBtn = new JButton("Copy");
        styleButton(copyBtn, NEON_CYAN);
        copyBtn.setToolTipText("Copy a plain-text summary of the current scan to the clipboard");
        copyBtn.addActionListener(e -> copyToClipboard());
        top.add(copyBtn);

        JPanel northWrapper = new JPanel(new BorderLayout(0, 0));
        northWrapper.setBackground(BG_DARK);
        northWrapper.add(top, BorderLayout.NORTH);

        statusLabel = new JLabel(" ");
        statusLabel.setForeground(FG_SECONDARY);
        statusLabel.setFont(MONO_SMALL);
        statusLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 4, 12));
        northWrapper.add(statusLabel, BorderLayout.CENTER);

        // Help banner — explains JDK-disabled-protocol caveat
        JTextArea help = new JTextArea(
                "How it works:\n"
                + "  - Probes are made from the plugin process (Burp's Montoya API does not expose the negotiated TLS metadata).\n"
                + "  - Each protocol is tested individually; supported = handshake completed, blocked-by-JDK = your local JVM disables it.\n"
                + "  - Modern JDKs (17+) disable SSLv3 / TLSv1 / TLSv1.1 by default. Those rows will appear as 'BLOCKED_BY_JDK' even if\n"
                + "    the server still accepts them. Edit jdk.tls.disabledAlgorithms in java.security and restart Burp to probe legacy protocols.\n"
                + "  - Cert chain inspection uses a permissive trust manager so we can examine self-signed/expired certs without aborting.");
        help.setEditable(false);
        help.setLineWrap(true);
        help.setWrapStyleWord(true);
        help.setBackground(BG_SURFACE);
        help.setForeground(FG_SECONDARY);
        help.setFont(MONO_SMALL);
        help.setBorder(BorderFactory.createCompoundBorder(
                new CyberTheme.GlowMatteBorder(1, 0, 1, 0, BORDER),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)));
        northWrapper.add(help, BorderLayout.SOUTH);

        add(northWrapper, BorderLayout.NORTH);

        // ════════════════ TABLES ════════════════
        // Protocol matrix
        protocolModel = new DefaultTableModel(
                new String[]{"Protocol", "Status", "Negotiated Cipher", "Detail"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        protocolTable = new JTable(protocolModel);
        styleTable(protocolTable);
        protocolTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        protocolTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        protocolTable.getColumnModel().getColumn(2).setPreferredWidth(220);
        protocolTable.getColumnModel().getColumn(3).setPreferredWidth(280);
        JScrollPane protoScroll = new JScrollPane(protocolTable);
        styleScrollPane(protoScroll);
        JPanel protoPanel = wrapTitled("Protocol Matrix", NEON_CYAN, protoScroll);

        // Cipher suites
        cipherModel = new DefaultTableModel(new String[]{"Cipher Suite", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        cipherTable = new JTable(cipherModel);
        styleTable(cipherTable);
        cipherTable.getColumnModel().getColumn(0).setPreferredWidth(420);
        cipherTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        JScrollPane cipherScroll = new JScrollPane(cipherTable);
        styleScrollPane(cipherScroll);
        JPanel cipherPanel = wrapTitled("Cipher Suites Accepted", NEON_GREEN, cipherScroll);

        // Cert chain
        certModel = new DefaultTableModel(
                new String[]{"#", "Subject", "Issuer", "Sig Alg", "Key", "Valid Until", "Days Left"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        certTable = new JTable(certModel);
        styleTable(certTable);
        certTable.getColumnModel().getColumn(0).setMaxWidth(40);
        certTable.getColumnModel().getColumn(1).setPreferredWidth(220);
        certTable.getColumnModel().getColumn(2).setPreferredWidth(220);
        certTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        certTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        certTable.getColumnModel().getColumn(5).setPreferredWidth(140);
        certTable.getColumnModel().getColumn(6).setPreferredWidth(80);
        JScrollPane certScroll = new JScrollPane(certTable);
        styleScrollPane(certScroll);
        JPanel certPanel = wrapTitled("Certificate Chain", NEON_MAGENTA, certScroll);

        // Issues
        issueModel = new DefaultTableModel(new String[]{"Severity", "Issue", "Detail"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        issueTable = new JTable(issueModel);
        styleTable(issueTable);
        issueTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        issueTable.getColumnModel().getColumn(1).setPreferredWidth(280);
        issueTable.getColumnModel().getColumn(2).setPreferredWidth(420);
        JScrollPane issueScroll = new JScrollPane(issueTable);
        styleScrollPane(issueScroll);
        JPanel issuePanel = wrapTitled("Issues", NEON_RED, issueScroll);

        JSplitPane topSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, protoPanel, cipherPanel);
        topSplit.setDividerLocation(180);
        styleSplitPane(topSplit);

        JSplitPane midSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, certPanel);
        midSplit.setDividerLocation(360);
        styleSplitPane(midSplit);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, midSplit, issuePanel);
        mainSplit.setDividerLocation(540);
        styleSplitPane(mainSplit);

        add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel wrapTitled(String title, Color color, JComponent body) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(BG_DARK);
        styleTitledBorder(p, title, color);
        p.add(body, BorderLayout.CENTER);
        return p;
    }

    /** Public entry — context menu uses this to populate the panel and run a scan. */
    public void runForTarget(String host, int port, boolean autoStart) {
        SwingUtilities.invokeLater(() -> {
            hostField.setText(host == null ? "" : host);
            portField.setText(String.valueOf(port));
            if (autoStart) runScan();
        });
    }

    private void runScan() {
        String host = hostField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
            if (port <= 0 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException nf) {
            statusLabel.setText("Invalid port — must be 1..65535");
            statusLabel.setForeground(NEON_RED);
            return;
        }
        if (host.isEmpty()) {
            statusLabel.setText("Enter a host first.");
            statusLabel.setForeground(NEON_RED);
            return;
        }

        currentHost = host;
        currentPort = port;
        clearTables();
        runBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        statusLabel.setForeground(NEON_GREEN);
        statusLabel.setText("Scanning " + host + ":" + port + " ...");

        analyzer.invalidate(host, port);
        analyzer.analyze(host, port,
                enumerateCiphersBox.isSelected(),
                publishFindingsBox.isSelected(),
                result -> SwingUtilities.invokeLater(() -> {
                    runBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    if (result == null) {
                        statusLabel.setForeground(NEON_RED);
                        statusLabel.setText("Scan failed — see Activity Log.");
                        return;
                    }
                    renderResult(result);
                    statusLabel.setForeground(NEON_GREEN);
                    statusLabel.setText("Scan complete — " + result.getProtocols().size()
                            + " protocols probed, " + result.getSupportedCiphers().size()
                            + " cipher(s), " + result.getCertChain().size()
                            + " cert(s), " + result.getIssues().size() + " issue(s).");
                }));
    }

    private void stopScan() {
        if (currentHost == null) return;
        boolean stopped = analyzer.cancel(currentHost, currentPort);
        if (stopped) {
            statusLabel.setForeground(NEON_ORANGE);
            statusLabel.setText("Scan cancelled.");
        }
        runBtn.setEnabled(true);
        stopBtn.setEnabled(false);
    }

    private void clearResults() {
        if (currentHost != null) analyzer.invalidate(currentHost, currentPort);
        clearTables();
        statusLabel.setText(" ");
    }

    private void clearTables() {
        protocolModel.setRowCount(0);
        cipherModel.setRowCount(0);
        certModel.setRowCount(0);
        issueModel.setRowCount(0);
    }

    private void renderResult(TlsResult r) {
        protocolModel.setRowCount(0);
        for (Map.Entry<String, TlsResult.ProtocolOutcome> e : r.getProtocols().entrySet()) {
            TlsResult.ProtocolOutcome o = e.getValue();
            protocolModel.addRow(new Object[]{
                    o.protocol,
                    o.status.name(),
                    o.negotiatedCipher == null ? "" : o.negotiatedCipher,
                    o.detail == null ? "" : o.detail
            });
        }

        cipherModel.setRowCount(0);
        for (String c : r.getSupportedCiphers()) {
            String tag = classifyCipher(c);
            cipherModel.addRow(new Object[]{c, tag});
        }

        certModel.setRowCount(0);
        for (TlsResult.CertInfo ci : r.getCertChain()) {
            String key = ci.publicKeyAlgorithm
                    + (ci.publicKeySize > 0 ? " " + ci.publicKeySize : "");
            certModel.addRow(new Object[]{
                    ci.index,
                    truncate(ci.subject, 90),
                    truncate(ci.issuer, 90),
                    ci.signatureAlgorithm,
                    key,
                    ci.notAfter,
                    ci.daysUntilExpiry
            });
        }

        issueModel.setRowCount(0);
        for (TlsResult.Issue i : r.getIssues()) {
            issueModel.addRow(new Object[]{i.severity.name(), i.title, i.detail});
        }
    }

    private static String classifyCipher(String cipher) {
        String lower = cipher.toLowerCase();
        if (lower.contains("_null_") || lower.contains("_anon_") || lower.contains("_export"))
            return "CRITICAL";
        if (lower.contains("_rc4_") || lower.contains("_des_") || lower.contains("_3des_"))
            return "WEAK";
        if (lower.contains("_md5"))
            return "WEAK (MD5)";
        if (lower.contains("_cbc_"))
            return "OK (legacy CBC)";
        if (lower.contains("_gcm_") || lower.contains("_chacha20"))
            return "STRONG (AEAD)";
        return "OK";
    }

    private void exportToFile() {
        if (currentHost == null) {
            statusLabel.setText("No scan to export.");
            return;
        }
        TlsResult r = analyzer.getCached(currentHost, currentPort);
        if (r == null) {
            statusLabel.setText("No scan result cached for " + currentHost + ":" + currentPort);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("tls-" + currentHost + "-" + currentPort + ".txt"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
            pw.println(buildSummary(r));
            statusLabel.setForeground(NEON_GREEN);
            statusLabel.setText("Exported to " + fc.getSelectedFile().getName());
        } catch (Exception e) {
            statusLabel.setForeground(NEON_RED);
            statusLabel.setText("Export failed: " + e.getMessage());
        }
    }

    private void copyToClipboard() {
        if (currentHost == null) {
            statusLabel.setText("No scan to copy.");
            return;
        }
        TlsResult r = analyzer.getCached(currentHost, currentPort);
        if (r == null) {
            statusLabel.setText("No scan result cached for " + currentHost + ":" + currentPort);
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(buildSummary(r)), null);
        statusLabel.setForeground(NEON_GREEN);
        statusLabel.setText("Summary copied to clipboard.");
    }

    private String buildSummary(TlsResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== OmniStrike TLS Analysis ===\n");
        sb.append("Target: ").append(r.getHost()).append(":").append(r.getPort()).append("\n");
        sb.append("Timestamp: ").append(new java.util.Date(r.getTimestampMs())).append("\n\n");

        sb.append("Protocols:\n");
        for (TlsResult.ProtocolOutcome o : r.getProtocols().values()) {
            sb.append("  ").append(String.format("%-9s", o.protocol))
                    .append("  ").append(o.status.name());
            if (o.negotiatedCipher != null) sb.append("  (").append(o.negotiatedCipher).append(")");
            if (o.detail != null && !o.detail.isEmpty()) sb.append("  — ").append(o.detail);
            sb.append("\n");
        }

        sb.append("\nCiphers accepted (").append(r.getSupportedCiphers().size()).append("):\n");
        for (String c : r.getSupportedCiphers()) {
            sb.append("  - ").append(c).append("  [").append(classifyCipher(c)).append("]\n");
        }

        sb.append("\nCertificate chain (").append(r.getCertChain().size()).append("):\n");
        for (TlsResult.CertInfo ci : r.getCertChain()) {
            sb.append("  [").append(ci.index).append("] ").append(ci.subject).append("\n");
            sb.append("       Issuer:    ").append(ci.issuer).append("\n");
            sb.append("       Sig Alg:   ").append(ci.signatureAlgorithm).append("\n");
            sb.append("       Key:       ").append(ci.publicKeyAlgorithm)
                    .append(" ").append(ci.publicKeySize).append("\n");
            sb.append("       Valid:     ").append(ci.notBefore).append("  →  ")
                    .append(ci.notAfter).append("  (").append(ci.daysUntilExpiry).append(" days left)\n");
            if (!ci.sanEntries.isEmpty()) {
                sb.append("       SANs:      ").append(String.join(", ", ci.sanEntries)).append("\n");
            }
            if (ci.selfSigned) sb.append("       (self-signed)\n");
        }

        sb.append("\nIssues (").append(r.getIssues().size()).append("):\n");
        if (r.getIssues().isEmpty()) {
            sb.append("  (none)\n");
        } else {
            for (TlsResult.Issue i : r.getIssues()) {
                sb.append("  [").append(i.severity).append("] ").append(i.title).append("\n");
                sb.append("       ").append(i.detail).append("\n");
            }
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
