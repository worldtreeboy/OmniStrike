package com.omnistrike.ui;

import com.omnistrike.framework.PrivacyManager;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Real-time scrolling activity log panel.
 * Thread-safe: all updates go through SwingUtilities.invokeLater.
 */
public class LogPanel extends JPanel {

    private final JTextArea logArea;
    private static final int MAX_LINES = 5000;
    private final java.util.List<String> rawLines = new java.util.ArrayList<>();

    public LogPanel() {
        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(MONO_FONT);
        logArea.setBackground(BG_DARK);
        logArea.setForeground(NEON_GREEN);
        logArea.setCaretColor(NEON_GREEN);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        CyberTheme.styleScrollPane(scrollPane);
        add(scrollPane, BorderLayout.CENTER);

        // Controls
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        controls.setBackground(BG_DARK);

        JButton copyAllBtn = new JButton("Copy All");
        CyberTheme.styleButton(copyAllBtn, NEON_CYAN);
        copyAllBtn.setToolTipText("Copy all log contents to the clipboard");
        copyAllBtn.addActionListener(e -> {
            String text = logArea.getText();
            if (text != null && !text.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(text), null);
            }
        });
        controls.add(copyAllBtn);

        JButton clearBtn = new JButton("Clear Log");
        CyberTheme.styleButton(clearBtn, NEON_RED);
        clearBtn.addActionListener(e -> {
            rawLines.clear();
            logArea.setText("");
        });
        controls.add(clearBtn);

        add(controls, BorderLayout.SOUTH);
    }

    public void log(String level, String module, String message) {
        String timestamp = new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new java.util.Date());
        String line = String.format("[%s] [%s] [%s] %s%n", timestamp, level, module, message);

        SwingUtilities.invokeLater(() -> {
            rawLines.add(line);
            if (rawLines.size() > MAX_LINES) rawLines.remove(0);
            logArea.append(PrivacyManager.maskForDisplay(line));
            if (logArea.getLineCount() > MAX_LINES) refreshPrivacyDisplay();
            // Auto-scroll to bottom
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    /** Rebuilds the visible log when the global UI privacy preference changes. */
    public void refreshPrivacyDisplay() {
        SwingUtilities.invokeLater(() -> {
            StringBuilder display = new StringBuilder();
            for (String line : rawLines) {
                display.append(PrivacyManager.maskForDisplay(line));
            }
            logArea.setText(display.toString());
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
