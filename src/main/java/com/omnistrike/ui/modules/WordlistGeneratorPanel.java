package com.omnistrike.ui.modules;

import com.omnistrike.framework.wordlist.WordlistGenerator;
import com.omnistrike.framework.PrivacyManager;
import com.omnistrike.framework.wordlist.WordlistGenerator.WordCategory;
import com.omnistrike.framework.wordlist.WordlistGenerator.WordEntry;
import com.omnistrike.ui.CyberTheme;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * UI panel for the Wordlist Generator framework tool.
 * Shows harvested words in tabbed views (Paths, Parameters, Content, All).
 * Provides domain input, filters, export, and clipboard copy.
 */
public class WordlistGeneratorPanel extends JPanel {

    private final WordlistGenerator generator;

    // Domain input
    private final JTextField domainField;

    // Stats labels
    private final JLabel totalLabel;
    private final JLabel pathLabel;
    private final JLabel paramLabel;
    private final JLabel contentLabel;

    // Filter controls
    private final JTextField minLenField;
    private final JTextField maxLenField;
    private final JTextField includeField;
    private final JTextField excludeField;

    // Tabbed pane with 4 tables
    private final JTabbedPane tabbedPane;
    private final WordTableTab pathsTab;
    private final WordTableTab paramsTab;
    private final WordTableTab contentTab;
    private final WordTableTab allTab;

    // Auto-refresh timer
    private final Timer autoRefreshTimer;
    private int lastKnownCount = 0;

    public WordlistGeneratorPanel(WordlistGenerator generator) {
        this.generator = generator;
        setLayout(new BorderLayout(0, 4));
        setBackground(BG_DARK);

        // ============ TOP: Domain + Stats ============
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setBackground(BG_DARK);
        topPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 4, 8));

        // Domain row
        JPanel domainRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        domainRow.setBackground(BG_DARK);

        JLabel domLabel = new JLabel("Target Domain:");
        domLabel.setForeground(NEON_CYAN);
        domLabel.setFont(MONO_LABEL);
        domainRow.add(domLabel);

        domainField = new JTextField(25);
        CyberTheme.styleTextField(domainField);
        domainField.setToolTipText("Enter the domain to harvest words from (e.g., example.com). Subdomains are included automatically.");
        domainField.putClientProperty("JTextField.placeholderText", "e.g. example.com");
        // Live-sync to generator
        domainField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { syncDomain(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { syncDomain(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { syncDomain(); }
            private void syncDomain() {
                generator.setTargetDomain(domainField.getText().trim());
            }
        });
        domainRow.add(domainField);

        JButton scrapeBtn = new JButton("Scrape History");
        CyberTheme.styleButton(scrapeBtn, NEON_GREEN);
        scrapeBtn.setToolTipText("Scan all existing proxy/site map history for this domain and build a wordlist");
        scrapeBtn.addActionListener(e -> scrapeHistory(scrapeBtn));
        domainRow.add(scrapeBtn);

        JLabel domainHint = new JLabel("(only traffic to this domain will be harvested)");
        domainHint.setForeground(FG_SECONDARY);
        domainHint.setFont(MONO_SMALL);
        domainRow.add(domainHint);

        topPanel.add(domainRow);

        // Stats row
        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 2));
        statsRow.setBackground(BG_DARK);

        totalLabel = createStatLabel("Total: 0", NEON_CYAN);
        pathLabel = createStatLabel("Paths: 0", NEON_GREEN);
        paramLabel = createStatLabel("Params: 0", NEON_ORANGE);
        contentLabel = createStatLabel("Content: 0", NEON_MAGENTA);

        statsRow.add(totalLabel);
        statsRow.add(pathLabel);
        statsRow.add(paramLabel);
        statsRow.add(contentLabel);

        topPanel.add(statsRow);
        add(topPanel, BorderLayout.NORTH);

        // ============ CENTER: Tabbed Tables ============
        tabbedPane = new JTabbedPane();
        CyberTheme.styleTabbedPane(tabbedPane);

        pathsTab = new WordTableTab();
        paramsTab = new WordTableTab();
        contentTab = new WordTableTab();
        allTab = new WordTableTab();

        tabbedPane.addTab("Paths", pathsTab);
        tabbedPane.addTab("Parameters", paramsTab);
        tabbedPane.addTab("Content Words", contentTab);
        tabbedPane.addTab("All Combined", allTab);

        add(tabbedPane, BorderLayout.CENTER);

        // ============ BOTTOM: Filters + Buttons ============
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));
        bottomPanel.setBackground(BG_DARK);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 6, 8));

        // Filter row
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterRow.setBackground(BG_DARK);

        JLabel filterLabel = new JLabel("Filters:");
        filterLabel.setForeground(NEON_CYAN);
        filterLabel.setFont(MONO_LABEL);
        filterRow.add(filterLabel);

        filterRow.add(makeLabel("Min Len:"));
        minLenField = new JTextField("3", 3);
        CyberTheme.styleTextField(minLenField);
        filterRow.add(minLenField);

        filterRow.add(makeLabel("Max Len:"));
        maxLenField = new JTextField("64", 3);
        CyberTheme.styleTextField(maxLenField);
        filterRow.add(maxLenField);

        filterRow.add(makeLabel("Include:"));
        includeField = new JTextField(12);
        CyberTheme.styleTextField(includeField);
        includeField.setToolTipText("Regex — only include words matching this pattern");
        filterRow.add(includeField);

        filterRow.add(makeLabel("Exclude:"));
        excludeField = new JTextField(12);
        CyberTheme.styleTextField(excludeField);
        excludeField.setToolTipText("Regex — exclude words matching this pattern");
        filterRow.add(excludeField);

        JButton applyBtn = new JButton("Apply");
        CyberTheme.styleButton(applyBtn, NEON_CYAN);
        applyBtn.addActionListener(e -> refreshAllTabs());
        filterRow.add(applyBtn);

        bottomPanel.add(filterRow);

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        buttonRow.setBackground(BG_DARK);

        JButton exportBtn = new JButton("Export to File");
        CyberTheme.styleButton(exportBtn, NEON_GREEN);
        exportBtn.addActionListener(e -> exportToFile());
        buttonRow.add(exportBtn);

        JButton copyBtn = new JButton("Copy to Clipboard");
        CyberTheme.styleButton(copyBtn, NEON_BLUE);
        copyBtn.addActionListener(e -> copyToClipboard());
        buttonRow.add(copyBtn);

        JButton clearBtn = new JButton("Clear All");
        CyberTheme.styleButton(clearBtn, NEON_RED);
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Clear all collected words? This cannot be undone.",
                    "Confirm Clear", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.YES_OPTION) {
                generator.clearAll();
                lastKnownCount = 0;
                refreshAllTabs();
            }
        });
        buttonRow.add(clearBtn);

        bottomPanel.add(buttonRow);
        add(bottomPanel, BorderLayout.SOUTH);

        // ============ Auto-Refresh Timer (3 seconds) ============
        autoRefreshTimer = new Timer(3000, e -> autoRefresh());
        autoRefreshTimer.start();
    }

    // ==================== Refresh Logic ====================

    private void autoRefresh() {
        SwingUtilities.invokeLater(() -> {
            int currentCount = generator.getTotalCount();
            if (currentCount != lastKnownCount) {
                lastKnownCount = currentCount;
                refreshAllTabs();
            }
            updateStats();
        });
    }

    private void refreshAllTabs() {
        int minLen = parseIntSafe(minLenField.getText(), 0);
        int maxLen = parseIntSafe(maxLenField.getText(), 0);
        String include = includeField.getText().trim();
        String exclude = excludeField.getText().trim();

        pathsTab.refresh(filterWords(WordCategory.PATH, minLen, maxLen, include, exclude));
        paramsTab.refresh(filterWords(WordCategory.PARAM, minLen, maxLen, include, exclude));
        contentTab.refresh(filterWords(WordCategory.CONTENT, minLen, maxLen, include, exclude));
        allTab.refresh(filterWords(null, minLen, maxLen, include, exclude));
        updateStats();
    }

    private List<WordEntry> filterWords(WordCategory category, int minLen, int maxLen,
                                         String include, String exclude) {
        java.util.regex.Pattern incl = null;
        java.util.regex.Pattern excl = null;
        try {
            if (!include.isEmpty()) incl = java.util.regex.Pattern.compile(include, java.util.regex.Pattern.CASE_INSENSITIVE);
        } catch (Exception ignored) {}
        try {
            if (!exclude.isEmpty()) excl = java.util.regex.Pattern.compile(exclude, java.util.regex.Pattern.CASE_INSENSITIVE);
        } catch (Exception ignored) {}

        final java.util.regex.Pattern fIncl = incl;
        final java.util.regex.Pattern fExcl = excl;

        var source = category != null
                ? generator.getWordsByCategory(category)
                : new ArrayList<>(generator.getAllWords());

        var stream = source.stream();
        if (minLen > 0) stream = stream.filter(e -> e.getWord().length() >= minLen);
        if (maxLen > 0) stream = stream.filter(e -> e.getWord().length() <= maxLen);
        if (fIncl != null) stream = stream.filter(e -> fIncl.matcher(e.getWord()).find());
        if (fExcl != null) stream = stream.filter(e -> !fExcl.matcher(e.getWord()).find());

        return stream.sorted(Comparator.comparingInt(WordEntry::getFrequency).reversed())
                .collect(java.util.stream.Collectors.toList());
    }

    private void updateStats() {
        totalLabel.setText("Total: " + generator.getTotalCount());
        pathLabel.setText("Paths: " + generator.getCountByCategory(WordCategory.PATH));
        paramLabel.setText("Params: " + generator.getCountByCategory(WordCategory.PARAM));
        contentLabel.setText("Content: " + generator.getCountByCategory(WordCategory.CONTENT));
    }

    // ==================== Scrape History ====================

    private void scrapeHistory(JButton scrapeBtn) {
        String domain = domainField.getText().trim();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Enter a target domain first.", "No Domain", JOptionPane.WARNING_MESSAGE);
            return;
        }

        scrapeBtn.setEnabled(false);
        scrapeBtn.setText("Scraping...");

        new Thread(() -> {
            try {
                int processed = generator.scrapeHistory();
                SwingUtilities.invokeLater(() -> {
                    scrapeBtn.setText("Scrape History");
                    scrapeBtn.setEnabled(true);
                    refreshAllTabs();
                    JOptionPane.showMessageDialog(this,
                            "Scraped " + processed + " history items.\n" +
                            generator.getTotalCount() + " unique words collected.",
                            "Scrape Complete", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    scrapeBtn.setText("Scrape History");
                    scrapeBtn.setEnabled(true);
                    JOptionPane.showMessageDialog(this,
                            "Scrape failed: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "WordlistGenerator-HistoryScraper").start();
    }

    // ==================== Export / Copy ====================

    private void exportToFile() {
        WordCategory category = getSelectedTabCategory();
        int minLen = parseIntSafe(minLenField.getText(), 0);
        int maxLen = parseIntSafe(maxLenField.getText(), 0);
        List<String> words = generator.exportWords(category, minLen, maxLen,
                includeField.getText().trim(), excludeField.getText().trim(), true);

        if (words.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No words to export.", "Empty", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser();
        String prefix = category != null ? category.name().toLowerCase() : "all";
        fc.setSelectedFile(new java.io.File("wordlist_" + prefix + ".txt"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                for (String word : words) {
                    pw.println(PrivacyManager.maskForDisplay(word));
                }
                JOptionPane.showMessageDialog(this,
                        "Exported " + words.size() + " words to " + fc.getSelectedFile().getName(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copyToClipboard() {
        WordCategory category = getSelectedTabCategory();
        int minLen = parseIntSafe(minLenField.getText(), 0);
        int maxLen = parseIntSafe(maxLenField.getText(), 0);
        List<String> words = generator.exportWords(category, minLen, maxLen,
                includeField.getText().trim(), excludeField.getText().trim(), true);

        if (words.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No words to copy.", "Empty", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String text = String.join("\n", words.stream()
                .map(PrivacyManager::maskForDisplay)
                .toList());
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
        JOptionPane.showMessageDialog(this,
                "Copied " + words.size() + " words to clipboard.",
                "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private WordCategory getSelectedTabCategory() {
        int idx = tabbedPane.getSelectedIndex();
        return switch (idx) {
            case 0 -> WordCategory.PATH;
            case 1 -> WordCategory.PARAM;
            case 2 -> WordCategory.CONTENT;
            default -> null; // All Combined
        };
    }

    // ==================== Helpers ====================

    private JLabel createStatLabel(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setForeground(color);
        label.setFont(MONO_BOLD);
        return label;
    }

    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(FG_PRIMARY);
        label.setFont(MONO_SMALL);
        return label;
    }

    private static int parseIntSafe(String s, int fallback) {
        try { return Integer.parseInt(s.trim()); }
        catch (Exception e) { return fallback; }
    }

    /** Stop the auto-refresh timer. Called during extension unload. */
    public void stopTimers() {
        if (autoRefreshTimer != null) {
            autoRefreshTimer.stop();
        }
    }

    // ==================== Inner: Word Table Tab ====================

    /**
     * A single tab containing a sortable JTable of words.
     */
    private static class WordTableTab extends JPanel {
        private final DefaultTableModel tableModel;
        private final JTable table;

        private static final String[] COLUMNS = {"Word", "Frequency", "Category", "Source URL"};

        WordTableTab() {
            setLayout(new BorderLayout());
            setBackground(BG_DARK);

            tableModel = new DefaultTableModel(COLUMNS, 0) {
                @Override
                public boolean isCellEditable(int row, int col) { return false; }
            };
            table = new JTable(tableModel);
            table.setAutoCreateRowSorter(true);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            CyberTheme.styleTable(table);

            // Set column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(200); // Word
            table.getColumnModel().getColumn(1).setPreferredWidth(80);  // Frequency
            table.getColumnModel().getColumn(2).setPreferredWidth(80);  // Category
            table.getColumnModel().getColumn(3).setPreferredWidth(350); // Source URL

            JScrollPane scrollPane = new JScrollPane(table);
            CyberTheme.styleScrollPane(scrollPane);
            add(scrollPane, BorderLayout.CENTER);
        }

        void refresh(List<WordEntry> entries) {
            tableModel.setRowCount(0);
            for (WordEntry entry : entries) {
                tableModel.addRow(new Object[]{
                        PrivacyManager.maskForDisplay(entry.getWord()),
                        entry.getFrequency(),
                        entry.getCategory().getDisplayName(),
                        PrivacyManager.maskForDisplay(truncateUrl(entry.getFirstSeenUrl()))
                });
            }
        }

        private static String truncateUrl(String url) {
            if (url == null) return "";
            return url.length() > 100 ? url.substring(0, 100) + "..." : url;
        }
    }

    /** Rebuilds every word table after UI Privacy Mode changes. */
    public void refreshPrivacyDisplay() {
        refreshAllTabs();
    }
}
