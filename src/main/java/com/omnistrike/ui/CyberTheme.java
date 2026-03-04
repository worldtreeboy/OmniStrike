package com.omnistrike.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

/**
 * Centralized cyberpunk/neon theme for OmniStrike UI.
 * All panels reference these constants and helpers for a unified dark, neon-lit aesthetic.
 */
public final class CyberTheme {

    private CyberTheme() {}

    // ── Native Mode Flag ──────────────────────────────────────────────────
    // When true, all style*() methods become no-ops so components keep Burp's native L&F.
    private static volatile boolean nativeMode = true;

    /** Returns true when OmniStrike theming is disabled (Burp native L&F). */
    public static boolean isNativeMode() { return nativeMode; }

    /**
     * Enable/disable native mode. When switching TO native mode, the mutable
     * color fields (BG_DARK, NEON_CYAN, etc.) are loaded from UIManager so
     * that direct {@code setBackground(BG_DARK)} calls in constructors use
     * Burp-native colors instead of dark/neon ones.
     */
    public static void setNativeMode(boolean native_) {
        nativeMode = native_;
        if (native_) loadNativeColors();
    }

    /** Client property key used to tag hover MouseListeners added by styleButton(). */
    private static final String HOVER_LISTENER_KEY = "CyberTheme.hoverListener";

    // ── Core Backgrounds (mutable — updated by GlobalThemeManager) ─────────
    public static Color BG_DARK     = new Color(0x0D, 0x0D, 0x1A);  // near-black with blue tint
    public static Color BG_PANEL    = new Color(0x14, 0x14, 0x28);  // dark navy panel backgrounds
    public static Color BG_INPUT    = new Color(0x1A, 0x1A, 0x35);  // input fields
    public static Color BG_SURFACE  = new Color(0x1E, 0x1E, 0x3A);  // cards, elevated surfaces
    public static Color BG_HOVER    = new Color(0x25, 0x25, 0x50);  // hover/selected states
    public static Color BORDER      = new Color(0x2A, 0x2A, 0x55);  // subtle borders

    // ── Neon Accents (mutable — updated by GlobalThemeManager) ──────────
    public static Color NEON_CYAN    = new Color(0x00, 0xF0, 0xFF);  // primary accent
    public static Color NEON_MAGENTA = new Color(0xFF, 0x00, 0xAA);  // secondary accent
    public static Color NEON_GREEN   = new Color(0x00, 0xFF, 0x88);  // success, running
    public static Color NEON_ORANGE  = new Color(0xFF, 0x88, 0x00);  // warnings
    public static Color NEON_RED     = new Color(0xFF, 0x22, 0x55);  // errors, critical
    public static Color NEON_BLUE    = new Color(0x44, 0x88, 0xFF);  // info, links

    // ── Text Colors (mutable — updated by GlobalThemeManager) ───────────
    public static Color FG_PRIMARY   = new Color(0xE0, 0xE0, 0xFF);  // main text
    public static Color FG_SECONDARY = new Color(0x88, 0x88, 0xBB);  // muted text
    public static Color FG_DIM       = new Color(0x55, 0x55, 0x88);  // disabled/dim text

    // ── Severity Neon Colors (mutable — updated by GlobalThemeManager) ──
    public static Color SEV_CRITICAL = new Color(0xFF, 0x00, 0x44);  // neon red
    public static Color SEV_HIGH     = new Color(0xFF, 0x66, 0x00);  // neon orange
    public static Color SEV_MEDIUM   = new Color(0xFF, 0xCC, 0x00);  // neon yellow
    public static Color SEV_LOW      = new Color(0x00, 0xCC, 0xFF);  // neon cyan
    public static Color SEV_INFO     = new Color(0x88, 0x88, 0xBB);  // muted purple

    // ── Font ────────────────────────────────────────────────────────────────
    /** Monospace font with fallback chain: JetBrains Mono → Consolas → monospaced */
    public static final Font MONO_FONT;
    public static final Font MONO_BOLD;
    public static final Font MONO_SMALL;
    public static final Font MONO_LABEL;

    static {
        String family = pickMonoFamily();
        MONO_FONT  = new Font(family, Font.PLAIN, 12);
        MONO_BOLD  = new Font(family, Font.BOLD, 12);
        MONO_SMALL = new Font(family, Font.PLAIN, 11);
        MONO_LABEL = new Font(family, Font.BOLD, 11);
    }

    private static String pickMonoFamily() {
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        java.util.Set<String> available = new java.util.HashSet<>(
                java.util.Arrays.asList(ge.getAvailableFontFamilyNames()));
        if (available.contains("JetBrains Mono")) return "JetBrains Mono";
        if (available.contains("Consolas")) return "Consolas";
        return Font.MONOSPACED;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PALETTE LOADING — called by GlobalThemeManager
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Copies all colors from a ThemePalette into the mutable static fields.
     * After this call, all helper methods (styleButton, styleTextField, etc.)
     * automatically use the new theme's colors since they reference these fields.
     */
    static void loadPalette(ThemePalette p) {
        BG_DARK     = p.bgDark;
        BG_PANEL    = p.bgPanel;
        BG_INPUT    = p.bgInput;
        BG_SURFACE  = p.bgSurface;
        BG_HOVER    = p.bgHover;
        BORDER      = p.border;

        NEON_CYAN    = p.accentPrimary;
        NEON_MAGENTA = p.accentSecondary;
        NEON_GREEN   = p.successGreen;
        NEON_ORANGE  = p.warningOrange;
        NEON_RED     = p.errorRed;
        NEON_BLUE    = p.infoBlue;

        FG_PRIMARY   = p.fgPrimary;
        FG_SECONDARY = p.fgSecondary;
        FG_DIM       = p.fgDim;

        SEV_CRITICAL = p.sevCritical;
        SEV_HIGH     = p.sevHigh;
        SEV_MEDIUM   = p.sevMedium;
        SEV_LOW      = p.sevLow;
        SEV_INFO     = p.sevInfo;
    }

    /**
     * Loads Burp's native UIManager colors into the mutable color fields.
     * Called when entering native mode so that direct {@code setBackground(BG_DARK)}
     * calls throughout constructors use Burp-native colors instead of dark/neon ones.
     * No stripping or updateComponentTreeUI is needed — colors are simply correct
     * from the start.
     */
    private static void loadNativeColors() {
        Color bg     = uiColor("Panel.background",            0xF0F0F0);
        Color fg     = uiColor("Panel.foreground",            0x333333);
        Color inputBg = uiColor("TextField.background",       0xFFFFFF);
        Color border  = uiColor("Component.borderColor",      0xCCCCCC);
        Color sel     = uiColor("List.selectionBackground",   0x3399FF);
        Color dim     = uiColor("Label.disabledForeground",   0x999999);

        // Map all background fields to native panel background
        BG_DARK    = bg;
        BG_PANEL   = bg;
        BG_INPUT   = inputBg;
        BG_SURFACE = bg;
        BG_HOVER   = sel;
        BORDER     = border;

        // Map all accent colors to native foreground (no neon in native mode)
        NEON_CYAN    = fg;
        NEON_MAGENTA = fg;
        NEON_GREEN   = fg;
        NEON_ORANGE  = fg;
        NEON_RED     = fg;
        NEON_BLUE    = fg;

        // Text colors
        FG_PRIMARY   = fg;
        FG_SECONDARY = dim;
        FG_DIM       = dim;

        // Severity colors — all map to native foreground
        SEV_CRITICAL = fg;
        SEV_HIGH     = fg;
        SEV_MEDIUM   = fg;
        SEV_LOW      = fg;
        SEV_INFO     = dim;
    }

    /** Safe UIManager color lookup with fallback. */
    private static Color uiColor(String key, int fallbackRgb) {
        Color c = UIManager.getColor(key);
        return c != null ? c : new Color(fallbackRgb);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STYLING HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /** Apply dark background to a JPanel. */
    public static void stylePanel(JPanel panel) {
        if (nativeMode) return;
        panel.setBackground(BG_DARK);
        panel.setForeground(FG_PRIMARY);
    }

    /** Apply dark background and neon foreground to any component. */
    public static void styleDark(JComponent comp) {
        if (nativeMode) return;
        comp.setBackground(BG_DARK);
        comp.setForeground(FG_PRIMARY);
        comp.setOpaque(true);
    }

    /** Style a button with a neon border and text color. Pass null for default neon cyan. */
    public static void styleButton(JButton btn, Color neonColor) {
        if (nativeMode) return;
        Color neon = neonColor != null ? neonColor : NEON_CYAN;
        btn.setBackground(BG_PANEL);
        btn.setForeground(neon);
        btn.setFocusPainted(false);
        btn.setFont(MONO_FONT);
        btn.setBorder(BorderFactory.createCompoundBorder(
                new GlowLineBorder(neon, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setOpaque(true);

        // Remove previous hover listener if present (prevents accumulation on theme switch)
        MouseListener old = (MouseListener) btn.getClientProperty(HOVER_LISTENER_KEY);
        if (old != null) btn.removeMouseListener(old);

        // Hover glow effect
        MouseAdapter hoverListener = new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (nativeMode) return;
                btn.setBackground(BG_HOVER);
                btn.setBorder(BorderFactory.createCompoundBorder(
                        new GlowLineBorder(neon, 2),
                        BorderFactory.createEmptyBorder(3, 11, 3, 11)));
            }
            @Override
            public void mouseExited(MouseEvent e) {
                if (nativeMode) return;
                btn.setBackground(BG_PANEL);
                btn.setBorder(BorderFactory.createCompoundBorder(
                        new GlowLineBorder(neon, 1),
                        BorderFactory.createEmptyBorder(4, 12, 4, 12)));
            }
        };
        btn.putClientProperty(HOVER_LISTENER_KEY, hoverListener);
        btn.addMouseListener(hoverListener);
    }

    /** Style a filled button (solid neon background). */
    public static void styleFilledButton(JButton btn, Color neonColor) {
        if (nativeMode) return;
        Color neon = neonColor != null ? neonColor : NEON_CYAN;
        btn.setBackground(neon);
        btn.setForeground(BG_DARK);
        btn.setFocusPainted(false);
        btn.setFont(MONO_BOLD);
        btn.setBorder(BorderFactory.createEmptyBorder(5, 14, 5, 14));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setOpaque(true);
    }

    /** Style a text field with dark input bg, neon cyan caret, light text. */
    public static void styleTextField(JTextField field) {
        if (nativeMode) return;
        field.setBackground(BG_INPUT);
        field.setForeground(FG_PRIMARY);
        field.setCaretColor(NEON_CYAN);
        field.setFont(MONO_FONT);
        field.setBorder(BorderFactory.createCompoundBorder(
                new GlowLineBorder(BORDER, 1),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        field.setSelectionColor(BG_HOVER);
        field.setSelectedTextColor(NEON_CYAN);
    }

    /** Style a password field. */
    public static void stylePasswordField(JPasswordField field) {
        if (nativeMode) return;
        field.setBackground(BG_INPUT);
        field.setForeground(FG_PRIMARY);
        field.setCaretColor(NEON_CYAN);
        field.setFont(MONO_FONT);
        field.setBorder(BorderFactory.createCompoundBorder(
                new GlowLineBorder(BORDER, 1),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        field.setSelectionColor(BG_HOVER);
        field.setSelectedTextColor(NEON_CYAN);
    }

    /** Style a text area. */
    public static void styleTextArea(JTextArea area) {
        if (nativeMode) return;
        area.setBackground(BG_INPUT);
        area.setForeground(FG_PRIMARY);
        area.setCaretColor(NEON_CYAN);
        area.setFont(MONO_FONT);
        area.setSelectionColor(BG_HOVER);
        area.setSelectedTextColor(NEON_CYAN);
    }

    /** Style a combo box. */
    public static void styleComboBox(JComboBox<?> combo) {
        if (nativeMode) return;
        combo.setBackground(BG_INPUT);
        combo.setForeground(FG_PRIMARY);
        combo.setFont(MONO_FONT);
        combo.setBorder(new GlowLineBorder(BORDER, 1));
        // Style the renderer for dropdown items
        combo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (nativeMode) return this;
                if (isSelected) {
                    setBackground(BG_HOVER);
                    setForeground(NEON_CYAN);
                } else {
                    setBackground(BG_INPUT);
                    setForeground(FG_PRIMARY);
                }
                setFont(MONO_FONT);
                setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
                return this;
            }
        });
    }

    /** Style a checkbox with neon coloring. */
    public static void styleCheckBox(JCheckBox cb) {
        if (nativeMode) return;
        cb.setBackground(BG_DARK);
        cb.setForeground(FG_PRIMARY);
        cb.setFont(MONO_FONT);
        cb.setFocusPainted(false);
    }

    /** Style a radio button with neon coloring. */
    public static void styleRadioButton(JRadioButton rb) {
        if (nativeMode) return;
        rb.setBackground(BG_DARK);
        rb.setForeground(FG_PRIMARY);
        rb.setFont(MONO_FONT);
        rb.setFocusPainted(false);
    }

    /** Style a JTable with dark rows, neon selection, custom header. */
    public static void styleTable(JTable table) {
        if (nativeMode) return;
        table.setBackground(BG_PANEL);
        table.setForeground(FG_PRIMARY);
        table.setSelectionBackground(BG_HOVER);
        table.setSelectionForeground(NEON_CYAN);
        table.setGridColor(BORDER);
        table.setFont(MONO_FONT);
        table.setRowHeight(24);
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(1, 1));

        // Style table header
        JTableHeader header = table.getTableHeader();
        header.setBackground(BG_SURFACE);
        header.setForeground(NEON_CYAN);
        header.setFont(MONO_BOLD);
        header.setBorder(new GlowMatteBorder(0, 0, 2, 0, NEON_CYAN));
        header.setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (nativeMode) return this;
                setBackground(BG_SURFACE);
                setForeground(NEON_CYAN);
                setFont(MONO_BOLD);
                setHorizontalAlignment(SwingConstants.LEFT);
                setBorder(BorderFactory.createCompoundBorder(
                        new GlowMatteBorder(0, 0, 2, 1, BORDER),
                        BorderFactory.createEmptyBorder(4, 6, 4, 6)));
                return this;
            }
        });

        // Alternating row colors via a default renderer
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (nativeMode) return this;
                if (isSelected) {
                    setBackground(BG_HOVER);
                    setForeground(NEON_CYAN);
                } else {
                    setBackground(row % 2 == 0 ? BG_PANEL : BG_SURFACE);
                    setForeground(FG_PRIMARY);
                }
                setFont(MONO_FONT);
                setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
                return this;
            }
        });
    }

    /** Style a scroll pane with dark scrollbars. */
    public static void styleScrollPane(JScrollPane sp) {
        if (nativeMode) return;
        sp.setBackground(BG_DARK);
        sp.getViewport().setBackground(BG_DARK);
        sp.setBorder(new GlowLineBorder(BORDER, 1));

        styleScrollBar(sp.getVerticalScrollBar());
        styleScrollBar(sp.getHorizontalScrollBar());
    }

    /** Style a single scrollbar with dark track and neon thumb. */
    private static void styleScrollBar(JScrollBar scrollBar) {
        scrollBar.setBackground(BG_DARK);
        scrollBar.setUI(new BasicScrollBarUI() {
            @Override
            protected void configureScrollBarColors() {
                this.thumbColor = BORDER;
                this.thumbHighlightColor = NEON_CYAN;
                this.trackColor = BG_DARK;
            }
            @Override
            protected JButton createDecreaseButton(int orientation) {
                return createZeroButton();
            }
            @Override
            protected JButton createIncreaseButton(int orientation) {
                return createZeroButton();
            }
            private JButton createZeroButton() {
                JButton btn = new JButton();
                btn.setPreferredSize(new Dimension(0, 0));
                btn.setMinimumSize(new Dimension(0, 0));
                btn.setMaximumSize(new Dimension(0, 0));
                return btn;
            }
        });
    }

    /** Style a tabbed pane with dark tabs and neon selected indicator. */
    public static void styleTabbedPane(JTabbedPane tp) {
        if (nativeMode) return;
        tp.setBackground(BG_DARK);
        tp.setForeground(FG_SECONDARY);
        tp.setFont(MONO_BOLD);
        tp.setOpaque(true);
    }

    /** Style a split pane with dark dividers. */
    public static void styleSplitPane(JSplitPane sp) {
        if (nativeMode) return;
        sp.setBackground(BG_DARK);
        sp.setBorder(null);
        sp.setDividerSize(4);
        // Set divider color
        if (sp.getUI() instanceof javax.swing.plaf.basic.BasicSplitPaneUI basicUI) {
            basicUI.getDivider().setBackground(BORDER);
            basicUI.getDivider().setBorder(null);
        }
    }

    /** Style a label as a neon heading. */
    public static void styleHeading(JLabel label) {
        if (nativeMode) return;
        label.setForeground(NEON_CYAN);
        label.setFont(MONO_BOLD.deriveFont(14f));
    }

    /** Style a label as primary text. */
    public static void styleLabel(JLabel label) {
        if (nativeMode) return;
        label.setForeground(FG_PRIMARY);
        label.setFont(MONO_FONT);
    }

    /** Style a label as secondary/muted text. */
    public static void styleMuted(JLabel label) {
        if (nativeMode) return;
        label.setForeground(FG_SECONDARY);
        label.setFont(MONO_SMALL);
    }

    /** Style a progress bar. */
    public static void styleProgressBar(JProgressBar pb) {
        if (nativeMode) return;
        pb.setBackground(BG_INPUT);
        pb.setForeground(NEON_CYAN);
        pb.setBorder(new GlowLineBorder(BORDER, 1));
        pb.setFont(MONO_SMALL);
    }

    // ── Neon Border Factory ─────────────────────────────────────────────────

    /** Creates a line border with a neon color. */
    public static Border createNeonBorder(Color neonColor) {
        return new GlowLineBorder(neonColor, 1);
    }

    /** Creates a compound neon border with inner padding. */
    public static Border createNeonBorderPadded(Color neonColor, int top, int left, int bottom, int right) {
        return BorderFactory.createCompoundBorder(
                new GlowLineBorder(neonColor, 1),
                BorderFactory.createEmptyBorder(top, left, bottom, right));
    }

    // ── Severity Helpers ────────────────────────────────────────────────────

    /** Returns the neon color for a severity string. */
    public static Color severityColor(String severity) {
        if (severity == null) return FG_DIM;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SEV_CRITICAL;
            case "HIGH"     -> SEV_HIGH;
            case "MEDIUM"   -> SEV_MEDIUM;
            case "LOW"      -> SEV_LOW;
            case "INFO"     -> SEV_INFO;
            default         -> FG_DIM;
        };
    }

    /** Creates a shared neon severity cell renderer for JTables. */
    public static DefaultTableCellRenderer createSeverityRenderer() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (nativeMode) return this;
                if (isSelected) {
                    setBackground(BG_HOVER);
                    setForeground(NEON_CYAN);
                } else if (value != null) {
                    String sev = value.toString();
                    Color neon = severityColor(sev);
                    setBackground(darken(neon, 0.25f));
                    setForeground(neon);
                } else {
                    setBackground(BG_PANEL);
                    setForeground(FG_PRIMARY);
                }
                setHorizontalAlignment(SwingConstants.CENTER);
                setFont(MONO_BOLD);
                setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
                return this;
            }
        };
    }

    /** Creates a severity badge label with a neon look. */
    public static JLabel createSeverityBadge(String text, Color neonColor) {
        JLabel label = new JLabel(text);
        if (nativeMode) return label;
        label.setOpaque(true);
        label.setBackground(darken(neonColor, 0.2f));
        label.setForeground(neonColor);
        label.setFont(MONO_BOLD.deriveFont(11f));
        label.setBorder(BorderFactory.createCompoundBorder(
                new GlowLineBorder(neonColor, 1),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        return label;
    }

    /** Style a titled border with neon color. */
    public static void styleTitledBorder(JComponent comp, String title, Color neonColor) {
        if (nativeMode) return;
        Color neon = neonColor != null ? neonColor : NEON_CYAN;
        comp.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                        new GlowLineBorder(neon, 1),
                        title,
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        MONO_BOLD,
                        neon),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));
    }

    // ── Color Utilities ─────────────────────────────────────────────────────

    /** Darken a color by mixing it with BG_DARK at the given ratio. */
    public static Color darken(Color c, float ratio) {
        int r = (int) (c.getRed() * ratio);
        int g = (int) (c.getGreen() * ratio);
        int b = (int) (c.getBlue() * ratio);
        return new Color(
                Math.max(BG_DARK.getRed(), Math.min(255, r)),
                Math.max(BG_DARK.getGreen(), Math.min(255, g)),
                Math.max(BG_DARK.getBlue(), Math.min(255, b)));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  GLOW BORDER CLASSES — animated borders for breathing effect
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * A LineBorder that dynamically tints toward the theme accent color
     * based on the current breathing phase. When breathing is off,
     * renders identically to a normal LineBorder. Only the border line
     * is affected — backgrounds and text stay untouched.
     */
    public static class GlowLineBorder extends javax.swing.border.LineBorder {
        private final Color baseColor;

        public GlowLineBorder(Color baseColor, int thickness) {
            super(baseColor, thickness);
            this.baseColor = baseColor;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Color original = this.lineColor;
            this.lineColor = computeGlowColor();
            super.paintBorder(c, g, x, y, width, height);
            this.lineColor = original;
        }

        @Override
        public Color getLineColor() {
            return computeGlowColor();
        }

        private Color computeGlowColor() {
            if (nativeMode) return baseColor;
            float amount = GlobalThemeManager.getBreathAmount();
            if (amount <= 0f) return baseColor;
            Color accent = getAccentColor();
            Color glowTarget = lerpColor(accent, Color.WHITE, 0.35f);
            return lerpColor(baseColor, glowTarget, amount);
        }
    }

    /**
     * A MatteBorder that dynamically tints toward the theme accent color
     * based on the current breathing phase. When breathing is off,
     * renders identically to a normal MatteBorder. Only the border area
     * is affected — backgrounds and text stay untouched.
     */
    public static class GlowMatteBorder extends javax.swing.border.MatteBorder {
        private final Color baseColor;

        public GlowMatteBorder(int top, int left, int bottom, int right, Color baseColor) {
            super(top, left, bottom, right, baseColor);
            this.baseColor = baseColor;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Color original = this.color;
            this.color = computeGlowColor();
            super.paintBorder(c, g, x, y, width, height);
            this.color = original;
        }

        private Color computeGlowColor() {
            if (nativeMode) return baseColor;
            float amount = GlobalThemeManager.getBreathAmount();
            if (amount <= 0f) return baseColor;
            Color accent = getAccentColor();
            Color glowTarget = lerpColor(accent, Color.WHITE, 0.35f);
            return lerpColor(baseColor, glowTarget, amount);
        }
    }

    /** Returns the current theme accent color, defaulting to cyan. */
    private static Color getAccentColor() {
        ThemePalette palette = GlobalThemeManager.getCurrentPalette();
        return palette != null ? palette.accentPrimary : new Color(0x00, 0xFF, 0xFF);
    }

    /** Linearly interpolates between two colors. */
    private static Color lerpColor(Color a, Color b, float t) {
        int r = (int)(a.getRed() + (b.getRed() - a.getRed()) * t);
        int gr = (int)(a.getGreen() + (b.getGreen() - a.getGreen()) * t);
        int bl = (int)(a.getBlue() + (b.getBlue() - a.getBlue()) * t);
        return new Color(clamp(r), clamp(gr), clamp(bl));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }

    /** Apply the cyberpunk theme recursively to all children of a container. */
    public static void applyRecursive(Container container) {
        if (nativeMode) return;
        container.setBackground(BG_DARK);
        if (container instanceof JComponent jc) {
            jc.setForeground(FG_PRIMARY);
        }
        for (Component child : container.getComponents()) {
            // Order matters: check subclasses before superclasses
            if (child instanceof JCheckBox chk) {
                styleCheckBox(chk);
            } else if (child instanceof JRadioButton rb) {
                styleRadioButton(rb);
            } else if (child instanceof JToggleButton tb) {
                // JToggleButton that isn't JCheckBox/JRadioButton (e.g. start/stop)
                tb.setBackground(BG_PANEL);
                tb.setForeground(FG_PRIMARY);
            } else if (child instanceof JButton b) {
                styleButton(b, null);
            } else if (child instanceof JPasswordField pf) {
                stylePasswordField(pf);
            } else if (child instanceof JTextField tf) {
                styleTextField(tf);
            } else if (child instanceof JTextArea ta) {
                styleTextArea(ta);
            } else if (child instanceof JComboBox<?> cb) {
                styleComboBox(cb);
            } else if (child instanceof JProgressBar pb) {
                styleProgressBar(pb);
            } else if (child instanceof JLabel l) {
                l.setForeground(FG_PRIMARY);
                l.setFont(MONO_FONT);
            } else if (child instanceof JScrollPane sp) {
                styleScrollPane(sp);
                if (sp.getViewport() != null) {
                    applyRecursive(sp.getViewport());
                }
            } else if (child instanceof JTabbedPane tp) {
                styleTabbedPane(tp);
                // Recurse into tabbed pane children
                for (int i = 0; i < tp.getTabCount(); i++) {
                    Component tabComp = tp.getComponentAt(i);
                    if (tabComp instanceof Container tc) {
                        applyRecursive(tc);
                    }
                }
            } else if (child instanceof JSplitPane sp) {
                styleSplitPane(sp);
                applyRecursive(sp);
            } else if (child instanceof JPanel p) {
                stylePanel(p);
                applyRecursive(p);
            } else if (child instanceof Container c) {
                applyRecursive(c);
            }
        }
    }

    /**
     * Strips all OmniStrike custom styling from a container tree, restoring
     * Swing's default L&F delegates. Call after setting nativeMode=true.
     * First nullifies explicit bg/fg so L&F defaults can take over, then
     * reinstalls delegates, then cleans up custom renderers and listeners.
     */
    public static void stripRecursive(Container container) {
        // 1. Null out explicit bg/fg on every component so updateComponentTreeUI
        //    can reinstall L&F defaults (Swing skips properties set explicitly)
        resetColorsRecursive(container);

        // 2. Reinstall L&F delegates for the entire tree
        SwingUtilities.updateComponentTreeUI(container);

        // 3. Walk tree to clean up things updateComponentTreeUI can't handle
        stripWalk(container);

        container.revalidate();
        container.repaint();
    }

    /**
     * Recursively set background/foreground to null so L&F defaults take over.
     * Only touches bg/fg — borders and fonts are left alone to avoid breaking
     * FlatLaf rendering and hit-testing.
     */
    static void resetColorsRecursive(Component comp) {
        if (comp instanceof JComponent jc) {
            jc.setBackground(null);
            jc.setForeground(null);
        }
        if (comp instanceof Container container) {
            for (Component child : container.getComponents()) {
                resetColorsRecursive(child);
            }
            if (comp instanceof JScrollPane sp) {
                if (sp.getViewport() != null) {
                    sp.getViewport().setBackground(null);
                    sp.getViewport().setForeground(null);
                    Component view = sp.getViewport().getView();
                    if (view != null) resetColorsRecursive(view);
                }
                resetColorsRecursive(sp.getVerticalScrollBar());
                resetColorsRecursive(sp.getHorizontalScrollBar());
            }
            if (comp instanceof JTabbedPane tp) {
                for (int i = 0; i < tp.getTabCount(); i++) {
                    Component tabComp = tp.getComponentAt(i);
                    if (tabComp != null) resetColorsRecursive(tabComp);
                }
            }
        }
    }

    static void stripWalk(Component comp) {
        // Reset JTable custom renderers
        if (comp instanceof JTable table) {
            table.setDefaultRenderer(Object.class, null);
            JTableHeader header = table.getTableHeader();
            if (header != null) header.setDefaultRenderer(null);
        }

        // Reset JComboBox custom renderer
        if (comp instanceof JComboBox<?> combo) {
            combo.setRenderer(new DefaultListCellRenderer());
        }

        // Remove tagged hover listeners from JButtons
        if (comp instanceof JButton btn) {
            MouseListener hover = (MouseListener) btn.getClientProperty(HOVER_LISTENER_KEY);
            if (hover != null) {
                btn.removeMouseListener(hover);
                btn.putClientProperty(HOVER_LISTENER_KEY, null);
            }
        }

        // Restore native scrollbar UI
        if (comp instanceof JScrollBar scrollBar) {
            scrollBar.updateUI();
        }

        // Recurse into containers
        if (comp instanceof Container container) {
            if (comp instanceof JScrollPane sp) {
                if (sp.getViewport() != null) {
                    Component view = sp.getViewport().getView();
                    if (view != null) stripWalk(view);
                }
                stripWalk(sp.getVerticalScrollBar());
                stripWalk(sp.getHorizontalScrollBar());
            }
            if (comp instanceof JTabbedPane tp) {
                for (int i = 0; i < tp.getTabCount(); i++) {
                    Component tabComp = tp.getComponentAt(i);
                    if (tabComp != null) stripWalk(tabComp);
                }
            }
            for (Component child : container.getComponents()) {
                stripWalk(child);
            }
        }
    }
}
