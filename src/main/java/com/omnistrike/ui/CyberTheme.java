package com.omnistrike.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.plaf.basic.BasicButtonUI;
import javax.swing.plaf.basic.BasicTabbedPaneUI;
import javax.swing.plaf.UIResource;
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
    private static final String BUTTON_ACCENT_KEY = "OmniStrike.buttonAccent";
    private static final String BUTTON_FILLED_KEY = "OmniStrike.buttonFilled";
    private static final String TITLED_NAME_KEY = "OmniStrike.titledName";
    private static final String TITLED_ACCENT_KEY = "OmniStrike.titledAccent";
    private static final String HTTP_MESSAGE_AREA_KEY = "OmniStrike.httpMessageArea";
    private static final double BODY_TEXT_MIN_CONTRAST = 7.0;

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
    public static final Font UI_FONT;
    public static final Font UI_BOLD;
    public static final Font UI_SMALL;
    public static final Font UI_TITLE;

    static {
        String family = pickMonoFamily();
        MONO_FONT  = new Font(family, Font.PLAIN, 12);
        MONO_BOLD  = new Font(family, Font.BOLD, 12);
        MONO_SMALL = new Font(family, Font.PLAIN, 11);
        MONO_LABEL = new Font(family, Font.BOLD, 11);
        String uiFamily = pickUiFamily();
        UI_FONT  = new Font(uiFamily, Font.PLAIN, 13);
        UI_BOLD  = new Font(uiFamily, Font.BOLD, 13);
        UI_SMALL = new Font(uiFamily, Font.PLAIN, 12);
        UI_TITLE = new Font(uiFamily, Font.BOLD, 22);
    }

    private static String pickMonoFamily() {
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        java.util.Set<String> available = new java.util.HashSet<>(
                java.util.Arrays.asList(ge.getAvailableFontFamilyNames()));
        if (available.contains("JetBrains Mono")) return "JetBrains Mono";
        if (available.contains("Consolas")) return "Consolas";
        return Font.MONOSPACED;
    }

    private static String pickUiFamily() {
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        java.util.Set<String> available = new java.util.HashSet<>(
                java.util.Arrays.asList(ge.getAvailableFontFamilyNames()));
        for (String candidate : new String[]{"Inter", "Segoe UI Variable Text", "Segoe UI", "Arial"}) {
            if (available.contains(candidate)) return candidate;
        }
        return Font.SANS_SERIF;
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
        Object titledName = panel.getClientProperty(TITLED_NAME_KEY);
        if (titledName instanceof String title) {
            Object accent = panel.getClientProperty(TITLED_ACCENT_KEY);
            styleTitledBorder(panel, title, accent instanceof Color c ? c : NEON_CYAN);
            panel.setBackground(BG_DARK);
            panel.setForeground(FG_PRIMARY);
            return;
        }
        if (Boolean.TRUE.equals(panel.getClientProperty("OmniStrike.card"))) {
            styleCard(panel);
            return;
        }
        panel.setBackground(BG_DARK);
        panel.setForeground(FG_PRIMARY);
    }

    /** Gives a panel an elevated card surface with comfortable interior spacing. */
    public static void styleCard(JPanel panel) {
        panel.putClientProperty("OmniStrike.card", Boolean.TRUE);
        if (nativeMode) return;
        panel.setBackground(BG_PANEL);
        panel.setForeground(FG_PRIMARY);
        panel.setBorder(BorderFactory.createCompoundBorder(
                new RoundedLineBorder(BORDER, 1, 14),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
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
        Object savedAccent = btn.getClientProperty(BUTTON_ACCENT_KEY);
        Color neon = neonColor != null ? neonColor
                : savedAccent instanceof Color c ? c : NEON_CYAN;
        btn.putClientProperty(BUTTON_ACCENT_KEY, neon);
        btn.putClientProperty(BUTTON_FILLED_KEY, Boolean.FALSE);
        btn.setBackground(BG_PANEL);
        btn.setForeground(neon);
        btn.setFocusPainted(false);
        btn.setFont(UI_BOLD);
        btn.setBorder(BorderFactory.createCompoundBorder(
                new RoundedLineBorder(neon, 1, 10),
                BorderFactory.createEmptyBorder(6, 14, 6, 14)));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setRolloverEnabled(true);
        btn.setUI(new ModernButtonUI(neon, false));

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
                        new RoundedLineBorder(neon, 2, 10),
                        BorderFactory.createEmptyBorder(5, 13, 5, 13)));
            }
            @Override
            public void mouseExited(MouseEvent e) {
                if (nativeMode) return;
                btn.setBackground(BG_PANEL);
                btn.setBorder(BorderFactory.createCompoundBorder(
                        new RoundedLineBorder(neon, 1, 10),
                        BorderFactory.createEmptyBorder(6, 14, 6, 14)));
            }
        };
        btn.putClientProperty(HOVER_LISTENER_KEY, hoverListener);
        btn.addMouseListener(hoverListener);
    }

    /** Style a filled button (solid neon background). */
    public static void styleFilledButton(JButton btn, Color neonColor) {
        if (nativeMode) return;
        Color neon = neonColor != null ? neonColor : NEON_CYAN;
        btn.putClientProperty(BUTTON_ACCENT_KEY, neon);
        btn.putClientProperty(BUTTON_FILLED_KEY, Boolean.TRUE);
        btn.setBackground(neon);
        btn.setForeground(BG_DARK);
        btn.setFocusPainted(false);
        btn.setFont(UI_BOLD);
        btn.setBorder(BorderFactory.createCompoundBorder(
                new RoundedLineBorder(neon, 1, 10),
                BorderFactory.createEmptyBorder(6, 16, 6, 16)));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setRolloverEnabled(true);
        btn.setUI(new ModernButtonUI(neon, true));
    }

    /** Style a text field with dark input bg, neon cyan caret, light text. */
    public static void styleTextField(JTextField field) {
        if (nativeMode) return;
        field.setBackground(BG_INPUT);
        field.setForeground(FG_PRIMARY);
        field.setCaretColor(NEON_CYAN);
        field.setFont(UI_FONT);
        field.setBorder(BorderFactory.createCompoundBorder(
                new RoundedLineBorder(BORDER, 1, 9),
                BorderFactory.createEmptyBorder(6, 9, 6, 9)));
        field.setSelectionColor(BG_HOVER);
        field.setSelectedTextColor(NEON_CYAN);
    }

    /** Style a password field. */
    public static void stylePasswordField(JPasswordField field) {
        if (nativeMode) return;
        field.setBackground(BG_INPUT);
        field.setForeground(FG_PRIMARY);
        field.setCaretColor(NEON_CYAN);
        field.setFont(UI_FONT);
        field.setBorder(BorderFactory.createCompoundBorder(
                new RoundedLineBorder(BORDER, 1, 9),
                BorderFactory.createEmptyBorder(6, 9, 6, 9)));
        field.setSelectionColor(BG_HOVER);
        field.setSelectedTextColor(NEON_CYAN);
    }

    /** Style a text area. */
    public static void styleTextArea(JTextArea area) {
        if (Boolean.TRUE.equals(area.getClientProperty(HTTP_MESSAGE_AREA_KEY))) {
            styleHttpMessageArea(area);
            return;
        }
        if (nativeMode) return;
        area.setBackground(BG_INPUT);
        area.setForeground(ensureContrast(FG_PRIMARY, BG_INPUT, BODY_TEXT_MIN_CONTRAST));
        area.setCaretColor(NEON_CYAN);
        area.setFont(MONO_FONT);
        area.setSelectionColor(BG_HOVER);
        area.setSelectedTextColor(ensureContrast(FG_PRIMARY, BG_HOVER, BODY_TEXT_MIN_CONTRAST));
    }

    /**
     * Style request/response and evidence viewers for long-form readability.
     * The client property lets palette changes retain this stronger treatment
     * instead of downgrading the viewer through the generic recursive styler.
     */
    public static void styleHttpMessageArea(JTextArea area) {
        area.putClientProperty(HTTP_MESSAGE_AREA_KEY, Boolean.TRUE);
        if (nativeMode) return;
        area.setBackground(BG_INPUT);
        area.setForeground(ensureContrast(FG_PRIMARY, BG_INPUT, BODY_TEXT_MIN_CONTRAST));
        area.setCaretColor(NEON_CYAN);
        area.setSelectionColor(BG_HOVER);
        area.setSelectedTextColor(ensureContrast(FG_PRIMARY, BG_HOVER, BODY_TEXT_MIN_CONTRAST));
        area.setFont(MONO_FONT.deriveFont(13f));
        area.setMargin(new Insets(9, 10, 9, 10));
    }

    /** Returns a color meeting the requested WCAG contrast ratio against background. */
    static Color ensureContrast(Color preferred, Color background, double minimumRatio) {
        if (preferred == null || background == null || contrastRatio(preferred, background) >= minimumRatio) {
            return preferred;
        }

        Color target = relativeLuminance(background) < 0.5 ? Color.WHITE : Color.BLACK;
        for (int step = 1; step <= 20; step++) {
            float amount = step / 20.0f;
            Color candidate = blend(preferred, target, amount);
            if (contrastRatio(candidate, background) >= minimumRatio) {
                return candidate;
            }
        }
        return target;
    }

    static double contrastRatio(Color first, Color second) {
        double firstLuminance = relativeLuminance(first);
        double secondLuminance = relativeLuminance(second);
        double lighter = Math.max(firstLuminance, secondLuminance);
        double darker = Math.min(firstLuminance, secondLuminance);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double relativeLuminance(Color color) {
        return 0.2126 * linearChannel(color.getRed())
                + 0.7152 * linearChannel(color.getGreen())
                + 0.0722 * linearChannel(color.getBlue());
    }

    private static double linearChannel(int channel) {
        double normalized = channel / 255.0;
        return normalized <= 0.04045
                ? normalized / 12.92
                : Math.pow((normalized + 0.055) / 1.055, 2.4);
    }

    private static Color blend(Color from, Color to, float amount) {
        float inverse = 1.0f - amount;
        return new Color(
                Math.round(from.getRed() * inverse + to.getRed() * amount),
                Math.round(from.getGreen() * inverse + to.getGreen() * amount),
                Math.round(from.getBlue() * inverse + to.getBlue() * amount));
    }

    /** Style a combo box. */
    public static void styleComboBox(JComboBox<?> combo) {
        if (nativeMode) return;
        combo.setBackground(BG_INPUT);
        combo.setForeground(FG_PRIMARY);
        combo.setFont(UI_FONT);
        combo.setBorder(new RoundedLineBorder(BORDER, 1, 9));
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
                setFont(UI_FONT);
                setBorder(BorderFactory.createEmptyBorder(6, 9, 6, 9));
                return this;
            }
        });
    }

    /** Style a checkbox with neon coloring. */
    public static void styleCheckBox(JCheckBox cb) {
        if (nativeMode) return;
        cb.setBackground(BG_DARK);
        cb.setForeground(FG_PRIMARY);
        cb.setFont(UI_FONT);
        cb.setFocusPainted(false);
        cb.setOpaque(false);
    }

    /** Style a radio button with neon coloring. */
    public static void styleRadioButton(JRadioButton rb) {
        if (nativeMode) return;
        rb.setBackground(BG_DARK);
        rb.setForeground(FG_PRIMARY);
        rb.setFont(UI_FONT);
        rb.setFocusPainted(false);
        rb.setOpaque(false);
    }

    /** Style a JTable with dark rows, neon selection, custom header. */
    public static void styleTable(JTable table) {
        if (nativeMode) return;
        table.setBackground(BG_PANEL);
        table.setForeground(FG_PRIMARY);
        table.setSelectionBackground(BG_HOVER);
        table.setSelectionForeground(NEON_CYAN);
        table.setGridColor(BORDER);
        table.setFont(UI_FONT);
        table.setRowHeight(30);
        table.setShowGrid(false);
        table.setShowHorizontalLines(true);
        table.setGridColor(BORDER);
        table.setIntercellSpacing(new Dimension(0, 0));

        // Style table header
        JTableHeader header = table.getTableHeader();
        header.setBackground(BG_SURFACE);
        header.setForeground(NEON_CYAN);
        header.setFont(UI_BOLD);
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 34));
        header.setBorder(new GlowMatteBorder(0, 0, 1, 0, BORDER));
        header.setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (nativeMode) return this;
                setBackground(BG_SURFACE);
                setForeground(NEON_CYAN);
                setFont(UI_BOLD);
                setHorizontalAlignment(SwingConstants.LEFT);
                setBorder(BorderFactory.createCompoundBorder(
                        new GlowMatteBorder(0, 0, 1, 0, BORDER),
                        BorderFactory.createEmptyBorder(7, 10, 7, 10)));
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
                setFont(UI_FONT);
                setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
                return this;
            }
        });
    }

    /** Style a scroll pane with dark scrollbars. */
    public static void styleScrollPane(JScrollPane sp) {
        if (nativeMode) return;
        sp.setBackground(BG_DARK);
        sp.getViewport().setBackground(BG_DARK);
        sp.setBorder(new RoundedLineBorder(BORDER, 1, 10));

        styleScrollBar(sp.getVerticalScrollBar());
        styleScrollBar(sp.getHorizontalScrollBar());
    }

    /** Style a single scrollbar with dark track and neon thumb. */
    private static void styleScrollBar(JScrollBar scrollBar) {
        scrollBar.setBackground(BG_DARK);
        scrollBar.setPreferredSize(new Dimension(10, 10));
        scrollBar.setUI(new BasicScrollBarUI() {
            @Override
            protected void configureScrollBarColors() {
                this.thumbColor = BORDER;
                this.thumbHighlightColor = NEON_CYAN;
                this.trackColor = BG_DARK;
            }
            @Override
            protected void paintThumb(Graphics g, JComponent c, Rectangle thumbBounds) {
                if (thumbBounds.isEmpty() || !scrollbar.isEnabled()) return;
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(isDragging ? NEON_CYAN : BORDER);
                g2.fillRoundRect(thumbBounds.x + 2, thumbBounds.y + 2,
                        Math.max(2, thumbBounds.width - 4), Math.max(2, thumbBounds.height - 4),
                        8, 8);
                g2.dispose();
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
        tp.setFont(UI_BOLD);
        tp.setOpaque(true);
        tp.setUI(new ModernTabbedPaneUI());
    }

    /** Style a split pane with dark dividers. */
    public static void styleSplitPane(JSplitPane sp) {
        if (nativeMode) return;
        sp.setBackground(BG_DARK);
        sp.setBorder(null);
        sp.setDividerSize(8);
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
        label.setFont(UI_BOLD.deriveFont(16f));
    }

    /** Style a label as primary text. */
    public static void styleLabel(JLabel label) {
        if (nativeMode) return;
        label.setForeground(FG_PRIMARY);
        label.setFont(UI_FONT);
    }

    /** Style a label as secondary/muted text. */
    public static void styleMuted(JLabel label) {
        if (nativeMode) return;
        label.setForeground(FG_SECONDARY);
        label.setFont(UI_SMALL);
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
                new RoundedLineBorder(neonColor, 1, 12),
                BorderFactory.createEmptyBorder(3, 9, 3, 9)));
        return label;
    }

    /** Style a titled border with neon color. */
    public static void styleTitledBorder(JComponent comp, String title, Color neonColor) {
        comp.putClientProperty(TITLED_NAME_KEY, title);
        comp.putClientProperty(TITLED_ACCENT_KEY, neonColor);
        if (nativeMode) return;
        Color neon = neonColor != null ? neonColor : NEON_CYAN;
        comp.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                        new RoundedLineBorder(BORDER, 1, 12),
                        title,
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        MONO_BOLD,
                        neon),
                BorderFactory.createEmptyBorder(8, 10, 10, 10)));
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

    /**
     * Rounded border used by cards and controls. It intentionally stays subtle;
     * semantic accent colors are reserved for selection and status.
     */
    public static class RoundedLineBorder extends javax.swing.border.AbstractBorder {
        private final Color color;
        private final int thickness;
        private final int radius;

        public RoundedLineBorder(Color color, int thickness, int radius) {
            this.color = color;
            this.thickness = Math.max(1, thickness);
            this.radius = Math.max(4, radius);
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(thickness, thickness, thickness, thickness);
        }

        @Override
        public Insets getBorderInsets(Component c, Insets insets) {
            insets.set(thickness, thickness, thickness, thickness);
            return insets;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.setStroke(new BasicStroke(thickness));
            int inset = Math.max(1, thickness / 2);
            g2.drawRoundRect(x + inset, y + inset,
                    Math.max(0, width - thickness - 1),
                    Math.max(0, height - thickness - 1), radius, radius);
            g2.dispose();
        }
    }

    /** Branded, low-noise gradient surface for the application header. */
    public static class HeroPanel extends JPanel {
        public HeroPanel() {
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            if (nativeMode) {
                super.paintComponent(g);
                return;
            }
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();
            int h = getHeight();
            g2.setPaint(new GradientPaint(0, 0, BG_SURFACE, w, h, BG_PANEL));
            g2.fillRoundRect(0, 0, w, h, 18, 18);
            g2.setColor(new Color(NEON_CYAN.getRed(), NEON_CYAN.getGreen(),
                    NEON_CYAN.getBlue(), 28));
            g2.fillOval(Math.max(0, w - 240), -120, 320, 240);
            g2.setColor(new Color(NEON_MAGENTA.getRed(), NEON_MAGENTA.getGreen(),
                    NEON_MAGENTA.getBlue(), 18));
            g2.fillOval(Math.max(0, w - 420), -160, 300, 250);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** Clean tabs with generous spacing and a single selected-state indicator. */
    private static class ModernTabbedPaneUI extends BasicTabbedPaneUI {
        @Override
        protected void installDefaults() {
            super.installDefaults();
            tabInsets = new Insets(8, 14, 8, 14);
            selectedTabPadInsets = new Insets(0, 0, 0, 0);
            contentBorderInsets = new Insets(1, 0, 0, 0);
        }

        @Override
        protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex,
                                          int x, int y, int w, int h, boolean isSelected) {
            g.setColor(isSelected ? BG_SURFACE : BG_DARK);
            g.fillRect(x, y, w, h);
            if (isSelected) {
                g.setColor(NEON_CYAN);
                g.fillRoundRect(x + 8, y + h - 3, Math.max(4, w - 16), 3, 3, 3);
            }
        }

        @Override
        protected void paintTabBorder(Graphics g, int tabPlacement, int tabIndex,
                                      int x, int y, int w, int h, boolean isSelected) {
            // Deliberately borderless; the selected underline provides hierarchy.
        }

        @Override
        protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {
            g.setColor(BORDER);
            g.drawLine(0, 0, tabPane.getWidth(), 0);
        }

        @Override
        protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects,
                                           int tabIndex, Rectangle iconRect,
                                           Rectangle textRect, boolean isSelected) {
            // Avoid the dated dotted focus rectangle.
        }
    }

    /** Rounded button painter that removes the square Swing content fill. */
    private static class ModernButtonUI extends BasicButtonUI {
        private final Color accent;
        private final boolean filled;

        ModernButtonUI(Color accent, boolean filled) {
            this.accent = accent;
            this.filled = filled;
        }

        @Override
        public void paint(Graphics g, JComponent c) {
            AbstractButton button = (AbstractButton) c;
            ButtonModel model = button.getModel();
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            Color fill;
            if (!button.isEnabled()) {
                fill = BG_INPUT;
            } else if (filled) {
                fill = model.isPressed() ? darken(accent, 0.72f)
                        : model.isRollover() ? lerpColor(accent, Color.WHITE, 0.12f) : accent;
            } else {
                fill = model.isPressed() ? BG_HOVER
                        : model.isRollover() ? BG_SURFACE : BG_PANEL;
            }
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, c.getWidth(), c.getHeight(), 10, 10);
            g2.dispose();
            super.paint(g, c);
        }
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
                if (Boolean.TRUE.equals(b.getClientProperty(BUTTON_FILLED_KEY))) {
                    Object accent = b.getClientProperty(BUTTON_ACCENT_KEY);
                    styleFilledButton(b, accent instanceof Color c ? c : NEON_CYAN);
                } else {
                    styleButton(b, null);
                }
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
                if (l.getForeground() == null || l.getForeground() instanceof UIResource) {
                    l.setForeground(FG_PRIMARY);
                }
                if (l.getFont() == null || l.getFont() instanceof UIResource) {
                    l.setFont(UI_FONT);
                }
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
            btn.putClientProperty(BUTTON_ACCENT_KEY, null);
            btn.putClientProperty(BUTTON_FILLED_KEY, null);
            btn.setContentAreaFilled(true);
            btn.setOpaque(true);
            btn.setBorder(UIManager.getBorder("Button.border"));
            btn.setFont(UIManager.getFont("Button.font"));
            btn.updateUI();
        }

        if (comp instanceof JTextField field) {
            String key = field instanceof JPasswordField ? "PasswordField" : "TextField";
            field.setBorder(UIManager.getBorder(key + ".border"));
            field.setFont(UIManager.getFont(key + ".font"));
            field.updateUI();
        }

        if (comp instanceof JComboBox<?> combo) {
            combo.setBorder(UIManager.getBorder("ComboBox.border"));
            combo.setFont(UIManager.getFont("ComboBox.font"));
        }

        if (comp instanceof JScrollPane scrollPane) {
            scrollPane.setBorder(UIManager.getBorder("ScrollPane.border"));
        }

        if (comp instanceof JPanel panel
                && (panel.getClientProperty("OmniStrike.card") != null
                || panel.getClientProperty(TITLED_NAME_KEY) != null)) {
            panel.setBorder(null);
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
