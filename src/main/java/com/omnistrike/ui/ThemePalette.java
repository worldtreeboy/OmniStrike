package com.omnistrike.ui;

import java.awt.Color;

/**
 * Immutable data class holding the full color set for one OmniStrike theme.
 * Each theme derives ~20 color slots from 3 hero colors (primary, secondary, base).
 * Use the static factory methods to obtain predefined palettes.
 */
public final class ThemePalette {

    // ── Display name ─────────────────────────────────────────────────────
    public final String name;

    // ── Backgrounds (6) ──────────────────────────────────────────────────
    public final Color bgDark;
    public final Color bgPanel;
    public final Color bgInput;
    public final Color bgSurface;
    public final Color bgHover;
    public final Color border;

    // ── Accents (6) ──────────────────────────────────────────────────────
    public final Color accentPrimary;
    public final Color accentSecondary;
    public final Color successGreen;
    public final Color warningOrange;
    public final Color errorRed;
    public final Color infoBlue;

    // ── Text (3) ─────────────────────────────────────────────────────────
    public final Color fgPrimary;
    public final Color fgSecondary;
    public final Color fgDim;

    // ── Severity (5) ─────────────────────────────────────────────────────
    public final Color sevCritical;
    public final Color sevHigh;
    public final Color sevMedium;
    public final Color sevLow;
    public final Color sevInfo;

    // ── Light theme flag ─────────────────────────────────────────────────
    public final boolean isLight;

    private ThemePalette(String name,
                         Color bgDark, Color bgPanel, Color bgInput, Color bgSurface, Color bgHover, Color border,
                         Color accentPrimary, Color accentSecondary, Color successGreen, Color warningOrange,
                         Color errorRed, Color infoBlue,
                         Color fgPrimary, Color fgSecondary, Color fgDim,
                         Color sevCritical, Color sevHigh, Color sevMedium, Color sevLow, Color sevInfo,
                         boolean isLight) {
        this.name = name;
        this.bgDark = bgDark;
        this.bgPanel = bgPanel;
        this.bgInput = bgInput;
        this.bgSurface = bgSurface;
        this.bgHover = bgHover;
        this.border = border;
        this.accentPrimary = accentPrimary;
        this.accentSecondary = accentSecondary;
        this.successGreen = successGreen;
        this.warningOrange = warningOrange;
        this.errorRed = errorRed;
        this.infoBlue = infoBlue;
        this.fgPrimary = fgPrimary;
        this.fgSecondary = fgSecondary;
        this.fgDim = fgDim;
        this.sevCritical = sevCritical;
        this.sevHigh = sevHigh;
        this.sevMedium = sevMedium;
        this.sevLow = sevLow;
        this.sevInfo = sevInfo;
        this.isLight = isLight;
    }

    // ═════════════════════════════════════════════════════════════════════
    //  COLOR DERIVATION UTILITIES
    // ═════════════════════════════════════════════════════════════════════

    /** Lighten a color by blending toward white. amount 0.0=no change, 1.0=white. */
    private static Color lighten(Color c, float amount) {
        int r = Math.min(255, (int) (c.getRed() + (255 - c.getRed()) * amount));
        int g = Math.min(255, (int) (c.getGreen() + (255 - c.getGreen()) * amount));
        int b = Math.min(255, (int) (c.getBlue() + (255 - c.getBlue()) * amount));
        return new Color(r, g, b);
    }

    /** Darken a color by blending toward black. amount 0.0=no change, 1.0=black. */
    private static Color darken(Color c, float amount) {
        int r = (int) (c.getRed() * (1.0f - amount));
        int g = (int) (c.getGreen() * (1.0f - amount));
        int b = (int) (c.getBlue() * (1.0f - amount));
        return new Color(Math.max(0, r), Math.max(0, g), Math.max(0, b));
    }

    /** Mix two colors at a given ratio (0.0=c1, 1.0=c2). */
    private static Color mix(Color c1, Color c2, float ratio) {
        float inv = 1.0f - ratio;
        int r = Math.min(255, (int) (c1.getRed() * inv + c2.getRed() * ratio));
        int g = Math.min(255, (int) (c1.getGreen() * inv + c2.getGreen() * ratio));
        int b = Math.min(255, (int) (c1.getBlue() * inv + c2.getBlue() * ratio));
        return new Color(r, g, b);
    }

    /** Create a color with the given alpha-like opacity against a background. */
    private static Color withOpacity(Color fg, Color bg, float opacity) {
        return mix(bg, fg, opacity);
    }

    // ═════════════════════════════════════════════════════════════════════
    //  FACTORY METHODS — 8 themed palettes (Original is null)
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Cyberpunk — High-Contrast Neon (Electric Blue + Neon Pink on Pitch Black).
     * Matches the original hardcoded CyberTheme colors exactly.
     */
    public static ThemePalette cyberpunk() {
        return new ThemePalette("Cyberpunk",
                // Backgrounds — exact original values
                new Color(0x0D, 0x0D, 0x1A),  // bgDark
                new Color(0x14, 0x14, 0x28),  // bgPanel
                new Color(0x1A, 0x1A, 0x35),  // bgInput
                new Color(0x1E, 0x1E, 0x3A),  // bgSurface
                new Color(0x25, 0x25, 0x50),  // bgHover
                new Color(0x2A, 0x2A, 0x55),  // border
                // Accents — exact original values
                new Color(0x00, 0xF0, 0xFF),  // accentPrimary (NEON_CYAN)
                new Color(0xFF, 0x00, 0xAA),  // accentSecondary (NEON_MAGENTA)
                new Color(0x00, 0xFF, 0x88),  // successGreen
                new Color(0xFF, 0x88, 0x00),  // warningOrange
                new Color(0xFF, 0x22, 0x55),  // errorRed
                new Color(0x44, 0x88, 0xFF),  // infoBlue
                // Text
                new Color(0xE0, 0xE0, 0xFF),  // fgPrimary
                new Color(0x88, 0x88, 0xBB),  // fgSecondary
                new Color(0x55, 0x55, 0x88),  // fgDim
                // Severity
                new Color(0xFF, 0x00, 0x44),  // sevCritical
                new Color(0xFF, 0x66, 0x00),  // sevHigh
                new Color(0xFF, 0xCC, 0x00),  // sevMedium
                new Color(0x00, 0xCC, 0xFF),  // sevLow
                new Color(0x88, 0x88, 0xBB),  // sevInfo
                false);
    }

    /**
     * Theme 2: Ghost — Matrix Green / CRT terminal aesthetic.
     * Hero: #00FF41 (Phosphorus Green), #013220 (Deep Forest), #1A1A1A (Terminal Grey).
     */
    public static ThemePalette ghost() {
        Color base = new Color(0x1A, 0x1A, 0x1A);
        Color primary = new Color(0x00, 0xFF, 0x41);
        Color secondary = new Color(0x33, 0x99, 0x55);
        return new ThemePalette("Ghost",
                // Backgrounds
                base,                                 // bgDark
                lighten(base, 0.05f),                 // bgPanel
                lighten(base, 0.08f),                 // bgInput
                lighten(base, 0.12f),                 // bgSurface
                lighten(base, 0.18f),                 // bgHover
                lighten(base, 0.25f),                 // border
                // Accents
                primary,                              // accentPrimary — phosphorus green
                secondary,                            // accentSecondary — visible forest green
                new Color(0x00, 0xFF, 0x88),          // successGreen
                new Color(0xFF, 0x88, 0x00),          // warningOrange
                new Color(0xFF, 0x22, 0x55),          // errorRed
                new Color(0x44, 0xCC, 0x88),          // infoBlue — green-tinted
                // Text
                new Color(0x88, 0xFF, 0x88),          // fgPrimary — green tint
                new Color(0x55, 0xAA, 0x66),          // fgSecondary
                new Color(0x33, 0x66, 0x44),          // fgDim
                // Severity — keep consistent
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xCC, 0xFF),
                new Color(0x55, 0xAA, 0x66),          // sevInfo — matches theme
                false);
    }

    /**
     * Theme 3: Megacorp — Minimalist Tech (LIGHT theme).
     * Hero: #A5F2F3 (Ice Blue), #708090 (Slate), #FFFFFF (White).
     */
    public static ThemePalette megacorp() {
        return new ThemePalette("Megacorp",
                // Backgrounds — light theme: dark=lightest bg, panel=slightly off-white, etc.
                new Color(0xF5, 0xF7, 0xFA),          // bgDark (lightest background)
                new Color(0xEB, 0xED, 0xF0),          // bgPanel
                new Color(0xFF, 0xFF, 0xFF),          // bgInput (white)
                new Color(0xE0, 0xE4, 0xE8),          // bgSurface
                new Color(0xD0, 0xD8, 0xE0),          // bgHover
                new Color(0xC0, 0xC8, 0xD0),          // border
                // Accents
                new Color(0x00, 0x88, 0x99),          // accentPrimary — darker ice blue for contrast on white
                new Color(0x50, 0x60, 0x70),          // accentSecondary — slate
                new Color(0x00, 0x99, 0x44),          // successGreen
                new Color(0xCC, 0x66, 0x00),          // warningOrange
                new Color(0xCC, 0x00, 0x33),          // errorRed
                new Color(0x22, 0x66, 0xCC),          // infoBlue
                // Text — dark on light
                new Color(0x1A, 0x1A, 0x2E),          // fgPrimary
                new Color(0x55, 0x66, 0x77),          // fgSecondary
                new Color(0x99, 0xAA, 0xBB),          // fgDim
                // Severity
                new Color(0xCC, 0x00, 0x33),
                new Color(0xDD, 0x55, 0x00),
                new Color(0xCC, 0x99, 0x00),
                new Color(0x00, 0x88, 0xCC),
                new Color(0x77, 0x88, 0x99),
                true);
    }

    /**
     * Theme 4: Junkyard — Industrial Rust / Akira aesthetic.
     * Hero: #FF5F00 (Safety Orange), #8B4513 (Rust Brown), #2A3439 (Gunmetal Gray).
     */
    public static ThemePalette junkyard() {
        Color base = new Color(0x2A, 0x34, 0x39);
        Color primary = new Color(0xFF, 0x5F, 0x00);
        return new ThemePalette("Junkyard",
                // Backgrounds
                base,                                 // bgDark
                lighten(base, 0.06f),                 // bgPanel
                lighten(base, 0.10f),                 // bgInput
                lighten(base, 0.14f),                 // bgSurface
                lighten(base, 0.20f),                 // bgHover
                lighten(base, 0.28f),                 // border
                // Accents
                primary,                              // accentPrimary — safety orange
                new Color(0xAA, 0x66, 0x33),          // accentSecondary — visible rust
                new Color(0x66, 0xCC, 0x44),          // successGreen
                new Color(0xFF, 0x88, 0x00),          // warningOrange
                new Color(0xFF, 0x33, 0x33),          // errorRed
                new Color(0x55, 0x99, 0xDD),          // infoBlue
                // Text
                new Color(0xDD, 0xCC, 0xBB),          // fgPrimary — warm light
                new Color(0x99, 0x88, 0x77),          // fgSecondary
                new Color(0x66, 0x5A, 0x50),          // fgDim
                // Severity
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xCC, 0xFF),
                new Color(0x99, 0x88, 0x77),
                false);
    }

    /**
     * Theme 6: Black Ice — Deep Stealth / Monochrome.
     * Hero: #FF0000 (Incision Red), #232323 (Carbon Fiber), #0B0B0B (Obsidian).
     */
    public static ThemePalette blackIce() {
        Color base = new Color(0x0B, 0x0B, 0x0B);
        return new ThemePalette("Black Ice",
                // Backgrounds
                base,                                 // bgDark
                new Color(0x14, 0x14, 0x14),          // bgPanel
                new Color(0x1C, 0x1C, 0x1C),          // bgInput
                new Color(0x22, 0x22, 0x22),          // bgSurface
                new Color(0x2E, 0x2E, 0x2E),          // bgHover
                new Color(0x3A, 0x3A, 0x3A),          // border
                // Accents
                new Color(0xFF, 0x00, 0x00),          // accentPrimary — incision red
                new Color(0x88, 0x00, 0x00),          // accentSecondary — deep red
                new Color(0x00, 0xCC, 0x66),          // successGreen
                new Color(0xFF, 0x88, 0x00),          // warningOrange
                new Color(0xFF, 0x22, 0x33),          // errorRed
                new Color(0x44, 0x77, 0xCC),          // infoBlue
                // Text — cool grey
                new Color(0xCC, 0xCC, 0xCC),          // fgPrimary
                new Color(0x88, 0x88, 0x88),          // fgSecondary
                new Color(0x55, 0x55, 0x55),          // fgDim
                // Severity
                new Color(0xFF, 0x00, 0x33),
                new Color(0xFF, 0x55, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xBB, 0xFF),
                new Color(0x88, 0x88, 0x88),
                false);
    }

    /**
     * Theme 7: Solarpunk — Overgrown Tech / Bio-Punk aesthetic.
     * Hero: #00FFD1 (Bioluminescent Turquoise), #4A5D23 (Moss Green), #CD7F32 (Weathered Bronze).
     */
    public static ThemePalette solarpunk() {
        Color base = new Color(0x1C, 0x22, 0x18);   // dark earthy green
        return new ThemePalette("Solarpunk",
                // Backgrounds
                base,                                 // bgDark
                lighten(base, 0.06f),                 // bgPanel
                lighten(base, 0.10f),                 // bgInput
                lighten(base, 0.14f),                 // bgSurface
                lighten(base, 0.20f),                 // bgHover
                lighten(base, 0.28f),                 // border
                // Accents
                new Color(0x00, 0xFF, 0xD1),          // accentPrimary — bioluminescent turquoise
                new Color(0x88, 0xAA, 0x44),          // accentSecondary — bright moss
                new Color(0x00, 0xFF, 0x88),          // successGreen
                new Color(0xFF, 0x99, 0x22),          // warningOrange
                new Color(0xFF, 0x33, 0x55),          // errorRed
                new Color(0x44, 0xBB, 0xDD),          // infoBlue
                // Text — warm organic light
                new Color(0xDD, 0xEE, 0xCC),          // fgPrimary
                new Color(0x99, 0xAA, 0x88),          // fgSecondary
                new Color(0x66, 0x77, 0x55),          // fgDim
                // Severity
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xCC, 0xFF),
                new Color(0x99, 0xAA, 0x88),
                false);
    }

    /**
     * Theme 8: Netrunner — Data Viz / Wireframe aesthetic.
     * Hero: #00FFFF (Cyan Wireframes), #6600FF (Grid Purple), #000080 (Deep Navy).
     */
    public static ThemePalette netrunner() {
        Color base = new Color(0x00, 0x00, 0x50);   // deep navy
        return new ThemePalette("Netrunner",
                // Backgrounds
                base,                                 // bgDark
                lighten(base, 0.05f),                 // bgPanel
                lighten(base, 0.09f),                 // bgInput
                lighten(base, 0.13f),                 // bgSurface
                lighten(base, 0.19f),                 // bgHover
                lighten(base, 0.26f),                 // border
                // Accents
                new Color(0x00, 0xFF, 0xFF),          // accentPrimary — cyan wireframes
                new Color(0x99, 0x44, 0xFF),          // accentSecondary — bright grid purple
                new Color(0x00, 0xFF, 0x88),          // successGreen
                new Color(0xFF, 0x88, 0x00),          // warningOrange
                new Color(0xFF, 0x22, 0x55),          // errorRed
                new Color(0x44, 0x88, 0xFF),          // infoBlue
                // Text
                new Color(0xCC, 0xDD, 0xFF),          // fgPrimary — cool blue-white
                new Color(0x77, 0x88, 0xBB),          // fgSecondary
                new Color(0x44, 0x55, 0x88),          // fgDim
                // Severity
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xCC, 0xFF),
                new Color(0x77, 0x88, 0xBB),
                false);
    }

    /**
     * Theme 9: Vapor-Tech — Low-Fi Glitch / VHS (LIGHT theme).
     * Hero: #FFDAB9 (Sunset Peach), #808080 (Static Gray), #E6E6FA (Soft Lavender).
     */
    public static ThemePalette vaporTech() {
        return new ThemePalette("Vapor-Tech",
                // Backgrounds — light theme with lavender base
                new Color(0xEE, 0xEE, 0xF8),          // bgDark (lightest)
                new Color(0xE2, 0xE0, 0xF0),          // bgPanel
                new Color(0xF8, 0xF6, 0xFF),          // bgInput
                new Color(0xD8, 0xD6, 0xE8),          // bgSurface
                new Color(0xCC, 0xCC, 0xDD),          // bgHover
                new Color(0xBB, 0xBB, 0xCC),          // border
                // Accents
                new Color(0xCC, 0x66, 0x88),          // accentPrimary — muted rose/peach for contrast
                new Color(0x77, 0x66, 0x99),          // accentSecondary — muted purple
                new Color(0x44, 0x99, 0x66),          // successGreen
                new Color(0xCC, 0x77, 0x33),          // warningOrange
                new Color(0xCC, 0x33, 0x55),          // errorRed
                new Color(0x55, 0x77, 0xBB),          // infoBlue
                // Text — dark on light
                new Color(0x2A, 0x22, 0x33),          // fgPrimary
                new Color(0x66, 0x55, 0x77),          // fgSecondary
                new Color(0x99, 0x88, 0xAA),          // fgDim
                // Severity
                new Color(0xCC, 0x00, 0x33),
                new Color(0xDD, 0x55, 0x00),
                new Color(0xBB, 0x88, 0x00),
                new Color(0x00, 0x88, 0xCC),
                new Color(0x88, 0x77, 0x99),
                true);
    }

    @Override
    public String toString() {
        return name;
    }
}
