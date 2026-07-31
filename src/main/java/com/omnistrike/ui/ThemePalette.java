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

    // ═════════════════════════════════════════════════════════════════════
    //  BONUS THEMES
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Blood Moon — Vampiric crimson on deep burgundy.
     * Think Castlevania title screen, dried blood on parchment.
     */
    public static ThemePalette bloodMoon() {
        Color base = new Color(0x15, 0x08, 0x08);  // near-black burgundy
        return new ThemePalette("Blood Moon",
                base,
                lighten(base, 0.06f),
                lighten(base, 0.10f),
                lighten(base, 0.14f),
                lighten(base, 0.20f),
                lighten(base, 0.28f),
                new Color(0xFF, 0x11, 0x22),          // accentPrimary — arterial red
                new Color(0x88, 0x22, 0x44),          // accentSecondary — dark wine
                new Color(0xCC, 0x44, 0x44),          // successGreen → blood-warm red-orange instead
                new Color(0xFF, 0x66, 0x00),          // warningOrange
                new Color(0xFF, 0x00, 0x33),          // errorRed
                new Color(0xAA, 0x33, 0x66),          // infoBlue → rose
                new Color(0xEE, 0xCC, 0xCC),          // fgPrimary — pale parchment
                new Color(0x99, 0x66, 0x66),          // fgSecondary
                new Color(0x66, 0x44, 0x44),          // fgDim
                new Color(0xFF, 0x00, 0x33),
                new Color(0xFF, 0x55, 0x00),
                new Color(0xFF, 0xAA, 0x00),
                new Color(0xCC, 0x44, 0x66),
                new Color(0x99, 0x66, 0x66),
                false);
    }

    /**
     * Radioactive — Toxic neon yellow-green on hazmat black.
     * Geiger counter clicking, nuclear waste barrels.
     */
    public static ThemePalette radioactive() {
        Color base = new Color(0x0A, 0x0F, 0x05);  // contaminated black-green
        return new ThemePalette("Radioactive",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.08f),
                lighten(base, 0.12f),
                lighten(base, 0.18f),
                lighten(base, 0.25f),
                new Color(0xBB, 0xFF, 0x00),          // accentPrimary — toxic yellow-green
                new Color(0x55, 0x88, 0x00),          // accentSecondary — hazmat olive
                new Color(0x66, 0xFF, 0x00),          // successGreen — radioactive green
                new Color(0xFF, 0xCC, 0x00),          // warningOrange — caution yellow
                new Color(0xFF, 0x22, 0x22),          // errorRed
                new Color(0x88, 0xDD, 0x00),          // infoBlue → acid green
                new Color(0xDD, 0xFF, 0xAA),          // fgPrimary — sickly pale green
                new Color(0x88, 0xAA, 0x55),          // fgSecondary
                new Color(0x55, 0x66, 0x33),          // fgDim
                new Color(0xFF, 0x00, 0x33),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xDD, 0x00),
                new Color(0x66, 0xDD, 0x00),
                new Color(0x88, 0xAA, 0x55),
                false);
    }

    /**
     * Deep Ocean — Bioluminescent creatures in the abyss.
     * Anglerfish glow, abyssal pressure, deep sea vents.
     */
    public static ThemePalette deepOcean() {
        Color base = new Color(0x02, 0x08, 0x14);  // abyssal black-blue
        return new ThemePalette("Deep Ocean",
                base,
                lighten(base, 0.04f),
                lighten(base, 0.07f),
                lighten(base, 0.11f),
                lighten(base, 0.16f),
                lighten(base, 0.22f),
                new Color(0x00, 0xDD, 0xBB),          // accentPrimary — bioluminescent teal
                new Color(0x22, 0x55, 0x99),          // accentSecondary — deep current blue
                new Color(0x00, 0xFF, 0xAA),          // successGreen — jellyfish glow
                new Color(0xFF, 0x88, 0x44),          // warningOrange — thermal vent
                new Color(0xFF, 0x33, 0x55),          // errorRed
                new Color(0x33, 0x99, 0xDD),          // infoBlue — deep water blue
                new Color(0xBB, 0xDD, 0xEE),          // fgPrimary — sea foam
                new Color(0x55, 0x88, 0x99),          // fgSecondary
                new Color(0x33, 0x55, 0x66),          // fgDim
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xBB, 0xEE),
                new Color(0x55, 0x88, 0x99),
                false);
    }

    /**
     * Sakura — Cherry blossom pink on midnight indigo.
     * Moonlit Japanese garden, petals falling.
     */
    public static ThemePalette sakura() {
        Color base = new Color(0x12, 0x0A, 0x18);  // midnight indigo
        return new ThemePalette("Sakura",
                base,
                lighten(base, 0.06f),
                lighten(base, 0.10f),
                lighten(base, 0.14f),
                lighten(base, 0.20f),
                lighten(base, 0.28f),
                new Color(0xFF, 0x77, 0xAA),          // accentPrimary — cherry blossom pink
                new Color(0xAA, 0x44, 0x88),          // accentSecondary — plum
                new Color(0x77, 0xDD, 0x88),          // successGreen — spring leaf
                new Color(0xFF, 0xAA, 0x55),          // warningOrange
                new Color(0xFF, 0x44, 0x66),          // errorRed
                new Color(0x99, 0x77, 0xDD),          // infoBlue — wisteria
                new Color(0xF0, 0xDD, 0xEE),          // fgPrimary — petal white-pink
                new Color(0xAA, 0x88, 0xAA),          // fgSecondary
                new Color(0x66, 0x55, 0x66),          // fgDim
                new Color(0xFF, 0x22, 0x55),
                new Color(0xFF, 0x66, 0x44),
                new Color(0xFF, 0xBB, 0x33),
                new Color(0x88, 0x99, 0xEE),
                new Color(0xAA, 0x88, 0xAA),
                false);
    }

    /**
     * Synthwave — 80s retrowave sunset. Hot pink, electric purple, orange horizon.
     * Outrun grids, palm trees, chrome Lamborghinis.
     */
    public static ThemePalette synthwave() {
        Color base = new Color(0x13, 0x05, 0x1A);  // deep synthwave purple-black
        return new ThemePalette("Synthwave",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.09f),
                lighten(base, 0.13f),
                lighten(base, 0.19f),
                lighten(base, 0.26f),
                new Color(0xFF, 0x00, 0xCC),          // accentPrimary — hot magenta
                new Color(0xFF, 0x66, 0x00),          // accentSecondary — sunset orange
                new Color(0x00, 0xFF, 0x99),          // successGreen — neon mint
                new Color(0xFF, 0xAA, 0x00),          // warningOrange — chrome gold
                new Color(0xFF, 0x11, 0x44),          // errorRed
                new Color(0x88, 0x44, 0xFF),          // infoBlue — electric purple
                new Color(0xEE, 0xCC, 0xFF),          // fgPrimary — soft lavender-white
                new Color(0xAA, 0x77, 0xBB),          // fgSecondary
                new Color(0x66, 0x44, 0x77),          // fgDim
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x55, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x88, 0x44, 0xFF),
                new Color(0xAA, 0x77, 0xBB),
                false);
    }

    /**
     * Amber Terminal — Classic amber phosphor CRT.
     * 1980s mainframe, glowing warm monochrome.
     */
    public static ThemePalette amberTerminal() {
        Color base = new Color(0x14, 0x0C, 0x00);  // warm black
        return new ThemePalette("Amber Terminal",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.08f),
                lighten(base, 0.12f),
                lighten(base, 0.18f),
                lighten(base, 0.25f),
                new Color(0xFF, 0xBB, 0x00),          // accentPrimary — amber
                new Color(0xAA, 0x77, 0x00),          // accentSecondary — dark amber
                new Color(0xDD, 0xCC, 0x00),          // successGreen → amber-yellow
                new Color(0xFF, 0x88, 0x00),          // warningOrange
                new Color(0xFF, 0x44, 0x22),          // errorRed — warm red
                new Color(0xCC, 0x99, 0x33),          // infoBlue → golden
                new Color(0xFF, 0xCC, 0x66),          // fgPrimary — warm amber glow
                new Color(0xAA, 0x88, 0x44),          // fgSecondary
                new Color(0x66, 0x55, 0x22),          // fgDim
                new Color(0xFF, 0x33, 0x00),
                new Color(0xFF, 0x77, 0x00),
                new Color(0xFF, 0xBB, 0x00),
                new Color(0xCC, 0x99, 0x33),
                new Color(0xAA, 0x88, 0x44),
                false);
    }

    /**
     * Frozen — Arctic ice, crystalline whites and glacial blues.
     * Breath visible in the air, frost on the monitor (LIGHT theme).
     */
    public static ThemePalette frozen() {
        return new ThemePalette("Frozen",
                new Color(0xEA, 0xF2, 0xF8),          // bgDark — ice white
                new Color(0xD8, 0xE8, 0xF0),          // bgPanel — frost
                new Color(0xF2, 0xF8, 0xFC),          // bgInput — snow white
                new Color(0xC8, 0xDD, 0xE8),          // bgSurface — glacial
                new Color(0xB0, 0xCC, 0xDD),          // bgHover — ice blue
                new Color(0x99, 0xBB, 0xCC),          // border — frozen edge
                new Color(0x00, 0x77, 0xBB),          // accentPrimary — deep glacier blue
                new Color(0x55, 0x99, 0xBB),          // accentSecondary — arctic slate
                new Color(0x00, 0x88, 0x55),          // successGreen — evergreen
                new Color(0xBB, 0x77, 0x00),          // warningOrange
                new Color(0xCC, 0x22, 0x44),          // errorRed
                new Color(0x33, 0x88, 0xCC),          // infoBlue
                new Color(0x11, 0x22, 0x33),          // fgPrimary — dark navy on ice
                new Color(0x44, 0x66, 0x77),          // fgSecondary
                new Color(0x88, 0xAA, 0xBB),          // fgDim
                new Color(0xCC, 0x00, 0x33),
                new Color(0xDD, 0x55, 0x00),
                new Color(0xBB, 0x88, 0x00),
                new Color(0x00, 0x77, 0xCC),
                new Color(0x77, 0x88, 0x99),
                true);
    }

    /**
     * Dracula — The beloved Dracula color scheme.
     * Purple-heavy, pastel accents on charcoal.
     */
    public static ThemePalette dracula() {
        Color base = new Color(0x28, 0x2A, 0x36);  // Dracula background
        return new ThemePalette("Dracula",
                base,
                new Color(0x2E, 0x30, 0x3E),          // bgPanel
                new Color(0x34, 0x36, 0x46),          // bgInput
                new Color(0x38, 0x3A, 0x4C),          // bgSurface
                new Color(0x44, 0x47, 0x5A),          // bgHover — Dracula current line
                new Color(0x55, 0x57, 0x6A),          // border
                new Color(0xBD, 0x93, 0xF9),          // accentPrimary — Dracula purple
                new Color(0xFF, 0x79, 0xC6),          // accentSecondary — Dracula pink
                new Color(0x50, 0xFA, 0x7B),          // successGreen — Dracula green
                new Color(0xFF, 0xB8, 0x6C),          // warningOrange — Dracula orange
                new Color(0xFF, 0x55, 0x55),          // errorRed — Dracula red
                new Color(0x8B, 0xE9, 0xFD),          // infoBlue — Dracula cyan
                new Color(0xF8, 0xF8, 0xF2),          // fgPrimary — Dracula foreground
                new Color(0xBB, 0xBB, 0xAA),          // fgSecondary
                new Color(0x62, 0x72, 0xA4),          // fgDim — Dracula comment
                new Color(0xFF, 0x55, 0x55),
                new Color(0xFF, 0xB8, 0x6C),
                new Color(0xF1, 0xFA, 0x8C),          // sevMedium — Dracula yellow
                new Color(0x8B, 0xE9, 0xFD),
                new Color(0x62, 0x72, 0xA4),
                false);
    }

    // ═════════════════════════════════════════════════════════════════════
    //  WAVE 2 THEMES
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Predator — Thermal vision HUD.
     * Infrared imaging: black base, hot yellows/reds/whites like heat signatures.
     */
    public static ThemePalette predator() {
        Color base = new Color(0x08, 0x05, 0x10);  // deep thermal black
        return new ThemePalette("Predator",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.08f),
                lighten(base, 0.12f),
                lighten(base, 0.18f),
                lighten(base, 0.25f),
                new Color(0xFF, 0xDD, 0x00),          // accentPrimary — heat signature yellow
                new Color(0xFF, 0x44, 0x00),          // accentSecondary — hot red
                new Color(0xFF, 0xFF, 0x44),          // successGreen → white-hot
                new Color(0xFF, 0x88, 0x00),          // warningOrange — warm zone
                new Color(0xFF, 0x00, 0x22),          // errorRed — critical heat
                new Color(0xFF, 0xAA, 0x33),          // infoBlue → thermal amber
                new Color(0xFF, 0xEE, 0xBB),          // fgPrimary — warm white
                new Color(0xCC, 0x88, 0x44),          // fgSecondary — warm mid
                new Color(0x66, 0x33, 0x22),          // fgDim — cool zone
                new Color(0xFF, 0x00, 0x00),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xDD, 0x00),
                new Color(0xFF, 0xAA, 0x33),
                new Color(0xCC, 0x88, 0x44),
                false);
    }

    /**
     * Void — Pure OLED black + single ultraviolet accent. Ultra-minimal.
     * Staring into the abyss, the abyss stares back.
     */
    public static ThemePalette voidTheme() {
        Color base = new Color(0x00, 0x00, 0x00);  // true black
        return new ThemePalette("Void",
                base,
                new Color(0x0A, 0x0A, 0x0A),
                new Color(0x11, 0x11, 0x11),
                new Color(0x16, 0x16, 0x16),
                new Color(0x22, 0x22, 0x22),
                new Color(0x2A, 0x2A, 0x2A),
                new Color(0x99, 0x55, 0xFF),          // accentPrimary — ultraviolet
                new Color(0x55, 0x22, 0xAA),          // accentSecondary — deep UV
                new Color(0x77, 0x55, 0xFF),          // successGreen → violet confirmation
                new Color(0xBB, 0x77, 0xFF),          // warningOrange → light violet warning
                new Color(0xFF, 0x33, 0x66),          // errorRed — the only warm color
                new Color(0x77, 0x44, 0xDD),          // infoBlue → mid purple
                new Color(0xBB, 0xBB, 0xBB),          // fgPrimary — neutral grey
                new Color(0x66, 0x66, 0x66),          // fgSecondary
                new Color(0x33, 0x33, 0x33),          // fgDim
                new Color(0xFF, 0x33, 0x66),
                new Color(0xBB, 0x77, 0xFF),
                new Color(0xDD, 0xAA, 0xFF),
                new Color(0x77, 0x55, 0xFF),
                new Color(0x66, 0x66, 0x66),
                false);
    }

    /**
     * Honey Badger — Black + gold luxury. High-end watch UI meets hacker tool.
     * Doesn't care. Takes what it wants.
     */
    public static ThemePalette honeyBadger() {
        Color base = new Color(0x0C, 0x0A, 0x06);  // rich black with warm undertone
        return new ThemePalette("Honey Badger",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.08f),
                lighten(base, 0.12f),
                lighten(base, 0.18f),
                lighten(base, 0.25f),
                new Color(0xFF, 0xD7, 0x00),          // accentPrimary — pure gold
                new Color(0xBB, 0x99, 0x33),          // accentSecondary — antique gold
                new Color(0xDD, 0xBB, 0x00),          // successGreen → gold success
                new Color(0xFF, 0x99, 0x00),          // warningOrange — amber
                new Color(0xFF, 0x33, 0x33),          // errorRed
                new Color(0xCC, 0xAA, 0x44),          // infoBlue → warm gold
                new Color(0xEE, 0xDD, 0xBB),          // fgPrimary — champagne
                new Color(0xAA, 0x99, 0x66),          // fgSecondary — tarnished gold
                new Color(0x66, 0x55, 0x33),          // fgDim
                new Color(0xFF, 0x22, 0x22),
                new Color(0xFF, 0x88, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0xCC, 0xAA, 0x44),
                new Color(0xAA, 0x99, 0x66),
                false);
    }

    /**
     * Catppuccin Mocha — Beloved community pastel theme on warm dark base.
     * Soothing pastels, cozy coding vibes, warm chocolate background.
     */
    public static ThemePalette catppuccinMocha() {
        return new ThemePalette("Catppuccin",
                new Color(0x1E, 0x1E, 0x2E),          // bgDark — Mocha Base
                new Color(0x24, 0x24, 0x37),          // bgPanel — Mocha Mantle
                new Color(0x2A, 0x2A, 0x40),          // bgInput
                new Color(0x31, 0x32, 0x44),          // bgSurface — Mocha Surface0
                new Color(0x45, 0x47, 0x5A),          // bgHover — Mocha Surface1
                new Color(0x58, 0x5B, 0x70),          // border — Mocha Surface2
                new Color(0x89, 0xB4, 0xFA),          // accentPrimary — Mocha Blue
                new Color(0xF5, 0xC2, 0xE7),          // accentSecondary — Mocha Pink
                new Color(0xA6, 0xE3, 0xA1),          // successGreen — Mocha Green
                new Color(0xFA, 0xB3, 0x87),          // warningOrange — Mocha Peach
                new Color(0xF3, 0x8B, 0xA8),          // errorRed — Mocha Red
                new Color(0x74, 0xC7, 0xEC),          // infoBlue — Mocha Sapphire
                new Color(0xCD, 0xD6, 0xF4),          // fgPrimary — Mocha Text
                new Color(0xA6, 0xAD, 0xC8),          // fgSecondary — Mocha Subtext1
                new Color(0x6C, 0x70, 0x86),          // fgDim — Mocha Overlay0
                new Color(0xF3, 0x8B, 0xA8),
                new Color(0xFA, 0xB3, 0x87),
                new Color(0xF9, 0xE2, 0xAF),          // sevMedium — Mocha Yellow
                new Color(0x74, 0xC7, 0xEC),
                new Color(0x6C, 0x70, 0x86),
                false);
    }

    /**
     * Nord — Arctic, calm blue-grey palette. The legendary Nord color scheme.
     * Aurora borealis over frozen lakes.
     */
    public static ThemePalette nord() {
        return new ThemePalette("Nord",
                new Color(0x2E, 0x34, 0x40),          // bgDark — Nord Polar Night
                new Color(0x3B, 0x42, 0x52),          // bgPanel — Nord 1
                new Color(0x43, 0x4C, 0x5E),          // bgInput — Nord 2
                new Color(0x4C, 0x56, 0x6A),          // bgSurface — Nord 3
                new Color(0x55, 0x60, 0x75),          // bgHover
                new Color(0x5E, 0x6A, 0x82),          // border
                new Color(0x88, 0xC0, 0xD0),          // accentPrimary — Nord Frost (cyan)
                new Color(0x81, 0xA1, 0xC1),          // accentSecondary — Nord blue
                new Color(0xA3, 0xBE, 0x8C),          // successGreen — Nord green
                new Color(0xD0, 0x87, 0x70),          // warningOrange — Nord orange
                new Color(0xBF, 0x61, 0x6A),          // errorRed — Nord red
                new Color(0x5E, 0x81, 0xAC),          // infoBlue — Nord deep blue
                new Color(0xEC, 0xEF, 0xF4),          // fgPrimary — Nord Snow Storm
                new Color(0xD8, 0xDE, 0xE9),          // fgSecondary — Nord 4
                new Color(0x7B, 0x88, 0xA1),          // fgDim
                new Color(0xBF, 0x61, 0x6A),
                new Color(0xD0, 0x87, 0x70),
                new Color(0xEB, 0xCB, 0x8B),          // sevMedium — Nord yellow
                new Color(0x88, 0xC0, 0xD0),
                new Color(0x7B, 0x88, 0xA1),
                false);
    }

    /**
     * Gruvbox — Retro groove. Warm earthy browns, oranges, greens on dark.
     * Looks like a wood-paneled 70s computer terminal.
     */
    public static ThemePalette gruvbox() {
        return new ThemePalette("Gruvbox",
                new Color(0x28, 0x28, 0x28),          // bgDark — Gruvbox bg0
                new Color(0x32, 0x30, 0x2F),          // bgPanel — Gruvbox bg1
                new Color(0x3C, 0x38, 0x36),          // bgInput — Gruvbox bg2
                new Color(0x50, 0x49, 0x45),          // bgSurface — Gruvbox bg3
                new Color(0x66, 0x5C, 0x54),          // bgHover — Gruvbox bg4
                new Color(0x7C, 0x6F, 0x64),          // border — Gruvbox gray
                new Color(0xFE, 0x80, 0x19),          // accentPrimary — Gruvbox orange
                new Color(0xB8, 0xBB, 0x26),          // accentSecondary — Gruvbox green
                new Color(0xB8, 0xBB, 0x26),          // successGreen — Gruvbox green
                new Color(0xFE, 0x80, 0x19),          // warningOrange — Gruvbox orange
                new Color(0xFB, 0x49, 0x34),          // errorRed — Gruvbox red
                new Color(0x83, 0xA5, 0x98),          // infoBlue — Gruvbox aqua
                new Color(0xEB, 0xDB, 0xB2),          // fgPrimary — Gruvbox fg
                new Color(0xBD, 0xAE, 0x93),          // fgSecondary — Gruvbox fg4
                new Color(0x92, 0x83, 0x74),          // fgDim — Gruvbox gray
                new Color(0xFB, 0x49, 0x34),
                new Color(0xFE, 0x80, 0x19),
                new Color(0xFA, 0xBD, 0x2F),          // sevMedium — Gruvbox yellow
                new Color(0x83, 0xA5, 0x98),
                new Color(0x92, 0x83, 0x74),
                false);
    }

    /**
     * Solarized Dark — Ethan Schoonover's legendary precision-engineered scheme.
     * Scientifically designed for optimal readability and reduced eye strain.
     */
    public static ThemePalette solarizedDark() {
        return new ThemePalette("Solarized Dark",
                new Color(0x00, 0x2B, 0x36),          // bgDark — Solarized base03
                new Color(0x07, 0x36, 0x42),          // bgPanel — Solarized base02
                new Color(0x0D, 0x3E, 0x4B),          // bgInput
                new Color(0x13, 0x47, 0x55),          // bgSurface
                new Color(0x1C, 0x55, 0x63),          // bgHover
                new Color(0x2A, 0x66, 0x74),          // border
                new Color(0x26, 0x8B, 0xD2),          // accentPrimary — Solarized blue
                new Color(0x2A, 0xA1, 0x98),          // accentSecondary — Solarized cyan
                new Color(0x85, 0x99, 0x00),          // successGreen — Solarized green
                new Color(0xCB, 0x4B, 0x16),          // warningOrange — Solarized orange
                new Color(0xDC, 0x32, 0x2F),          // errorRed — Solarized red
                new Color(0x6C, 0x71, 0xC4),          // infoBlue — Solarized violet
                new Color(0xFD, 0xF6, 0xE3),          // fgPrimary — Solarized base3
                new Color(0x93, 0xA1, 0xA1),          // fgSecondary — Solarized base1
                new Color(0x65, 0x7B, 0x83),          // fgDim — Solarized base00
                new Color(0xDC, 0x32, 0x2F),
                new Color(0xCB, 0x4B, 0x16),
                new Color(0xB5, 0x89, 0x00),          // sevMedium — Solarized yellow
                new Color(0x26, 0x8B, 0xD2),
                new Color(0x65, 0x7B, 0x83),
                false);
    }

    /**
     * Mars Colony — Dusty Martian soil, orange horizon, EVA suit HUD.
     * Red planet survival, dome habitats, iron oxide everything.
     */
    public static ThemePalette marsColony() {
        Color base = new Color(0x1A, 0x0E, 0x08);  // dark Martian soil
        return new ThemePalette("Mars Colony",
                base,
                lighten(base, 0.06f),
                lighten(base, 0.10f),
                lighten(base, 0.14f),
                lighten(base, 0.20f),
                lighten(base, 0.28f),
                new Color(0xFF, 0x77, 0x33),          // accentPrimary — Martian sunset orange
                new Color(0xCC, 0x44, 0x22),          // accentSecondary — iron oxide red
                new Color(0x88, 0xCC, 0x55),          // successGreen — biodome green
                new Color(0xFF, 0xAA, 0x22),          // warningOrange — dust storm
                new Color(0xFF, 0x33, 0x33),          // errorRed — pressure alert
                new Color(0xDD, 0x88, 0x44),          // infoBlue → warm amber
                new Color(0xEE, 0xCC, 0xAA),          // fgPrimary — Martian dust-white
                new Color(0xAA, 0x88, 0x66),          // fgSecondary
                new Color(0x66, 0x44, 0x33),          // fgDim
                new Color(0xFF, 0x22, 0x22),
                new Color(0xFF, 0x77, 0x00),
                new Color(0xFF, 0xBB, 0x33),
                new Color(0xDD, 0x88, 0x44),
                new Color(0xAA, 0x88, 0x66),
                false);
    }

    /**
     * Neon Tokyo — Rain-soaked Shibuya crossing at 2 AM.
     * Electric blue + hot pink reflections on wet asphalt.
     */
    public static ThemePalette neonTokyo() {
        Color base = new Color(0x0A, 0x0A, 0x14);  // wet asphalt
        return new ThemePalette("Neon Tokyo",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.09f),
                lighten(base, 0.13f),
                lighten(base, 0.19f),
                lighten(base, 0.26f),
                new Color(0x00, 0xBB, 0xFF),          // accentPrimary — rain-reflected neon blue
                new Color(0xFF, 0x33, 0x88),          // accentSecondary — hot pink signage
                new Color(0x00, 0xFF, 0x99),          // successGreen — kanji neon green
                new Color(0xFF, 0x99, 0x00),          // warningOrange — taxi light
                new Color(0xFF, 0x11, 0x55),          // errorRed — danger kanji
                new Color(0x55, 0x99, 0xFF),          // infoBlue
                new Color(0xDD, 0xDD, 0xF0),          // fgPrimary — rain-washed white
                new Color(0x88, 0x88, 0xAA),          // fgSecondary
                new Color(0x44, 0x44, 0x66),          // fgDim
                new Color(0xFF, 0x00, 0x44),
                new Color(0xFF, 0x66, 0x00),
                new Color(0xFF, 0xCC, 0x00),
                new Color(0x00, 0xBB, 0xFF),
                new Color(0x88, 0x88, 0xAA),
                false);
    }

    /**
     * Phantom — Gray-on-gray stealth. Muted teal accent, like smoke and mirrors.
     * The theme for people who think other dark themes are too colorful.
     */
    public static ThemePalette phantom() {
        Color base = new Color(0x16, 0x18, 0x1A);  // smoke black
        return new ThemePalette("Phantom",
                base,
                new Color(0x1E, 0x20, 0x22),
                new Color(0x26, 0x28, 0x2A),
                new Color(0x2E, 0x30, 0x33),
                new Color(0x3A, 0x3C, 0x40),
                new Color(0x48, 0x4A, 0x50),
                new Color(0x55, 0xBB, 0xAA),          // accentPrimary — muted teal (the only color)
                new Color(0x44, 0x88, 0x77),          // accentSecondary — darker teal
                new Color(0x55, 0xAA, 0x88),          // successGreen — subtle green-teal
                new Color(0xBB, 0x99, 0x55),          // warningOrange — muted amber
                new Color(0xBB, 0x55, 0x55),          // errorRed — muted red
                new Color(0x55, 0x88, 0x99),          // infoBlue — steel blue
                new Color(0xBB, 0xBB, 0xBB),          // fgPrimary — light grey
                new Color(0x77, 0x77, 0x77),          // fgSecondary — mid grey
                new Color(0x44, 0x44, 0x44),          // fgDim — dark grey
                new Color(0xBB, 0x44, 0x44),
                new Color(0xBB, 0x88, 0x44),
                new Color(0xBB, 0xBB, 0x44),
                new Color(0x44, 0x99, 0xAA),
                new Color(0x77, 0x77, 0x77),
                false);
    }

    /**
     * Monokai — The iconic Sublime Text color scheme.
     * Warm charcoal base, vibrant orange/pink/green/yellow accents.
     */
    public static ThemePalette monokai() {
        return new ThemePalette("Monokai",
                new Color(0x27, 0x28, 0x22),          // bgDark — Monokai background
                new Color(0x30, 0x31, 0x2B),          // bgPanel
                new Color(0x39, 0x3A, 0x33),          // bgInput
                new Color(0x42, 0x43, 0x3C),          // bgSurface
                new Color(0x52, 0x53, 0x4C),          // bgHover
                new Color(0x62, 0x63, 0x5C),          // border
                new Color(0xF9, 0x26, 0x72),          // accentPrimary — Monokai pink
                new Color(0xFD, 0x97, 0x1F),          // accentSecondary — Monokai orange
                new Color(0xA6, 0xE2, 0x2E),          // successGreen — Monokai green
                new Color(0xFD, 0x97, 0x1F),          // warningOrange — Monokai orange
                new Color(0xF9, 0x26, 0x72),          // errorRed — Monokai pink
                new Color(0x66, 0xD9, 0xEF),          // infoBlue — Monokai cyan
                new Color(0xF8, 0xF8, 0xF2),          // fgPrimary — Monokai foreground
                new Color(0xBB, 0xBB, 0xAA),          // fgSecondary
                new Color(0x75, 0x71, 0x5E),          // fgDim — Monokai comment
                new Color(0xF9, 0x26, 0x72),
                new Color(0xFD, 0x97, 0x1F),
                new Color(0xE6, 0xDB, 0x74),          // sevMedium — Monokai yellow
                new Color(0x66, 0xD9, 0xEF),
                new Color(0x75, 0x71, 0x5E),
                false);
    }

    /**
     * Cyberdeck — Retro 90s hacker aesthetic. Mixed green/amber CRT,
     * like a jury-rigged terminal from a William Gibson novel.
     */
    public static ThemePalette cyberdeck() {
        Color base = new Color(0x0A, 0x0C, 0x08);  // dirty CRT black
        return new ThemePalette("Cyberdeck",
                base,
                lighten(base, 0.05f),
                lighten(base, 0.08f),
                lighten(base, 0.12f),
                lighten(base, 0.18f),
                lighten(base, 0.25f),
                new Color(0x33, 0xFF, 0x33),          // accentPrimary — classic terminal green
                new Color(0xFF, 0xBB, 0x00),          // accentSecondary — amber CRT bleed
                new Color(0x33, 0xFF, 0x33),          // successGreen — same terminal green
                new Color(0xFF, 0xBB, 0x00),          // warningOrange — amber
                new Color(0xFF, 0x33, 0x33),          // errorRed — CRT red
                new Color(0x33, 0xCC, 0x99),          // infoBlue → mixed green-cyan
                new Color(0xAA, 0xFF, 0xAA),          // fgPrimary — phosphor green glow
                new Color(0x66, 0xAA, 0x66),          // fgSecondary — faded phosphor
                new Color(0x33, 0x66, 0x33),          // fgDim — barely visible scan lines
                new Color(0xFF, 0x22, 0x22),
                new Color(0xFF, 0xAA, 0x00),
                new Color(0xFF, 0xDD, 0x00),
                new Color(0x33, 0xCC, 0x99),
                new Color(0x66, 0xAA, 0x66),
                false);
    }

    @Override
    public String toString() {
        return name;
    }
    /**
     * Omni Pro — the polished default: deep slate surfaces, cyan focus, and violet depth.
     * Designed for long assessment sessions with restrained contrast and clear hierarchy.
     */
    public static ThemePalette omniPro() {
        return new ThemePalette("Omni Pro",
                new Color(0x08, 0x0B, 0x14),
                new Color(0x0E, 0x14, 0x22),
                new Color(0x11, 0x18, 0x27),
                new Color(0x15, 0x1D, 0x2E),
                new Color(0x1B, 0x2A, 0x45),
                new Color(0x26, 0x35, 0x52),
                new Color(0x38, 0xBD, 0xF8),
                new Color(0xA7, 0x8B, 0xFA),
                new Color(0x34, 0xD3, 0x99),
                new Color(0xFB, 0xBF, 0x24),
                new Color(0xFB, 0x71, 0x85),
                new Color(0x60, 0xA5, 0xFA),
                new Color(0xF1, 0xF5, 0xF9),
                new Color(0x94, 0xA3, 0xB8),
                new Color(0x64, 0x74, 0x8B),
                new Color(0xFB, 0x71, 0x85),
                new Color(0xFB, 0x92, 0x3C),
                new Color(0xFB, 0xBF, 0x24),
                new Color(0x38, 0xBD, 0xF8),
                new Color(0x94, 0xA3, 0xB8),
                false);
    }
}
