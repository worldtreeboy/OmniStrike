package com.omnistrike.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.UIManager;
import java.awt.Color;

import static org.junit.jupiter.api.Assertions.*;

class CyberThemeTest {

    @AfterEach
    void restoreNativeMode() {
        CyberTheme.setNativeMode(true);
    }

    @Test
    void themeCatalogKeepsNativeDefaultAndAddsOmniPro() {
        assertEquals(GlobalThemeManager.THEME_NAMES.length,
                GlobalThemeManager.ALL_THEMES.length);
        assertNull(GlobalThemeManager.ALL_THEMES[0]);
        assertEquals("Default", GlobalThemeManager.THEME_NAMES[0]);
        assertSame(GlobalThemeManager.ALL_THEMES[1],
                GlobalThemeManager.findThemeByName("Omni Pro"));
        assertNull(GlobalThemeManager.findThemeByName("Default"));
    }

    @Test
    void startupThemeFallsBackToBurpDefault() {
        assertEquals("Default", GlobalThemeManager.normalizeThemeName(null));
        assertEquals("Default", GlobalThemeManager.normalizeThemeName("missing-theme"));
        assertEquals("Default", GlobalThemeManager.normalizeThemeName("Default"));
        assertEquals("Omni Pro", GlobalThemeManager.normalizeThemeName("Omni Pro"));
    }

    @Test
    void nativeStartupDoesNotRewriteBurpUiDefaults() {
        GlobalThemeManager.saveOriginalDefaults();
        Object original = UIManager.get("Panel.background");
        Color marker = new Color(1, 2, 3);
        UIManager.put("Panel.background", marker);
        try {
            GlobalThemeManager.applyTheme(null);
            assertSame(marker, UIManager.get("Panel.background"));
            assertTrue(CyberTheme.isNativeMode());
        } finally {
            if (original == null) UIManager.getDefaults().remove("Panel.background");
            else UIManager.put("Panel.background", original);
        }
    }

    @Test
    void omniProInstallsRoundedPaintedControlsAndModernTabs() {
        CyberTheme.setNativeMode(false);
        CyberTheme.loadPalette(ThemePalette.omniPro());

        JButton outline = new JButton("Controls");
        CyberTheme.styleButton(outline, CyberTheme.NEON_CYAN);
        assertAll(
                () -> assertFalse(outline.isOpaque()),
                () -> assertFalse(outline.isContentAreaFilled()),
                () -> assertTrue(outline.isRolloverEnabled()),
                () -> assertTrue(outline.getUI().getClass().getSimpleName().contains("ModernButtonUI")),
                () -> assertNotNull(outline.getBorder())
        );

        JButton filled = new JButton("Run");
        CyberTheme.styleFilledButton(filled, CyberTheme.NEON_GREEN);
        assertFalse(filled.isContentAreaFilled());
        assertEquals(Boolean.TRUE, filled.getClientProperty("OmniStrike.buttonFilled"));

        JPanel card = new JPanel();
        CyberTheme.styleCard(card);
        assertEquals(Boolean.TRUE, card.getClientProperty("OmniStrike.card"));
        assertEquals(CyberTheme.BG_PANEL, card.getBackground());

        JTabbedPane tabs = new JTabbedPane();
        CyberTheme.styleTabbedPane(tabs);
        assertTrue(tabs.getUI().getClass().getSimpleName().contains("ModernTabbedPaneUI"));
    }

    @Test
    void nativeModeLeavesNewControlsUnderSwingLookAndFeel() {
        CyberTheme.setNativeMode(true);
        JButton button = new JButton("Native");
        Object originalUi = button.getUI();
        Color originalBackground = button.getBackground();

        CyberTheme.styleButton(button, Color.MAGENTA);

        assertSame(originalUi, button.getUI());
        assertEquals(originalBackground, button.getBackground());
        assertTrue(button.isContentAreaFilled());
    }
}
