package com.omnistrike.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import static org.junit.jupiter.api.Assertions.*;

class CyberThemeTest {

    @AfterEach
    void restoreNativeMode() {
        CyberTheme.setNativeMode(true);
        GlobalThemeManager.setCurrentScope(GlobalThemeManager.ThemeScope.OMNISTRIKE_ONLY);
        GlobalThemeManager.setOmniStrikeRoot(null);
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

    @Test
    void httpMessageAreasKeepHighContrastAcrossEveryCustomPalette() {
        CyberTheme.setNativeMode(false);

        for (ThemePalette palette : GlobalThemeManager.ALL_THEMES) {
            if (palette == null) continue;
            CyberTheme.loadPalette(palette);
            JTextArea area = new JTextArea("GET / HTTP/1.1");
            CyberTheme.styleHttpMessageArea(area);

            assertTrue(CyberTheme.contrastRatio(area.getForeground(), area.getBackground()) >= 7.0,
                    () -> palette.name + " HTTP text contrast was "
                            + CyberTheme.contrastRatio(area.getForeground(), area.getBackground()));
            assertEquals(13f, area.getFont().getSize2D());
            assertNotNull(area.getMargin());
        }
    }

    @Test
    void globalThemeCoversSyntaxEditorsPlainTextAndOmniStrikeText() throws Exception {
        ThemePalette palette = ThemePalette.omniPro();
        JPanel omniRoot = new JPanel();
        JTextArea omniText = new JTextArea();
        omniRoot.add(omniText);
        JTextPane burpSyntaxText = new JTextPane();
        JTextArea burpPlainText = new JTextArea();
        Color burpBackground = new Color(0xFA, 0xFA, 0xFA);
        Color burpForeground = new Color(0x22, 0x22, 0x22);
        burpSyntaxText.setBackground(burpBackground);
        burpSyntaxText.setForeground(burpForeground);
        SimpleAttributeSet darkSyntax = new SimpleAttributeSet();
        StyleConstants.setForeground(darkSyntax, new Color(0x18, 0x20, 0x2C));
        burpSyntaxText.getStyledDocument().insertString(0, "GET / HTTP/1.1", darkSyntax);
        burpPlainText.setBackground(burpBackground);
        burpPlainText.setForeground(burpForeground);

        GlobalThemeManager.setOmniStrikeRoot(omniRoot);
        GlobalThemeManager.setCurrentScope(GlobalThemeManager.ThemeScope.GLOBAL);
        SwingUtilities.invokeAndWait(() -> {
            GlobalThemeManager.forceThemeRecursive(burpSyntaxText, palette);
            GlobalThemeManager.forceThemeRecursive(burpPlainText, palette);
            GlobalThemeManager.forceThemeRecursive(omniRoot, palette);
        });

        assertEquals(palette.bgInput, burpSyntaxText.getBackground());
        assertEquals(palette.fgPrimary, burpSyntaxText.getForeground());
        Color syntaxForeground = StyleConstants.getForeground(
                burpSyntaxText.getStyledDocument().getCharacterElement(0).getAttributes());
        assertTrue(CyberTheme.contrastRatio(syntaxForeground, burpSyntaxText.getBackground()) >= 7.0);
        assertEquals(palette.bgInput, burpPlainText.getBackground());
        assertEquals(palette.fgPrimary, burpPlainText.getForeground());
        assertEquals(palette.bgInput, omniText.getBackground());
        assertEquals(palette.fgPrimary, omniText.getForeground());
    }

    @Test
    void frostbyteWorkspaceArtworkIsBundledAndPaintable() {
        MascotBackdropPanel backdrop = new MascotBackdropPanel();
        assertTrue(backdrop.hasMascot());
        assertEquals(2, backdrop.getArtworkCount());
        assertEquals("Frostbyte", backdrop.getActiveArtworkName());

        backdrop.setSize(800, 450);
        BufferedImage rendered = new BufferedImage(800, 450, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = rendered.createGraphics();
        try {
            backdrop.paint(graphics);
        } finally {
            graphics.dispose();
        }

        assertNotEquals(0, rendered.getRGB(400, 225));
        assertEquals("Nightblade", backdrop.nextArtwork());
        assertEquals("Frostbyte", backdrop.nextArtwork());
    }
}
