package com.omnistrike.ui;

import javax.imageio.ImageIO;
import javax.swing.JPanel;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static com.omnistrike.ui.CyberTheme.BG_DARK;

/**
 * Full-bleed workspace art used while no scanner module is selected.
 * A cached render keeps normal Swing repaints cheap, including ambient glow ticks.
 */
final class MascotBackdropPanel extends JPanel {

    private static final ArtworkResource[] ARTWORK_RESOURCES = {
            new ArtworkResource("Frostbyte", "/com/omnistrike/ui/assets/frostbyte-mascot.png"),
            new ArtworkResource("Nightblade", "/com/omnistrike/ui/assets/nightblade-mascot.jpg")
    };

    private final List<Artwork> artworks;
    private int activeArtworkIndex;
    private BufferedImage rendered;
    private int renderedWidth = -1;
    private int renderedHeight = -1;
    private ThemePalette renderedPalette;
    private boolean renderedNativeMode;

    MascotBackdropPanel() {
        artworks = loadArtworks();
        setOpaque(true);
    }

    boolean hasMascot() {
        return !artworks.isEmpty();
    }

    int getArtworkCount() {
        return artworks.size();
    }

    String getActiveArtworkName() {
        return activeArtwork() != null ? activeArtwork().name : "Artwork";
    }

    String nextArtwork() {
        if (artworks.size() > 1) {
            activeArtworkIndex = (activeArtworkIndex + 1) % artworks.size();
            rendered = null;
            repaint();
        }
        return getActiveArtworkName();
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        int width = getWidth();
        int height = getHeight();
        if (width <= 0 || height <= 0) return;

        ThemePalette palette = GlobalThemeManager.getCurrentPalette();
        boolean nativeMode = CyberTheme.isNativeMode();
        if (rendered == null || renderedWidth != width || renderedHeight != height
                || renderedPalette != palette || renderedNativeMode != nativeMode) {
            rendered = renderBackdrop(width, height, nativeMode);
            renderedWidth = width;
            renderedHeight = height;
            renderedPalette = palette;
            renderedNativeMode = nativeMode;
        }
        graphics.drawImage(rendered, 0, 0, null);
    }

    private BufferedImage renderBackdrop(int width, int height, boolean nativeMode) {
        BufferedImage canvas = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = canvas.createGraphics();
        try {
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            Color base = nativeMode && getBackground() != null ? getBackground() : BG_DARK;
            g2.setColor(base);
            g2.fillRect(0, 0, width, height);

            Artwork artwork = activeArtwork();
            if (artwork == null) return canvas;
            BufferedImage mascot = artwork.image;

            // A quiet, cropped copy fills the canvas as atmospheric texture.
            g2.setComposite(AlphaComposite.SrcOver.derive(nativeMode ? 0.18f : 0.28f));
            drawCover(g2, mascot, width, height);

            // The complete portrait stays visible and centered over that texture.
            g2.setComposite(AlphaComposite.SrcOver.derive(nativeMode ? 0.58f : 0.82f));
            drawContain(g2, mascot, width, height, 0.96);

            // Edge and floor fades protect overlaid text without hiding the artwork.
            g2.setComposite(AlphaComposite.SrcOver);
            Color transparentBase = new Color(base.getRed(), base.getGreen(), base.getBlue(), 12);
            Color opaqueBase = new Color(base.getRed(), base.getGreen(), base.getBlue(), nativeMode ? 175 : 205);
            g2.setPaint(new GradientPaint(0, 0, opaqueBase, width * 0.45f, 0, transparentBase));
            g2.fillRect(0, 0, width, height);
            g2.setPaint(new GradientPaint(0, height * 0.55f, transparentBase, 0, height, opaqueBase));
            g2.fillRect(0, 0, width, height);
        } finally {
            g2.dispose();
        }
        return canvas;
    }

    private static void drawCover(Graphics2D g2, BufferedImage image, int width, int height) {
        double scale = Math.max(width / (double) image.getWidth(), height / (double) image.getHeight());
        int drawWidth = Math.max(1, (int) Math.ceil(image.getWidth() * scale));
        int drawHeight = Math.max(1, (int) Math.ceil(image.getHeight() * scale));
        g2.drawImage(image, (width - drawWidth) / 2, (height - drawHeight) / 2,
                drawWidth, drawHeight, null);
    }

    private static void drawContain(Graphics2D g2, BufferedImage image,
                                    int width, int height, double paddingFactor) {
        double scale = Math.min(width / (double) image.getWidth(), height / (double) image.getHeight())
                * paddingFactor;
        int drawWidth = Math.max(1, (int) Math.floor(image.getWidth() * scale));
        int drawHeight = Math.max(1, (int) Math.floor(image.getHeight() * scale));
        g2.drawImage(image, (width - drawWidth) / 2, (height - drawHeight) / 2,
                drawWidth, drawHeight, null);
    }

    private Artwork activeArtwork() {
        return artworks.isEmpty() ? null : artworks.get(activeArtworkIndex);
    }

    private static List<Artwork> loadArtworks() {
        List<Artwork> loaded = new ArrayList<>();
        for (ArtworkResource definition : ARTWORK_RESOURCES) {
            URL resource = MascotBackdropPanel.class.getResource(definition.resourcePath);
            if (resource == null) continue;
            try {
                BufferedImage image = ImageIO.read(resource);
                if (image != null) loaded.add(new Artwork(definition.name, image));
            } catch (IOException ignored) {
                // A missing optional backdrop must never prevent OmniStrike loading.
            }
        }
        return loaded;
    }

    private static final class ArtworkResource {
        final String name;
        final String resourcePath;

        ArtworkResource(String name, String resourcePath) {
            this.name = name;
            this.resourcePath = resourcePath;
        }
    }

    private static final class Artwork {
        final String name;
        final BufferedImage image;

        Artwork(String name, BufferedImage image) {
            this.name = name;
            this.image = image;
        }
    }
}
