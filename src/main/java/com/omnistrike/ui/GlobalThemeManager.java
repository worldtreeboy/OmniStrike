package com.omnistrike.ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.JTableHeader;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton managing global theme state across the entire Burp Suite application.
 *
 * Uses a two-pronged approach for truly global theming:
 *   1. UIManager defaults — so newly-created components inherit theme colors
 *   2. Brute-force recursive walker — physically sets bg/fg on EVERY existing
 *      component in every open Frame, overriding any hardcoded colors set by
 *      Burp Suite's own panels (Proxy, Repeater, Intruder, etc.)
 */
public final class GlobalThemeManager {

    private GlobalThemeManager() {}

    /** Snapshot of original UIManager defaults, taken once before the first theme apply. */
    private static Map<String, Object> savedDefaults;

    /** Currently active palette (null = Original / Burp defaults). */
    private static ThemePalette currentPalette;

    /** All available palettes. Index 0 is null (Default = Burp's native look). */
    public static final ThemePalette[] ALL_THEMES = {
            null,                              // 0 - Default (no theme, Burp native)
            ThemePalette.cyberpunk(),          // 1 - Cyberpunk
            ThemePalette.ghost(),              // 2 - Ghost
            ThemePalette.megacorp(),           // 3 - Megacorp
            ThemePalette.junkyard(),           // 4 - Junkyard
            ThemePalette.blackIce(),           // 5 - Black Ice
            ThemePalette.solarpunk(),          // 6 - Solarpunk
            ThemePalette.netrunner(),          // 7 - Netrunner
            ThemePalette.vaporTech(),          // 8 - Vapor-Tech
    };

    /** Display names for the dropdown, matching ALL_THEMES order. */
    public static final String[] THEME_NAMES = {
            "Default",
            "Cyberpunk",
            "Ghost",
            "Megacorp",
            "Junkyard",
            "Black Ice",
            "Solarpunk",
            "Netrunner",
            "Vapor-Tech",
    };

    // ── UIManager keys to override ──────────────────────────────────────
    private static final String[] UI_KEYS = {
            // Panels
            "Panel.background", "Panel.foreground",
            // Buttons
            "Button.background", "Button.foreground", "Button.font",
            "Button.select", "Button.focus", "Button.disabledText",
            "ToggleButton.background", "ToggleButton.foreground", "ToggleButton.select",
            // Text fields
            "TextField.background", "TextField.foreground", "TextField.caretForeground",
            "TextField.selectionBackground", "TextField.selectionForeground",
            "TextField.inactiveForeground", "TextField.disabledBackground",
            "FormattedTextField.background", "FormattedTextField.foreground",
            "PasswordField.background", "PasswordField.foreground", "PasswordField.caretForeground",
            "PasswordField.selectionBackground", "PasswordField.selectionForeground",
            // Text areas
            "TextArea.background", "TextArea.foreground", "TextArea.caretForeground",
            "TextArea.selectionBackground", "TextArea.selectionForeground",
            "TextPane.background", "TextPane.foreground", "TextPane.caretForeground",
            "TextPane.selectionBackground", "TextPane.selectionForeground",
            "EditorPane.background", "EditorPane.foreground", "EditorPane.caretForeground",
            "EditorPane.selectionBackground", "EditorPane.selectionForeground",
            // Tables
            "Table.background", "Table.foreground",
            "Table.selectionBackground", "Table.selectionForeground", "Table.gridColor",
            "Table.focusCellBackground", "Table.focusCellForeground",
            "TableHeader.background", "TableHeader.foreground",
            // Scroll
            "ScrollBar.background", "ScrollBar.foreground",
            "ScrollBar.thumb", "ScrollBar.thumbDarkShadow", "ScrollBar.thumbHighlight",
            "ScrollBar.thumbShadow", "ScrollBar.track", "ScrollBar.trackHighlight",
            "ScrollPane.background", "ScrollPane.foreground",
            // Tabs
            "TabbedPane.background", "TabbedPane.foreground",
            "TabbedPane.selected", "TabbedPane.selectedForeground",
            "TabbedPane.contentAreaColor", "TabbedPane.tabAreaBackground",
            "TabbedPane.unselectedBackground", "TabbedPane.shadow", "TabbedPane.darkShadow",
            "TabbedPane.highlight", "TabbedPane.light",
            // ComboBox
            "ComboBox.background", "ComboBox.foreground",
            "ComboBox.selectionBackground", "ComboBox.selectionForeground",
            "ComboBox.disabledBackground", "ComboBox.disabledForeground",
            "ComboBox.buttonBackground", "ComboBox.buttonDarkShadow",
            // Check/Radio
            "CheckBox.background", "CheckBox.foreground",
            "RadioButton.background", "RadioButton.foreground",
            // Labels
            "Label.foreground", "Label.background", "Label.disabledForeground",
            // Lists
            "List.background", "List.foreground",
            "List.selectionBackground", "List.selectionForeground",
            // Trees
            "Tree.background", "Tree.foreground",
            "Tree.selectionBackground", "Tree.selectionForeground",
            "Tree.textBackground", "Tree.textForeground",
            "Tree.selectionBorderColor", "Tree.hash",
            // Menus
            "MenuBar.background", "MenuBar.foreground", "MenuBar.shadow", "MenuBar.highlight",
            "Menu.background", "Menu.foreground", "Menu.selectionBackground", "Menu.selectionForeground",
            "MenuItem.background", "MenuItem.foreground", "MenuItem.selectionBackground", "MenuItem.selectionForeground",
            "MenuItem.acceleratorForeground", "MenuItem.disabledForeground",
            "CheckBoxMenuItem.background", "CheckBoxMenuItem.foreground",
            "CheckBoxMenuItem.selectionBackground", "CheckBoxMenuItem.selectionForeground",
            "RadioButtonMenuItem.background", "RadioButtonMenuItem.foreground",
            "RadioButtonMenuItem.selectionBackground", "RadioButtonMenuItem.selectionForeground",
            "PopupMenu.background", "PopupMenu.foreground",
            // Tooltips
            "ToolTip.background", "ToolTip.foreground",
            // Option pane
            "OptionPane.background", "OptionPane.foreground", "OptionPane.messageForeground",
            // Split pane
            "SplitPane.background", "SplitPane.shadow", "SplitPane.darkShadow", "SplitPane.highlight",
            // Progress bar
            "ProgressBar.background", "ProgressBar.foreground", "ProgressBar.selectionBackground", "ProgressBar.selectionForeground",
            // Spinner
            "Spinner.background", "Spinner.foreground",
            // Slider
            "Slider.background", "Slider.foreground",
            // Viewport
            "Viewport.background", "Viewport.foreground",
            // Toolbar
            "ToolBar.background", "ToolBar.foreground", "ToolBar.shadow", "ToolBar.darkShadow",
            "ToolBar.dockingBackground", "ToolBar.floatingBackground",
            // Separator
            "Separator.foreground", "Separator.background",
            // Internal frame
            "InternalFrame.activeTitleBackground", "InternalFrame.activeTitleForeground",
            "InternalFrame.inactiveTitleBackground", "InternalFrame.inactiveTitleForeground",
            "InternalFrame.borderColor",
            // Desktop
            "Desktop.background",
            // Dialog
            "Dialog.background", "Dialog.foreground",
            // File chooser
            "FileChooser.listViewBackground",
            // ColorChooser
            "ColorChooser.background", "ColorChooser.foreground",
            // Global fallback keys (used by many L&Fs)
            "control", "controlText", "controlHighlight", "controlLtHighlight", "controlShadow", "controlDkShadow",
            "window", "windowText", "windowBorder",
            "text", "textText", "textHighlight", "textHighlightText", "textInactiveText",
            "info", "infoText",
            "menu", "menuText",
            "desktop",
            "activeCaption", "activeCaptionText", "activeCaptionBorder",
            "inactiveCaption", "inactiveCaptionText", "inactiveCaptionBorder",
            "scrollbar",
            // FlatLaf specific keys (Burp Suite uses FlatLaf)
            "Component.focusColor", "Component.borderColor",
            "@background", "@foreground", "@selectionBackground", "@selectionForeground",
            "@accentColor",
    };

    // ═════════════════════════════════════════════════════════════════════
    //  PUBLIC API
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Snapshot the current UIManager defaults for all keys we intend to override.
     * Call once at extension initialization, before applying any theme.
     */
    public static synchronized void saveOriginalDefaults() {
        if (savedDefaults != null) return; // already saved
        savedDefaults = new HashMap<>();
        for (String key : UI_KEYS) {
            Object value = UIManager.get(key);
            if (value instanceof Color c) {
                savedDefaults.put(key, new Color(c.getRGB(), true));
            } else {
                savedDefaults.put(key, value);
            }
        }
    }

    /**
     * Apply a theme palette. Pass null to restore Burp's original defaults.
     * Updates CyberTheme static fields, UIManager keys, then brute-force
     * walks every component in every frame to physically override colors.
     */
    public static void applyTheme(ThemePalette palette) {
        if (palette == null) {
            restoreOriginal();
            return;
        }
        currentPalette = palette;
        // 1. Load palette into CyberTheme mutable static fields
        CyberTheme.loadPalette(palette);
        // 2. Apply UIManager overrides for newly-created components
        applyUIManagerOverrides(palette);
        // 3. Force-walk all existing components + repaint
        forceThemeOnAllFrames(palette);
    }

    /**
     * Restore Burp's original UIManager defaults and repaint.
     */
    public static void restoreOriginal() {
        currentPalette = null;
        if (savedDefaults != null) {
            for (Map.Entry<String, Object> entry : savedDefaults.entrySet()) {
                UIManager.put(entry.getKey(), entry.getValue());
            }
        }
        // updateComponentTreeUI reinstalls L&F delegates which read from UIManager
        SwingUtilities.invokeLater(() -> {
            for (Frame frame : Frame.getFrames()) {
                try {
                    SwingUtilities.updateComponentTreeUI(frame);
                    frame.repaint();
                } catch (Exception ignored) {}
            }
        });
    }

    /** Returns the currently active palette (null if Original). */
    public static ThemePalette getCurrentPalette() {
        return currentPalette;
    }

    // ═════════════════════════════════════════════════════════════════════
    //  PRIVATE — UIManager manipulation
    // ═════════════════════════════════════════════════════════════════════

    private static void applyUIManagerOverrides(ThemePalette p) {
        // ── Panels ──
        UIManager.put("Panel.background", p.bgDark);
        UIManager.put("Panel.foreground", p.fgPrimary);

        // ── Buttons ──
        UIManager.put("Button.background", p.bgPanel);
        UIManager.put("Button.foreground", p.accentPrimary);
        UIManager.put("Button.font", CyberTheme.MONO_FONT);
        UIManager.put("Button.select", p.bgHover);
        UIManager.put("Button.focus", p.accentPrimary);
        UIManager.put("Button.disabledText", p.fgDim);
        UIManager.put("ToggleButton.background", p.bgPanel);
        UIManager.put("ToggleButton.foreground", p.accentPrimary);
        UIManager.put("ToggleButton.select", p.bgHover);

        // ── Text Fields ──
        UIManager.put("TextField.background", p.bgInput);
        UIManager.put("TextField.foreground", p.fgPrimary);
        UIManager.put("TextField.caretForeground", p.accentPrimary);
        UIManager.put("TextField.selectionBackground", p.bgHover);
        UIManager.put("TextField.selectionForeground", p.accentPrimary);
        UIManager.put("TextField.inactiveForeground", p.fgDim);
        UIManager.put("TextField.disabledBackground", p.bgSurface);
        UIManager.put("FormattedTextField.background", p.bgInput);
        UIManager.put("FormattedTextField.foreground", p.fgPrimary);
        UIManager.put("PasswordField.background", p.bgInput);
        UIManager.put("PasswordField.foreground", p.fgPrimary);
        UIManager.put("PasswordField.caretForeground", p.accentPrimary);
        UIManager.put("PasswordField.selectionBackground", p.bgHover);
        UIManager.put("PasswordField.selectionForeground", p.accentPrimary);

        // ── Text Areas ──
        UIManager.put("TextArea.background", p.bgInput);
        UIManager.put("TextArea.foreground", p.fgPrimary);
        UIManager.put("TextArea.caretForeground", p.accentPrimary);
        UIManager.put("TextArea.selectionBackground", p.bgHover);
        UIManager.put("TextArea.selectionForeground", p.accentPrimary);
        UIManager.put("TextPane.background", p.bgInput);
        UIManager.put("TextPane.foreground", p.fgPrimary);
        UIManager.put("TextPane.caretForeground", p.accentPrimary);
        UIManager.put("TextPane.selectionBackground", p.bgHover);
        UIManager.put("TextPane.selectionForeground", p.accentPrimary);
        UIManager.put("EditorPane.background", p.bgInput);
        UIManager.put("EditorPane.foreground", p.fgPrimary);
        UIManager.put("EditorPane.caretForeground", p.accentPrimary);
        UIManager.put("EditorPane.selectionBackground", p.bgHover);
        UIManager.put("EditorPane.selectionForeground", p.accentPrimary);

        // ── Tables ──
        UIManager.put("Table.background", p.bgPanel);
        UIManager.put("Table.foreground", p.fgPrimary);
        UIManager.put("Table.selectionBackground", p.bgHover);
        UIManager.put("Table.selectionForeground", p.accentPrimary);
        UIManager.put("Table.gridColor", p.border);
        UIManager.put("Table.focusCellBackground", p.bgHover);
        UIManager.put("Table.focusCellForeground", p.accentPrimary);
        UIManager.put("TableHeader.background", p.bgSurface);
        UIManager.put("TableHeader.foreground", p.accentPrimary);

        // ── Scroll ──
        UIManager.put("ScrollBar.background", p.bgDark);
        UIManager.put("ScrollBar.foreground", p.fgDim);
        UIManager.put("ScrollBar.thumb", p.border);
        UIManager.put("ScrollBar.thumbDarkShadow", p.bgDark);
        UIManager.put("ScrollBar.thumbHighlight", p.accentPrimary);
        UIManager.put("ScrollBar.thumbShadow", p.bgSurface);
        UIManager.put("ScrollBar.track", p.bgDark);
        UIManager.put("ScrollBar.trackHighlight", p.bgPanel);
        UIManager.put("ScrollPane.background", p.bgDark);
        UIManager.put("ScrollPane.foreground", p.fgPrimary);

        // ── Tabs ──
        UIManager.put("TabbedPane.background", p.bgDark);
        UIManager.put("TabbedPane.foreground", p.fgSecondary);
        UIManager.put("TabbedPane.selected", p.bgPanel);
        UIManager.put("TabbedPane.selectedForeground", p.accentPrimary);
        UIManager.put("TabbedPane.contentAreaColor", p.bgDark);
        UIManager.put("TabbedPane.tabAreaBackground", p.bgDark);
        UIManager.put("TabbedPane.unselectedBackground", p.bgDark);
        UIManager.put("TabbedPane.shadow", p.border);
        UIManager.put("TabbedPane.darkShadow", p.bgDark);
        UIManager.put("TabbedPane.highlight", p.accentPrimary);
        UIManager.put("TabbedPane.light", p.bgPanel);

        // ── Combo Box ──
        UIManager.put("ComboBox.background", p.bgInput);
        UIManager.put("ComboBox.foreground", p.fgPrimary);
        UIManager.put("ComboBox.selectionBackground", p.bgHover);
        UIManager.put("ComboBox.selectionForeground", p.accentPrimary);
        UIManager.put("ComboBox.disabledBackground", p.bgSurface);
        UIManager.put("ComboBox.disabledForeground", p.fgDim);
        UIManager.put("ComboBox.buttonBackground", p.bgPanel);
        UIManager.put("ComboBox.buttonDarkShadow", p.border);

        // ── Check/Radio ──
        UIManager.put("CheckBox.background", p.bgDark);
        UIManager.put("CheckBox.foreground", p.fgPrimary);
        UIManager.put("RadioButton.background", p.bgDark);
        UIManager.put("RadioButton.foreground", p.fgPrimary);

        // ── Labels ──
        UIManager.put("Label.foreground", p.fgPrimary);
        UIManager.put("Label.background", p.bgDark);
        UIManager.put("Label.disabledForeground", p.fgDim);

        // ── Lists ──
        UIManager.put("List.background", p.bgPanel);
        UIManager.put("List.foreground", p.fgPrimary);
        UIManager.put("List.selectionBackground", p.bgHover);
        UIManager.put("List.selectionForeground", p.accentPrimary);

        // ── Trees ──
        UIManager.put("Tree.background", p.bgPanel);
        UIManager.put("Tree.foreground", p.fgPrimary);
        UIManager.put("Tree.selectionBackground", p.bgHover);
        UIManager.put("Tree.selectionForeground", p.accentPrimary);
        UIManager.put("Tree.textBackground", p.bgPanel);
        UIManager.put("Tree.textForeground", p.fgPrimary);
        UIManager.put("Tree.selectionBorderColor", p.accentPrimary);
        UIManager.put("Tree.hash", p.border);

        // ── Menus ──
        UIManager.put("MenuBar.background", p.bgPanel);
        UIManager.put("MenuBar.foreground", p.fgPrimary);
        UIManager.put("MenuBar.shadow", p.border);
        UIManager.put("MenuBar.highlight", p.accentPrimary);
        UIManager.put("Menu.background", p.bgPanel);
        UIManager.put("Menu.foreground", p.fgPrimary);
        UIManager.put("Menu.selectionBackground", p.bgHover);
        UIManager.put("Menu.selectionForeground", p.accentPrimary);
        UIManager.put("MenuItem.background", p.bgPanel);
        UIManager.put("MenuItem.foreground", p.fgPrimary);
        UIManager.put("MenuItem.selectionBackground", p.bgHover);
        UIManager.put("MenuItem.selectionForeground", p.accentPrimary);
        UIManager.put("MenuItem.acceleratorForeground", p.fgSecondary);
        UIManager.put("MenuItem.disabledForeground", p.fgDim);
        UIManager.put("CheckBoxMenuItem.background", p.bgPanel);
        UIManager.put("CheckBoxMenuItem.foreground", p.fgPrimary);
        UIManager.put("CheckBoxMenuItem.selectionBackground", p.bgHover);
        UIManager.put("CheckBoxMenuItem.selectionForeground", p.accentPrimary);
        UIManager.put("RadioButtonMenuItem.background", p.bgPanel);
        UIManager.put("RadioButtonMenuItem.foreground", p.fgPrimary);
        UIManager.put("RadioButtonMenuItem.selectionBackground", p.bgHover);
        UIManager.put("RadioButtonMenuItem.selectionForeground", p.accentPrimary);
        UIManager.put("PopupMenu.background", p.bgPanel);
        UIManager.put("PopupMenu.foreground", p.fgPrimary);

        // ── Tooltips ──
        UIManager.put("ToolTip.background", p.bgSurface);
        UIManager.put("ToolTip.foreground", p.fgPrimary);

        // ── Option Pane (dialogs) ──
        UIManager.put("OptionPane.background", p.bgDark);
        UIManager.put("OptionPane.foreground", p.fgPrimary);
        UIManager.put("OptionPane.messageForeground", p.fgPrimary);

        // ── Split Pane ──
        UIManager.put("SplitPane.background", p.bgDark);
        UIManager.put("SplitPane.shadow", p.border);
        UIManager.put("SplitPane.darkShadow", p.bgDark);
        UIManager.put("SplitPane.highlight", p.border);

        // ── Progress Bar ──
        UIManager.put("ProgressBar.background", p.bgInput);
        UIManager.put("ProgressBar.foreground", p.accentPrimary);
        UIManager.put("ProgressBar.selectionBackground", p.fgPrimary);
        UIManager.put("ProgressBar.selectionForeground", p.bgDark);

        // ── Spinner ──
        UIManager.put("Spinner.background", p.bgInput);
        UIManager.put("Spinner.foreground", p.fgPrimary);

        // ── Slider ──
        UIManager.put("Slider.background", p.bgDark);
        UIManager.put("Slider.foreground", p.accentPrimary);

        // ── Viewport ──
        UIManager.put("Viewport.background", p.bgDark);
        UIManager.put("Viewport.foreground", p.fgPrimary);

        // ── Toolbar ──
        UIManager.put("ToolBar.background", p.bgPanel);
        UIManager.put("ToolBar.foreground", p.fgPrimary);
        UIManager.put("ToolBar.shadow", p.border);
        UIManager.put("ToolBar.darkShadow", p.bgDark);
        UIManager.put("ToolBar.dockingBackground", p.bgPanel);
        UIManager.put("ToolBar.floatingBackground", p.bgPanel);

        // ── Separator ──
        UIManager.put("Separator.foreground", p.border);
        UIManager.put("Separator.background", p.bgDark);

        // ── Internal Frame ──
        UIManager.put("InternalFrame.activeTitleBackground", p.bgSurface);
        UIManager.put("InternalFrame.activeTitleForeground", p.accentPrimary);
        UIManager.put("InternalFrame.inactiveTitleBackground", p.bgPanel);
        UIManager.put("InternalFrame.inactiveTitleForeground", p.fgDim);
        UIManager.put("InternalFrame.borderColor", p.border);

        // ── Desktop ──
        UIManager.put("Desktop.background", p.bgDark);

        // ── Dialog ──
        UIManager.put("Dialog.background", p.bgDark);
        UIManager.put("Dialog.foreground", p.fgPrimary);

        // ── File chooser ──
        UIManager.put("FileChooser.listViewBackground", p.bgPanel);

        // ── ColorChooser ──
        UIManager.put("ColorChooser.background", p.bgDark);
        UIManager.put("ColorChooser.foreground", p.fgPrimary);

        // ── Global AWT/Swing fallback system colors ──
        UIManager.put("control", p.bgPanel);
        UIManager.put("controlText", p.fgPrimary);
        UIManager.put("controlHighlight", p.bgHover);
        UIManager.put("controlLtHighlight", p.bgSurface);
        UIManager.put("controlShadow", p.border);
        UIManager.put("controlDkShadow", p.bgDark);
        UIManager.put("window", p.bgDark);
        UIManager.put("windowText", p.fgPrimary);
        UIManager.put("windowBorder", p.border);
        UIManager.put("text", p.bgInput);
        UIManager.put("textText", p.fgPrimary);
        UIManager.put("textHighlight", p.bgHover);
        UIManager.put("textHighlightText", p.accentPrimary);
        UIManager.put("textInactiveText", p.fgDim);
        UIManager.put("info", p.bgSurface);
        UIManager.put("infoText", p.fgPrimary);
        UIManager.put("menu", p.bgPanel);
        UIManager.put("menuText", p.fgPrimary);
        UIManager.put("desktop", p.bgDark);
        UIManager.put("activeCaption", p.bgSurface);
        UIManager.put("activeCaptionText", p.accentPrimary);
        UIManager.put("activeCaptionBorder", p.border);
        UIManager.put("inactiveCaption", p.bgPanel);
        UIManager.put("inactiveCaptionText", p.fgDim);
        UIManager.put("inactiveCaptionBorder", p.border);
        UIManager.put("scrollbar", p.bgDark);

        // ── FlatLaf specific (Burp Suite uses FlatLaf) ──
        UIManager.put("Component.focusColor", p.accentPrimary);
        UIManager.put("Component.borderColor", p.border);
        UIManager.put("@background", p.bgDark);
        UIManager.put("@foreground", p.fgPrimary);
        UIManager.put("@selectionBackground", p.bgHover);
        UIManager.put("@selectionForeground", p.accentPrimary);
        UIManager.put("@accentColor", p.accentPrimary);
    }

    // ═════════════════════════════════════════════════════════════════════
    //  BRUTE-FORCE COMPONENT WALKER — themes EVERY component in the JVM
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Walk every frame in the JVM, update the L&F delegates, then force-set
     * colors on every component. This is the nuclear option that guarantees
     * truly global theming even for Burp Suite's internal panels.
     */
    private static void forceThemeOnAllFrames(ThemePalette p) {
        SwingUtilities.invokeLater(() -> {
            for (Frame frame : Frame.getFrames()) {
                try {
                    // First reinstall L&F delegates so they pick up new UIManager values
                    SwingUtilities.updateComponentTreeUI(frame);
                    // Then force-walk every component to override hardcoded colors
                    forceThemeRecursive(frame, p);
                    frame.repaint();
                } catch (Exception ignored) {
                    // Some frames may belong to other classloaders or be disposed
                }
                // Also handle owned windows (dialogs, popups)
                for (Window window : frame.getOwnedWindows()) {
                    try {
                        SwingUtilities.updateComponentTreeUI(window);
                        forceThemeRecursive(window, p);
                        window.repaint();
                    } catch (Exception ignored) {}
                }
            }
        });
    }

    /**
     * Recursively walk a component tree and force-set colors based on component type.
     * This overrides any colors that were hardcoded by Burp Suite's own panels.
     */
    private static void forceThemeRecursive(Component comp, ThemePalette p) {
        try {
            forceColors(comp, p);
        } catch (Exception ignored) {}

        // Recurse into containers
        if (comp instanceof Container container) {
            // Special: JScrollPane — also handle viewport and scrollbars
            if (comp instanceof JScrollPane sp) {
                if (sp.getViewport() != null) {
                    sp.getViewport().setBackground(p.bgDark);
                    sp.getViewport().setForeground(p.fgPrimary);
                    Component view = sp.getViewport().getView();
                    if (view != null) {
                        forceThemeRecursive(view, p);
                    }
                }
                forceScrollBar(sp.getVerticalScrollBar(), p);
                forceScrollBar(sp.getHorizontalScrollBar(), p);
            }

            // Special: JSplitPane — handle divider
            if (comp instanceof JSplitPane sp) {
                if (sp.getUI() instanceof javax.swing.plaf.basic.BasicSplitPaneUI basicUI) {
                    try {
                        basicUI.getDivider().setBackground(p.border);
                    } catch (Exception ignored) {}
                }
            }

            // Special: JTable — handle header separately
            if (comp instanceof JTable table) {
                JTableHeader header = table.getTableHeader();
                if (header != null) {
                    header.setBackground(p.bgSurface);
                    header.setForeground(p.accentPrimary);
                }
            }

            // Recurse into all children
            for (Component child : container.getComponents()) {
                forceThemeRecursive(child, p);
            }
        }
    }

    /**
     * Force-set colors on a single component based on its type.
     */
    private static void forceColors(Component comp, ThemePalette p) {
        // ── JTable ──
        if (comp instanceof JTable table) {
            table.setBackground(p.bgPanel);
            table.setForeground(p.fgPrimary);
            table.setSelectionBackground(p.bgHover);
            table.setSelectionForeground(p.accentPrimary);
            table.setGridColor(p.border);
            return;
        }

        // ── JTextComponent (TextField, TextArea, TextPane, EditorPane, PasswordField) ──
        if (comp instanceof JTextComponent tc) {
            tc.setBackground(p.bgInput);
            tc.setForeground(p.fgPrimary);
            tc.setCaretColor(p.accentPrimary);
            tc.setSelectionColor(p.bgHover);
            tc.setSelectedTextColor(p.accentPrimary);
            return;
        }

        // ── JList ──
        if (comp instanceof JList<?> list) {
            list.setBackground(p.bgPanel);
            list.setForeground(p.fgPrimary);
            list.setSelectionBackground(p.bgHover);
            list.setSelectionForeground(p.accentPrimary);
            return;
        }

        // ── JTree ──
        if (comp instanceof JTree tree) {
            tree.setBackground(p.bgPanel);
            tree.setForeground(p.fgPrimary);
            return;
        }

        // ── JComboBox ──
        if (comp instanceof JComboBox<?>) {
            comp.setBackground(p.bgInput);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JTabbedPane ──
        if (comp instanceof JTabbedPane tp) {
            tp.setBackground(p.bgDark);
            tp.setForeground(p.fgSecondary);
            tp.setOpaque(true);
            return;
        }

        // ── JToolBar ──
        if (comp instanceof JToolBar) {
            comp.setBackground(p.bgPanel);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JMenuBar ──
        if (comp instanceof JMenuBar) {
            comp.setBackground(p.bgPanel);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JMenuItem (covers JMenu, JCheckBoxMenuItem, JRadioButtonMenuItem) ──
        if (comp instanceof JMenuItem) {
            comp.setBackground(p.bgPanel);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JPopupMenu ──
        if (comp instanceof JPopupMenu) {
            comp.setBackground(p.bgPanel);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JProgressBar ──
        if (comp instanceof JProgressBar) {
            comp.setBackground(p.bgInput);
            comp.setForeground(p.accentPrimary);
            return;
        }

        // ── JSlider ──
        if (comp instanceof JSlider) {
            comp.setBackground(p.bgDark);
            comp.setForeground(p.accentPrimary);
            return;
        }

        // ── JSpinner ──
        if (comp instanceof JSpinner) {
            comp.setBackground(p.bgInput);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── JButton / JToggleButton ──
        if (comp instanceof AbstractButton btn) {
            // Don't override opaque=false buttons (icon-only buttons, arrow buttons)
            if (btn instanceof JCheckBox || btn instanceof JRadioButton) {
                btn.setBackground(p.bgDark);
                btn.setForeground(p.fgPrimary);
            } else {
                btn.setBackground(p.bgPanel);
                btn.setForeground(p.fgPrimary);
            }
            return;
        }

        // ── JScrollPane ──
        if (comp instanceof JScrollPane) {
            comp.setBackground(p.bgDark);
            return;
        }

        // ── JSplitPane ──
        if (comp instanceof JSplitPane) {
            comp.setBackground(p.bgDark);
            return;
        }

        // ── JLabel — only set foreground (bg is usually transparent) ──
        if (comp instanceof JLabel label) {
            label.setForeground(p.fgPrimary);
            return;
        }

        // ── JPanel and other generic containers ──
        if (comp instanceof JPanel) {
            comp.setBackground(p.bgDark);
            comp.setForeground(p.fgPrimary);
            return;
        }

        // ── Fallback: any other component ──
        comp.setBackground(p.bgDark);
        comp.setForeground(p.fgPrimary);
    }

    /**
     * Force scrollbar colors.
     */
    private static void forceScrollBar(JScrollBar bar, ThemePalette p) {
        if (bar == null) return;
        bar.setBackground(p.bgDark);
        bar.setForeground(p.fgDim);
    }
}
