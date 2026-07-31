package com.omnistrike.framework;

/**
 * Process-wide privacy preferences shared by the AI boundary and Swing views.
 * Real HTTP objects are never modified by this class.
 */
public final class PrivacyManager {

    private static volatile boolean aiRedactionEnabled = true;
    private static volatile boolean uiMaskingEnabled = false;

    private PrivacyManager() {}

    public static boolean isAiRedactionEnabled() {
        return aiRedactionEnabled;
    }

    public static void setAiRedactionEnabled(boolean enabled) {
        aiRedactionEnabled = enabled;
    }

    public static boolean isUiMaskingEnabled() {
        return uiMaskingEnabled;
    }

    public static void setUiMaskingEnabled(boolean enabled) {
        uiMaskingEnabled = enabled;
    }

    public static String redactAiPrompt(String prompt) {
        return aiRedactionEnabled ? SensitiveDataRedactor.redact(prompt) : prompt;
    }

    public static String maskForDisplay(String text) {
        return uiMaskingEnabled ? SensitiveDataRedactor.redact(text) : text;
    }

    public static String maskValueForDisplay(String type, String value) {
        return uiMaskingEnabled ? SensitiveDataRedactor.maskValue(type, value) : value;
    }
}
