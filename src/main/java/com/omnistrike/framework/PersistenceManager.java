package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.util.function.Consumer;

/**
 * Central wrapper over Burp's user-level preferences
 * ({@code api.persistence().preferences()}), which persist across Burp restarts.
 *
 * <p>Every method is failure-isolated: if the preferences store is unavailable
 * or throws, reads fall back to the supplied default and writes are silently
 * dropped. A persistence problem must never break the extension — the worst case
 * is a setting that isn't remembered.
 *
 * <p>All keys are namespaced with {@code omnistrike.} to avoid collisions with
 * other extensions sharing the same preferences store.
 */
public final class PersistenceManager {

    private static final String PREFIX = "omnistrike.";

    /** Null when the preferences API is unavailable — all ops then no-op/default. */
    private final Preferences prefs;
    private volatile Consumer<String> errorLogger;

    public PersistenceManager(MontoyaApi api) {
        Preferences p = null;
        try {
            p = api.persistence().preferences();
        } catch (Exception ignored) {
            // Persistence unavailable — every accessor will fall back to defaults.
        }
        this.prefs = p;
    }

    public void setErrorLogger(Consumer<String> logger) {
        this.errorLogger = logger;
    }

    /** True if the underlying preferences store is available. */
    public boolean isAvailable() {
        return prefs != null;
    }

    // ── String ────────────────────────────────────────────────────────────

    public String getString(String key, String def) {
        if (prefs == null) return def;
        try {
            String v = prefs.getString(PREFIX + key);
            return v != null ? v : def;
        } catch (Exception e) {
            logErr(key, e);
            return def;
        }
    }

    public void setString(String key, String value) {
        if (prefs == null || value == null) return;
        try {
            prefs.setString(PREFIX + key, value);
        } catch (Exception e) {
            logErr(key, e);
        }
    }

    // ── Integer ───────────────────────────────────────────────────────────

    public int getInt(String key, int def) {
        if (prefs == null) return def;
        try {
            Integer v = prefs.getInteger(PREFIX + key);
            return v != null ? v : def;
        } catch (Exception e) {
            logErr(key, e);
            return def;
        }
    }

    public void setInt(String key, int value) {
        if (prefs == null) return;
        try {
            prefs.setInteger(PREFIX + key, value);
        } catch (Exception e) {
            logErr(key, e);
        }
    }

    // ── Boolean ───────────────────────────────────────────────────────────

    public boolean getBoolean(String key, boolean def) {
        if (prefs == null) return def;
        try {
            Boolean v = prefs.getBoolean(PREFIX + key);
            return v != null ? v : def;
        } catch (Exception e) {
            logErr(key, e);
            return def;
        }
    }

    public void setBoolean(String key, boolean value) {
        if (prefs == null) return;
        try {
            prefs.setBoolean(PREFIX + key, value);
        } catch (Exception e) {
            logErr(key, e);
        }
    }

    private void logErr(String key, Exception e) {
        Consumer<String> l = errorLogger;
        if (l != null) {
            try { l.accept("[Persistence] '" + key + "': " + e.getMessage()); }
            catch (Exception ignored) {}
        }
    }
}
