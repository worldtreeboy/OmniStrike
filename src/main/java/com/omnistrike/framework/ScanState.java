package com.omnistrike.framework;

/**
 * Global scan cancellation flag. Checked by all modules before sending HTTP requests.
 * Unlike Thread.isInterrupted() which gets cleared by Burp's sendRequest() internals,
 * this volatile boolean persists until explicitly reset.
 */
public final class ScanState {
    private static volatile boolean cancelled = false;

    public static void cancel() { cancelled = true; }
    public static void reset() { cancelled = false; }
    public static boolean isCancelled() { return cancelled; }

    private ScanState() {}
}
