package com.omnistrike.framework;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Global scan cancellation flag. Checked by all modules before sending HTTP requests.
 * Unlike Thread.isInterrupted() which gets cleared by Burp's sendRequest() internals,
 * this volatile boolean persists until explicitly reset.
 */
public final class ScanState {
    private static volatile boolean cancelled = false;

    /* A cancellation epoch keeps old workers cancelled even after a new scan
       resets the global flag. Burp's HTTP stack may clear thread interrupts. */
    private static final AtomicLong epoch = new AtomicLong();
    private static final ThreadLocal<Long> taskEpoch = new ThreadLocal<>();

    public static void cancel() {
        cancelled = true;
        epoch.incrementAndGet();
    }

    public static void reset() { cancelled = false; }

    public static boolean isCancelled() {
        Long bound = taskEpoch.get();
        return cancelled || (bound != null && bound.longValue() != epoch.get());
    }

    static long currentEpoch() { return epoch.get(); }
    static void bindTask(long submittedEpoch) { taskEpoch.set(submittedEpoch); }
    static void clearTaskBinding() { taskEpoch.remove(); }

    private ScanState() {}
}
