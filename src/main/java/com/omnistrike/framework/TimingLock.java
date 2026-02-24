package com.omnistrike.framework;

import java.util.concurrent.Semaphore;

/**
 * Global lock that serializes time-based blind detection across all scanner modules.
 * <p>
 * When multiple modules perform timing measurements concurrently against the same
 * server, they corrupt each other's baselines — causing false positives. This lock
 * ensures only one module runs time-based payloads at a time, while error-based,
 * output-based, and OOB tests from other modules continue running concurrently.
 * <p>
 * Time-based testing is disabled by default and must be explicitly enabled via the
 * "Time-Based Testing" checkbox in the OmniStrike UI tab.
 */
public final class TimingLock {

    private static final Semaphore LOCK = new Semaphore(1);

    /** Global toggle — when false, all time-based blind tests are skipped. */
    private static volatile boolean enabled = false;

    private TimingLock() {
        // Utility class — no instantiation
    }

    /** Returns true if time-based blind testing is globally enabled. */
    public static boolean isEnabled() {
        return enabled;
    }

    /** Enable or disable time-based blind testing globally. */
    public static void setEnabled(boolean value) {
        enabled = value;
    }

    /**
     * Acquire the timing lock. Blocks until the lock is available.
     * Must be paired with {@link #release()} in a finally block.
     */
    public static void acquire() throws InterruptedException {
        LOCK.acquire();
    }

    /**
     * Release the timing lock. Always call this in a finally block.
     */
    public static void release() {
        LOCK.release();
    }
}
