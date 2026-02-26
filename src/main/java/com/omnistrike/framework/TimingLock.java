package com.omnistrike.framework;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Global lock that serializes time-based blind detection across all scanner modules.
 * <p>
 * When multiple modules perform timing measurements concurrently against the same
 * server, they corrupt each other's baselines — causing false positives. This lock
 * ensures only one module runs time-based payloads at a time, while error-based,
 * output-based, and OOB tests from other modules continue running concurrently.
 * <p>
 * Uses ReentrantLock instead of Semaphore to enforce ownership: only the thread
 * that acquired the lock can release it. This prevents permits from leaking above 1
 * if a caller accidentally releases without acquiring (e.g., InterruptedException
 * in acquire() followed by a finally block calling release()).
 * <p>
 * Time-based testing is disabled by default and must be explicitly enabled via the
 * "Time-Based Testing" checkbox in the OmniStrike UI tab.
 */
public final class TimingLock {

    private static final ReentrantLock LOCK = new ReentrantLock(true); // fair ordering

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
     *
     * @throws InterruptedException if the current thread is interrupted while waiting
     */
    public static void acquire() throws InterruptedException {
        LOCK.lockInterruptibly();
    }

    /**
     * Release the timing lock. Only the thread that acquired the lock can release it.
     * Safe to call in a finally block — if the current thread does not hold the lock
     * (e.g., acquire() was interrupted before succeeding), this is a no-op.
     */
    public static void release() {
        if (LOCK.isHeldByCurrentThread()) {
            LOCK.unlock();
        }
    }
}
