package com.omnistrike.framework;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Global request throttle with three mutually exclusive modes:
 *
 *   NONE   — no delay between requests (fastest, noisiest)
 *   AUTO   — dynamically backs off when WAF/rate-limiting is detected,
 *            then gradually cools down when traffic flows normally
 *   MANUAL — user-defined fixed delay in milliseconds
 *
 * Only one mode is active at a time. Switching modes resets auto state.
 *
 * Auto throttle algorithm:
 *   - On WAF block (429, 503, WAF 403): step UP the backoff ladder
 *   - Backoff steps: 500ms → 1s → 2s → 4s → 8s → 15s (cap)
 *   - After 30 seconds with no blocks: step DOWN one level
 *   - After 60 seconds with no blocks: reset to 0
 *
 * Integration: ActiveScanExecutor.wrapWithRateLimit() calls getCurrentDelay()
 * before every scan task. ResponseGuard calls onBlocked() when a WAF response
 * is detected. Modules don't need to change — throttling is transparent.
 */
public final class ThrottleController {

    public enum ThrottleMode { NONE, AUTO, MANUAL }

    // ── Configuration ─────────────────────────────────────────────────────
    private volatile ThrottleMode mode = ThrottleMode.NONE;
    private volatile int manualDelayMs = 0;

    // ── Auto state ────────────────────────────────────────────────────────
    private final AtomicInteger blockCount = new AtomicInteger(0);
    private volatile long lastBlockTimestamp = 0;
    private volatile int currentAutoDelayMs = 0;

    private static final int[] BACKOFF_STEPS = {500, 1000, 2000, 4000, 8000, 15000};
    private static final long COOLDOWN_STEP_MS = 30_000;  // Step down after 30s clean
    private static final long COOLDOWN_RESET_MS = 60_000; // Full reset after 60s clean

    private volatile Consumer<String> logger;

    // ════════════════════════════════════════════════════════════════════════
    //  Mode management
    // ════════════════════════════════════════════════════════════════════════

    public ThrottleMode getMode() { return mode; }

    public void setMode(ThrottleMode newMode) {
        if (this.mode == newMode) return;
        this.mode = newMode;
        // Reset auto state when switching modes
        resetAutoState();
        log("[Throttle] Mode → " + newMode
                + (newMode == ThrottleMode.MANUAL ? " (" + manualDelayMs + "ms)" : ""));
    }

    public void setManualDelay(int ms) {
        this.manualDelayMs = Math.max(0, ms);
    }

    public int getManualDelay() { return manualDelayMs; }

    public void setLogger(Consumer<String> logger) { this.logger = logger; }

    // ════════════════════════════════════════════════════════════════════════
    //  Core API — called by ActiveScanExecutor before each task
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Returns the delay (ms) to apply before the next scan task.
     * Called by ActiveScanExecutor.wrapWithRateLimit() on every task execution.
     */
    public int getCurrentDelay() {
        return switch (mode) {
            case NONE   -> 0;
            case MANUAL -> manualDelayMs;
            case AUTO   -> computeAutoDelay();
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Auto throttle events — called by ResponseGuard
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Called when a WAF block or rate limit is detected (429, 503, WAF 403, etc.).
     * Steps UP the backoff ladder. Only has effect in AUTO mode.
     */
    public void onBlocked() {
        if (mode != ThrottleMode.AUTO) return;

        lastBlockTimestamp = System.currentTimeMillis();
        int blocks = blockCount.incrementAndGet();
        int step = Math.min(blocks - 1, BACKOFF_STEPS.length - 1);
        int newDelay = BACKOFF_STEPS[step];
        currentAutoDelayMs = newDelay;

        log("[Throttle] WAF/rate-limit detected — backing off to " + newDelay + "ms"
                + " (consecutive blocks: " + blocks + ")");
    }

    /**
     * Returns the current auto delay, computed with cool-down logic.
     * Automatically steps down when no blocks have been seen for a while.
     */
    private int computeAutoDelay() {
        if (currentAutoDelayMs == 0) return 0;

        long elapsed = System.currentTimeMillis() - lastBlockTimestamp;

        // Full reset after 60 seconds with no blocks
        if (elapsed >= COOLDOWN_RESET_MS) {
            resetAutoState();
            log("[Throttle] Auto reset — no blocks for 60s, delay → 0ms");
            return 0;
        }

        // Step down one level after 30 seconds with no blocks.
        // Use compareAndSet to avoid overwriting a concurrent onBlocked() increment.
        if (elapsed >= COOLDOWN_STEP_MS) {
            int blocks = blockCount.get();
            if (blocks > 0) {
                int newBlocks = blocks - 1;
                // Only decrement if the value hasn't changed (another thread may have incremented)
                if (blockCount.compareAndSet(blocks, newBlocks)) {
                    if (newBlocks > 0) {
                        int step = Math.min(newBlocks - 1, BACKOFF_STEPS.length - 1);
                        currentAutoDelayMs = BACKOFF_STEPS[step];
                    } else {
                        currentAutoDelayMs = 0;
                    }
                    lastBlockTimestamp = System.currentTimeMillis();
                    log("[Throttle] Auto cool-down — delay → " + currentAutoDelayMs + "ms");
                }
                // If CAS failed, another thread modified blockCount — skip this cool-down cycle
            }
        }

        return currentAutoDelayMs;
    }

    private void resetAutoState() {
        blockCount.set(0);
        currentAutoDelayMs = 0;
        lastBlockTimestamp = 0;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Status — for UI display
    // ════════════════════════════════════════════════════════════════════════

    /** Current effective delay for display in the UI status bar. */
    public int getEffectiveDelay() { return getCurrentDelay(); }

    /** Number of consecutive blocks (for auto mode status display). */
    public int getBlockCount() { return blockCount.get(); }

    /** Human-readable status string for the UI. */
    public String getStatusText() {
        return switch (mode) {
            case NONE   -> "No Throttle";
            case MANUAL -> "Manual: " + manualDelayMs + "ms";
            case AUTO   -> {
                int delay = currentAutoDelayMs;
                int blocks = blockCount.get();
                yield delay > 0
                        ? "Auto: " + delay + "ms (blocks: " + blocks + ")"
                        : "Auto: idle";
            }
        };
    }

    private void log(String msg) {
        Consumer<String> l = logger;
        if (l != null) {
            try { l.accept(msg); } catch (Exception ignored) {}
        }
    }
}
