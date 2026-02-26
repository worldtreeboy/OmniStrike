package com.omnistrike.framework;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread pool for active scan modules. All active modules submit their
 * work (injection tests, introspection queries, etc.) to this executor.
 * Uses a bounded queue to prevent OOM under heavy traffic.
 * Includes per-host rate limiting to avoid overwhelming targets.
 */
public class ActiveScanExecutor {

    private volatile ExecutorService executor;
    private volatile int threadPoolSize;
    private volatile int rateLimitMs = 0;
    private final Object resizeLock = new Object();
    private final AtomicLong discardedTaskCount = new AtomicLong(0);
    private volatile java.util.function.Consumer<String> logger;
    private volatile boolean unloading = false;

    private static final int MAX_QUEUE_SIZE = 5000;

    public ActiveScanExecutor(int threadPoolSize) {
        this.threadPoolSize = threadPoolSize;
        this.executor = createPool(threadPoolSize);
    }

    /** Sets the logger for warnings (should route to api.logging().logToOutput()). */
    public void setLogger(java.util.function.Consumer<String> logger) {
        this.logger = logger;
    }

    /** Returns the total number of scan tasks silently discarded due to queue overflow. */
    public long getDiscardedTaskCount() {
        return discardedTaskCount.get();
    }

    private ExecutorService createPool(int size) {
        return new ThreadPoolExecutor(
                size, size, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(MAX_QUEUE_SIZE),
                r -> {
                    Thread t = new Thread(r, "OmniStrike-Scanner");
                    t.setDaemon(true);
                    return t;
                },
                (rejectedTask, pool) -> {
                    // Log instead of silently discarding — user needs to know scans are being dropped
                    long total = discardedTaskCount.incrementAndGet();
                    java.util.function.Consumer<String> log = logger;
                    if (log != null) {
                        log.accept("[ActiveScanExecutor] WARNING: Scan task discarded (queue full at "
                                + MAX_QUEUE_SIZE + " tasks). Total discarded: " + total
                                + ". Consider reducing scan scope or increasing thread pool size.");
                    }
                }
        );
    }

    public void submit(Runnable task) {
        ExecutorService ex = executor;
        if (ex != null && !ex.isShutdown()) {
            try {
                ex.submit(wrapWithRateLimit(task));
            } catch (RejectedExecutionException ignored) {
                // Pool shutting down or queue full — discard gracefully
            }
        }
    }

    /**
     * Submits a task and returns its Future for cancellation support.
     * Returns null if the task could not be submitted.
     */
    public Future<?> submitTracked(Runnable task) {
        ExecutorService ex = executor;
        if (ex != null && !ex.isShutdown()) {
            try {
                return ex.submit(wrapWithRateLimit(task));
            } catch (RejectedExecutionException ignored) {
                // Pool shutting down or queue full
            }
        }
        return null;
    }

    /**
     * Wraps a task with a rate limit delay before execution.
     * Also catches NullPointerException from Burp's API proxy becoming null
     * during extension unload while threads are still running.
     */
    private Runnable wrapWithRateLimit(Runnable task) {
        return () -> {
            int delay = rateLimitMs;
            if (delay > 0) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            try {
                task.run();
            } catch (NullPointerException e) {
                if (!unloading) {
                    // Not during unload — this is a real bug in a scan module. Log it.
                    java.util.function.Consumer<String> log = logger;
                    if (log != null) {
                        log.accept("[ActiveScanExecutor] NPE in scan task: " + e.getMessage());
                    }
                }
                // During unload: Burp invalidates its API proxy, causing NPE — discard safely.
            }
        };
    }

    public int getRateLimitMs() {
        return rateLimitMs;
    }

    public void setRateLimitMs(int ms) {
        this.rateLimitMs = Math.max(0, ms);
    }

    public void resize(int newSize) {
        synchronized (resizeLock) {
            if (newSize == this.threadPoolSize) return;
            ExecutorService old = this.executor;
            this.threadPoolSize = newSize;
            this.executor = createPool(newSize);
            if (old != null) {
                old.shutdown();
            }
        }
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public int getQueueSize() {
        ExecutorService ex = executor;
        if (ex instanceof ThreadPoolExecutor) {
            return ((ThreadPoolExecutor) ex).getQueue().size();
        }
        return 0;
    }

    public int getActiveCount() {
        ExecutorService ex = executor;
        if (ex instanceof ThreadPoolExecutor) {
            return ((ThreadPoolExecutor) ex).getActiveCount();
        }
        return 0;
    }

    /**
     * Immediately stop all running and queued scans.
     * Shuts down the current thread pool (interrupting workers) and creates a fresh one.
     * Returns the number of tasks that were purged (queued + not-yet-started).
     */
    public int cancelAll() {
        synchronized (resizeLock) {
            ExecutorService old = this.executor;
            if (old == null) return 0;
            // shutdownNow() returns all queued + not-yet-started tasks — use its count
            // directly instead of also counting queue.size() which would double-count.
            List<Runnable> notRun = old.shutdownNow();
            this.executor = createPool(threadPoolSize);
            return notRun.size();
        }
    }

    /** Signal that the extension is unloading — NPEs from Burp's dead API proxy are expected. */
    public void setUnloading(boolean unloading) {
        this.unloading = unloading;
    }

    public void shutdown() {
        synchronized (resizeLock) {
            ExecutorService ex = executor;
            if (ex != null) {
                ex.shutdown();
                try {
                    if (!ex.awaitTermination(5, TimeUnit.SECONDS)) {
                        ex.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    ex.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}
