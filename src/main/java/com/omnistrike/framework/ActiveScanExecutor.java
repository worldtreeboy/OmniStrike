package com.omnistrike.framework;

import java.util.concurrent.*;

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

    private static final int MAX_QUEUE_SIZE = 5000;

    public ActiveScanExecutor(int threadPoolSize) {
        this.threadPoolSize = threadPoolSize;
        this.executor = createPool(threadPoolSize);
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
                new ThreadPoolExecutor.DiscardOldestPolicy()
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
            task.run();
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
