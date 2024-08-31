package com.dpi.queue;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Bounded, thread-safe blocking queue for handing packets between pipeline
 * threads.
 * Equivalent to C++ template class ThreadSafeQueue.
 *
 * Uses {@link ArrayBlockingQueue} which provides all the same semantics as the
 * C++ impl (block on full push, block on empty pop, optional timeout,
 * shutdown).
 */
public class ThreadSafeQueue<T> {

    private final ArrayBlockingQueue<T> queue;
    private volatile boolean shutdown = false;

    /** Create a queue with the given maximum capacity. */
    public ThreadSafeQueue(int maxSize) {
        this.queue = new ArrayBlockingQueue<>(maxSize);
    }

    public ThreadSafeQueue() {
        this(10_000);
    }

    /**
     * Push an item, blocking if the queue is full.
     * Returns immediately if shutdown has been signalled.
     */
    public void push(T item) {
        if (shutdown)
            return;
        try {
            // Poll with timeout loop so we can respect the shutdown flag
            while (!shutdown) {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS))
                    return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Try to push without blocking.
     * 
     * @return true if successfully added, false if full or shutdown.
     */
    public boolean tryPush(T item) {
        if (shutdown)
            return false;
        return queue.offer(item);
    }

    /**
     * Pop an item, blocking until one is available.
     * Returns null if shutdown and queue is empty.
     */
    public T pop() {
        try {
            while (!shutdown || !queue.isEmpty()) {
                T item = queue.poll(100, TimeUnit.MILLISECONDS);
                if (item != null)
                    return item;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return null;
    }

    /**
     * Pop with a timeout.
     * 
     * @param timeoutMs maximum milliseconds to wait
     * @return item or null on timeout/shutdown
     */
    public T popWithTimeout(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    /** Signal shutdown — wakes blocked callers. */
    public void shutdown() {
        shutdown = true;
    }

    public boolean isShutdown() {
        return shutdown;
    }
}
