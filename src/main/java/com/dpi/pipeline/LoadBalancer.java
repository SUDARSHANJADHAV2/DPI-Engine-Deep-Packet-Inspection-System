package com.dpi.pipeline;

import com.dpi.queue.ThreadSafeQueue;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer thread — dispatches packets to Fast Path Processors.
 * Equivalent to C++ class LoadBalancer.
 *
 * Uses consistent hashing on the five-tuple so that the same flow always
 * reaches the same FP thread (required for stateful connection tracking).
 */
public class LoadBalancer {

    private final int lb_id;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final long[] perFpCounts;

    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lb_id = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(10_000);
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[numFps];
    }

    public void start() {
        if (running)
            return;
        running = true;
        thread = new Thread(this::run, "LB-" + lb_id);
        thread.setDaemon(true);
        thread.start();
        System.out.printf("[LB%d] Started (serving FP%d-FP%d)%n",
                lb_id, fpStartId, fpStartId + numFps - 1);
    }

    public void stop() {
        if (!running)
            return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[LB" + lb_id + "] Stopped");
    }

    private void run() {
        while (running) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null)
                continue;

            packetsReceived.incrementAndGet();
            int fpIndex = selectFp(job.tuple);
            fpQueues.get(fpIndex).push(job);
            packetsDispatched.incrementAndGet();
            perFpCounts[fpIndex]++;
        }
    }

    /** Select FP index using five-tuple hash modulo pool size. */
    private int selectFp(FiveTuple tuple) {
        return (int) (Integer.toUnsignedLong(tuple.hashCode()) % numFps);
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public int getId() {
        return lb_id;
    }

    public boolean isRunning() {
        return running;
    }

    public record LbStats(long packetsReceived, long packetsDispatched, long[] perFpPackets) {
    }

    public LbStats getStats() {
        return new LbStats(packetsReceived.get(), packetsDispatched.get(), perFpCounts.clone());
    }
}
