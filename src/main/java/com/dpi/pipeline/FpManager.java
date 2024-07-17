package com.dpi.pipeline;

import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.types.AppType;
import com.dpi.types.Connection;
import com.dpi.types.PacketAction;
import com.dpi.types.PacketJob;
import com.dpi.queue.ThreadSafeQueue;

import java.util.*;
import java.util.function.BiConsumer;

/**
 * Creates and manages a pool of FastPathProcessor threads.
 * Equivalent to C++ class FPManager.
 */
public class FpManager {

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FpManager(int numFps, RuleManager ruleManager,
            BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        fps.forEach(FastPathProcessor::start);
    }

    public void stopAll() {
        fps.forEach(FastPathProcessor::stop);
    }

    public FastPathProcessor getFp(int id) {
        return fps.get(id);
    }

    public ThreadSafeQueue<PacketJob> getFpQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public int getNumFps() {
        return fps.size();
    }

    /** Return all FP input queues as a list (used by LbManager). */
    public List<ThreadSafeQueue<PacketJob>> getQueues() {
        List<ThreadSafeQueue<PacketJob>> queues = new ArrayList<>(fps.size());
        for (FastPathProcessor fp : fps)
            queues.add(fp.getInputQueue());
        return queues;
    }

    // ---- Aggregated stats record ----
    public record AggregatedStats(
            long totalProcessed,
            long totalForwarded,
            long totalDropped,
            long totalConnections) {
    }

    public AggregatedStats getAggregatedStats() {
        long processed = 0, forwarded = 0, dropped = 0, connections = 0;
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FpStats s = fp.getStats();
            processed += s.packetsProcessed();
            forwarded += s.packetsForwarded();
            dropped += s.packetsDropped();
            connections += s.connectionsTracked();
        }
        return new AggregatedStats(processed, forwarded, dropped, connections);
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        long totalClassified = 0, totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            ConnectionTracker tracker = fp.getConnectionTracker();
            tracker.forEach((Connection conn) -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
            });
        }

        for (Map.Entry<AppType, Long> e : appCounts.entrySet()) {
            if (e.getKey() == AppType.UNKNOWN)
                totalUnknown += e.getValue();
            else
                totalClassified += e.getValue();
        }

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? 100.0 * totalClassified / total : 0;
        double unknownPct = total > 0 ? 100.0 * totalUnknown / total : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%.1f%%)                  ║%n",
                totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║%n",
                totalUnknown, unknownPct));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appCounts.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sorted) {
            double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(Math.max(0, barLen));
            sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    e.getKey().getDisplayName(), e.getValue(), pct, bar));
        }
        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}
