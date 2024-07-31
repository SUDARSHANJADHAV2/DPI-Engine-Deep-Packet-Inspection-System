package com.dpi.tracker;

import com.dpi.types.AppType;
import com.dpi.types.Connection;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Aggregates statistics across all per-FP ConnectionTracker instances.
 * Equivalent to C++ class GlobalConnectionTable.
 */
public class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        this.trackers = new ArrayList<>(Collections.nCopies(numFps, null));
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId < trackers.size()) {
                trackers.set(fpId, tracker);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ---- Global stats record ----
    public record GlobalStats(
            long totalActiveConnections,
            long totalConnectionsSeen,
            Map<AppType, Long> appDistribution,
            List<Map.Entry<String, Long>> topDomains) {
    }

    public GlobalStats getGlobalStats() {
        lock.readLock().lock();
        try {
            long totalActive = 0;
            long totalSeen = 0;
            Map<AppType, Long> appDist = new EnumMap<>(AppType.class);
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null)
                    continue;

                ConnectionTracker.TrackerStats ts = tracker.getStats();
                totalActive += ts.activeConnections();
                totalSeen += ts.totalConnectionsSeen();

                tracker.forEach((Connection conn) -> {
                    appDist.merge(conn.appType, 1L, Long::sum);
                    if (!conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            // Top 20 domains by count
            List<Map.Entry<String, Long>> topDomains = new ArrayList<>(domainCounts.entrySet());
            topDomains.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            if (topDomains.size() > 20)
                topDomains = topDomains.subList(0, 20);

            return new GlobalStats(totalActive, totalSeen, appDist, topDomains);
        } finally {
            lock.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Active Connections:     %10d                          ║%n",
                stats.totalActiveConnections()));
        sb.append(String.format("║ Total Connections Seen: %10d                          ║%n",
                stats.totalConnectionsSeen()));

        if (!stats.appDistribution().isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");

            long total = stats.appDistribution().values().stream().mapToLong(Long::longValue).sum();

            List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(stats.appDistribution().entrySet());
            sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            for (Map.Entry<AppType, Long> e : sorted) {
                double pct = total > 0 ? 100.0 * e.getValue() / total : 0;
                sb.append(String.format("║ %-20s %10d (%5.1f%%)           ║%n",
                        e.getKey().getDisplayName(), e.getValue(), pct));
            }
        }

        if (!stats.topDomains().isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                      TOP DOMAINS                             ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            for (Map.Entry<String, Long> e : stats.topDomains()) {
                String domain = e.getKey();
                if (domain.length() > 35)
                    domain = domain.substring(0, 32) + "...";
                sb.append(String.format("║ %-40s %10d           ║%n", domain, e.getValue()));
            }
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}
