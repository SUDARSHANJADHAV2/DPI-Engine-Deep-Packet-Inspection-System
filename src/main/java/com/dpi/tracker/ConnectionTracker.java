package com.dpi.tracker;

import com.dpi.types.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Per-FastPathProcessor flow table.
 * Equivalent to C++ class ConnectionTracker.
 *
 * No external synchronization needed: each instance is owned by a single
 * thread.
 */
public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;

    private final LinkedHashMap<FiveTuple, Connection> connections;

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        // LinkedHashMap in access-order mode → natural LRU eviction candidate
        this.connections = new LinkedHashMap<>(1024, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<FiveTuple, Connection> eldest) {
                return size() > maxConnections;
            }
        };
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    /**
     * Look up or create a connection for the given flow tuple.
     * Returns null only if the table is full and eviction fails (shouldn't happen).
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null)
            return conn;

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    /**
     * Look up an existing connection. Also tries reverse direction.
     * Returns null if not found.
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null)
            return conn;
        return connections.get(tuple.reverse());
    }

    /** Update statistics on an existing connection. */
    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null)
            return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /** Mark connection as classified with the given app type and SNI. */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null)
            return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni != null ? sni : "";
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    /** Mark as blocked. */
    public void blockConnection(Connection conn) {
        if (conn == null)
            return;
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    /** Mark as closed (will be cleaned up next pass). */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null)
            conn.state = ConnectionState.CLOSED;
    }

    /**
     * Remove stale (timed-out or closed) connections.
     * 
     * @param timeoutMillis timeout in milliseconds
     * @return number of removed entries
     */
    public int cleanupStale(long timeoutMillis) {
        Instant cutoff = Instant.now().minusMillis(timeoutMillis);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.state == ConnectionState.CLOSED || c.lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public void forEach(Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    public void clear() {
        connections.clear();
    }

    // ---- Inner stats record ----
    public record TrackerStats(
            long activeConnections,
            long totalConnectionsSeen,
            long classifiedConnections,
            long blockedConnections) {
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }
}
