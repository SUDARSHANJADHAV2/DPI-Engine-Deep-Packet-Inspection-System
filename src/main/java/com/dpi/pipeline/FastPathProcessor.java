package com.dpi.pipeline;

import com.dpi.extractor.*;
import com.dpi.queue.ThreadSafeQueue;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.types.*;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor thread — the core DPI worker.
 * Equivalent to C++ class FastPathProcessor.
 *
 * Responsibilities:
 * 1. Dequeue packets from the input queue (fed by LoadBalancer)
 * 2. Track connections (flow state)
 * 3. Inspect payload — TLS SNI / HTTP Host / DNS
 * 4. Match against blocking rules
 * 5. Forward or drop via the output callback
 */
public class FastPathProcessor {

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    // Statistics (atomic — can be read from another thread)
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager,
            BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(10_000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running)
            return;
        running = true;
        thread = new Thread(this::run, "FP-" + fpId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
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
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed + " packets)");
    }

    // -------------------------------------------------------------------------
    // Main loop
    // -------------------------------------------------------------------------
    private void run() {
        while (running) {
            PacketJob job = inputQueue.popWithTimeout(100);

            if (job == null) {
                // Periodic stale connection cleanup (every ~5 s of idle)
                connTracker.cleanupStale(300_000L);
                continue;
            }

            packetsProcessed.incrementAndGet();
            PacketAction action = processPacket(job);

            if (outputCallback != null)
                outputCallback.accept(job, action);

            if (action == PacketAction.DROP)
                packetsDropped.incrementAndGet();
            else
                packetsForwarded.incrementAndGet();
        }
    }

    // -------------------------------------------------------------------------
    // Packet processing
    // -------------------------------------------------------------------------
    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null)
            return PacketAction.FORWARD;

        connTracker.updateConnection(conn, job.data.length, true);

        // Update TCP state machine
        if (job.tuple.protocol == 6)
            updateTcpState(conn, job.tcpFlags);

        // Already blocked connection → drop immediately
        if (conn.state == ConnectionState.BLOCKED)
            return PacketAction.DROP;

        // Inspect payload if not yet classified
        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    // -------------------------------------------------------------------------
    // Payload inspection (SNI → HTTP → DNS → port-based fallback)
    // -------------------------------------------------------------------------
    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length)
            return;

        if (tryExtractSni(job, conn))
            return;
        if (tryExtractHttpHost(job, conn))
            return;

        // DNS (port 53)
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = DnsExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Port-based fallback
        if (job.tuple.dstPort == 80)
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        else if (job.tuple.dstPort == 443)
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
    }

    private boolean tryExtractSni(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50)
            return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0)
            return false;

        Optional<String> sni = SniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni.isEmpty())
            return false;

        sniExtractions.incrementAndGet();
        AppType app = AppType.fromSni(sni.get());
        connTracker.classifyConnection(conn, app, sni.get());
        if (app != AppType.UNKNOWN && app != AppType.HTTPS)
            classificationHits.incrementAndGet();
        return true;
    }

    private boolean tryExtractHttpHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80)
            return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0)
            return false;

        Optional<String> host = HttpHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host.isEmpty())
            return false;

        AppType app = AppType.fromSni(host.get());
        connTracker.classifyConnection(conn, app, host.get());
        if (app != AppType.UNKNOWN && app != AppType.HTTP)
            classificationHits.incrementAndGet();
        return true;
    }

    // -------------------------------------------------------------------------
    // Rule checking
    // -------------------------------------------------------------------------
    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null)
            return PacketAction.FORWARD;

        RuleManager.BlockReason reason = ruleManager.shouldBlock(
                job.tuple.srcIp,
                job.tuple.dstPort,
                conn.appType,
                conn.sni);

        if (reason != null) {
            System.out.printf("[FP%d] BLOCKED packet: %s %s%n",
                    fpId, reason.type(), reason.detail());
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    // -------------------------------------------------------------------------
    // TCP state machine
    // -------------------------------------------------------------------------
    private void updateTcpState(Connection conn, int flags) {
        final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0)
                conn.synAckSeen = true;
            else
                conn.synSeen = true;
        }

        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW)
                conn.state = ConnectionState.ESTABLISHED;
        }

        if ((flags & FIN) != 0)
            conn.finSeen = true;
        if ((flags & RST) != 0)
            conn.state = ConnectionState.CLOSED;
        if (conn.finSeen && (flags & ACK) != 0)
            conn.state = ConnectionState.CLOSED;
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------
    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running;
    }

    public record FpStats(
            long packetsProcessed,
            long packetsForwarded,
            long packetsDropped,
            long connectionsTracked,
            long sniExtractions,
            long classificationHits) {
    }

    public FpStats getStats() {
        return new FpStats(
                packetsProcessed.get(),
                packetsForwarded.get(),
                packetsDropped.get(),
                connTracker.getActiveCount(),
                sniExtractions.get(),
                classificationHits.get());
    }
}
