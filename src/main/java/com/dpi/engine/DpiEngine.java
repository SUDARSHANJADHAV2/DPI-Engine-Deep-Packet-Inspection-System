package com.dpi.engine;

import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.*;
import com.dpi.pipeline.*;
import com.dpi.queue.ThreadSafeQueue;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.GlobalConnectionTable;
import com.dpi.types.*;

import java.util.List;

/**
 * Main DPI Engine orchestrator.
 * Equivalent to C++ class DPIEngine.
 *
 * Architecture (same as C++ ASCII diagram):
 * PcapReader → LB threads → FP threads → OutputQueue → PcapWriter
 */
public class DpiEngine {

    private final DpiEngineConfig config;

    // Shared components
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;

    // Thread pools
    private FpManager fpManager;
    private LbManager lbManager;

    // Output pipeline
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private Thread outputThread;
    private PcapWriter pcapWriter;
    private PcapGlobalHeader inputHeader;

    // Statistics
    private final DpiStats stats = new DpiStats();

    // Control
    private volatile boolean running = false;
    private Thread readerThread;

    public DpiEngine(DpiEngineConfig config) {
        this.config = config;
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Configuration:                                                ║%n");
        System.out.printf("║   Load Balancers:    %3d                                       ║%n",
                config.numLoadBalancers);
        System.out.printf("║   FPs per LB:        %3d                                       ║%n", config.fpsPerLb);
        System.out.printf("║   Total FP threads:  %3d                                       ║%n",
                config.numLoadBalancers * config.fpsPerLb);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public boolean initialize() {
        ruleManager = new RuleManager();

        if (!config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;

        // Output callback: called by each FP after it decides FORWARD/DROP
        var outputCallback = (java.util.function.BiConsumer<PacketJob, PacketAction>) (job, action) -> handleOutput(job,
                action);

        // Create FP manager
        fpManager = new FpManager(totalFps, ruleManager, outputCallback);

        // Create LB manager (connects to FP queues)
        List<ThreadSafeQueue<PacketJob>> fpQueues = fpManager.getQueues();
        lbManager = new LbManager(config.numLoadBalancers, config.fpsPerLb, fpQueues);

        // Create global connection table
        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFp(i).getConnectionTracker());
        }

        System.out.println("[DpiEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running)
            return;
        running = true;

        // Start output thread first
        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.setDaemon(true);
        outputThread.start();

        // Start FP and LB threads
        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DpiEngine] All threads started");
    }

    public void stop() {
        if (!running)
            return;
        running = false;

        lbManager.stopAll();
        fpManager.stopAll();

        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DpiEngine] All threads stopped");
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        // Let queues drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Process a PCAP file end-to-end.
     * 
     * @param inputFile  path to source PCAP
     * @param outputFile path to write forwarded packets PCAP
     */
    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DpiEngine] Processing: " + inputFile);
        System.out.println("[DpiEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null && !initialize())
            return false;

        // Open output PCAP writer
        pcapWriter = new PcapWriter();
        if (!pcapWriter.open(outputFile))
            return false;

        start();

        // Launch reader in background thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
        readerThread.start();

        waitForCompletion();

        // Give time for last packets to flush
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {
        }

        stop();
        pcapWriter.close();

        System.out.println(generateReport());
        System.out.println(fpManager.generateClassificationReport());

        return true;
    }

    // =========================================================================
    // Reader thread
    // =========================================================================
    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file");
                return;
            }

            inputHeader = reader.getGlobalHeader();
            pcapWriter.writeGlobalHeader(inputHeader);

            System.out.println("[Reader] Starting packet processing...");
            int packetId = 0;
            RawPacket raw;

            while ((raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null)
                    continue;
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp))
                    continue;

                PacketJob job = createPacketJob(raw, parsed, packetId++);

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);

                if (parsed.hasTcp)
                    stats.tcpPackets.incrementAndGet();
                else if (parsed.hasUdp)
                    stats.udpPackets.incrementAndGet();

                LoadBalancer lb = lbManager.getLbForPacket(job.tuple);
                lb.getInputQueue().push(job);
            }

            System.out.println("[Reader] Finished reading " + packetId + " packets");
        }
    }

    // =========================================================================
    // PacketJob factory
    // =========================================================================
    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;

        // Build five-tuple from parsed IP strings
        long srcIp = FiveTuple.parseIp(parsed.srcIp);
        long dstIp = FiveTuple.parseIp(parsed.destIp);
        job.tuple = new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);

        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data;

        // Calculate offsets
        job.ethOffset = 0;
        job.ipOffset = 14;

        if (raw.data.length > 14) {
            int ipIhl = raw.data[14] & 0x0F;
            int ipHdrLen = ipIhl * 4;
            job.transportOffset = 14 + ipHdrLen;

            if (parsed.hasTcp && raw.data.length > job.transportOffset) {
                int tcpDataOffset = (raw.data[job.transportOffset + 12] & 0xFF) >> 4;
                int tcpHdrLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHdrLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }

            if (job.payloadOffset < raw.data.length) {
                job.payloadLength = raw.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    // =========================================================================
    // Output thread
    // =========================================================================
    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            PacketJob job = outputQueue.popWithTimeout(100);
            if (job != null && pcapWriter != null) {
                pcapWriter.writePacket(job.tsSec, job.tsUsec, job.data);
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    // =========================================================================
    // Rule Management API
    // =========================================================================
    public void blockIp(String ip) {
        if (ruleManager != null)
            ruleManager.blockIp(ip);
    }

    public void unblockIp(String ip) {
        if (ruleManager != null)
            ruleManager.unblockIp(ip);
    }

    public void blockApp(AppType app) {
        if (ruleManager != null)
            ruleManager.blockApp(app);
    }

    public void unblockApp(AppType app) {
        if (ruleManager != null)
            ruleManager.unblockApp(app);
    }

    public void blockDomain(String d) {
        if (ruleManager != null)
            ruleManager.blockDomain(d);
    }

    public void unblockDomain(String d) {
        if (ruleManager != null)
            ruleManager.unblockDomain(d);
    }

    public boolean loadRules(String f) {
        return ruleManager != null && ruleManager.loadRules(f);
    }

    public boolean saveRules(String f) {
        return ruleManager != null && ruleManager.saveRules(f);
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    // =========================================================================
    // Reporting
    // =========================================================================
    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ PACKET STATISTICS                                             ║\n");
        sb.append(String.format("║   Total Packets:      %12d                        ║%n", stats.totalPackets.get()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║%n", stats.totalBytes.get()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║%n", stats.tcpPackets.get()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║%n", stats.udpPackets.get()));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ FILTERING STATISTICS                                          ║\n");
        sb.append(
                String.format("║   Forwarded:          %12d                        ║%n", stats.forwardedPackets.get()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║%n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║%n", dropRate));
        }

        if (lbManager != null) {
            LbManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            sb.append(
                    String.format("║   LB Received:        %12d                        ║%n", lbStats.totalReceived()));
            sb.append(String.format("║   LB Dispatched:      %12d                        ║%n",
                    lbStats.totalDispatched()));
        }

        if (fpManager != null) {
            FpManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ FAST PATH STATISTICS                                          ║\n");
            sb.append(
                    String.format("║   FP Processed:       %12d                        ║%n", fpStats.totalProcessed()));
            sb.append(
                    String.format("║   FP Forwarded:       %12d                        ║%n", fpStats.totalForwarded()));
            sb.append(String.format("║   FP Dropped:         %12d                        ║%n", fpStats.totalDropped()));
            sb.append(String.format("║   Active Connections: %12d                        ║%n",
                    fpStats.totalConnections()));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats rs = ruleManager.getStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ BLOCKING RULES                                                ║\n");
            sb.append(String.format("║   Blocked IPs:        %12d                        ║%n", rs.blockedIps()));
            sb.append(String.format("║   Blocked Apps:       %12d                        ║%n", rs.blockedApps()));
            sb.append(String.format("║   Blocked Domains:    %12d                        ║%n", rs.blockedDomains()));
            sb.append(String.format("║   Blocked Ports:      %12d                        ║%n", rs.blockedPorts()));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public DpiStats getStats() {
        return stats;
    }

    public DpiEngineConfig getConfig() {
        return config;
    }

    public boolean isRunning() {
        return running;
    }
}
