package com.dpi.pipeline;

import com.dpi.queue.ThreadSafeQueue;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.ArrayList;
import java.util.List;

/**
 * Creates and manages a pool of LoadBalancer threads.
 * Equivalent to C++ class LBManager.
 */
public class LbManager {

    private final List<LoadBalancer> lbs = new ArrayList<>();

    public LbManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int fpStart = lbId * fpsPerLb;
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = fpQueues.subList(fpStart, fpStart + fpsPerLb);
            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.printf("[LBManager] Created %d load balancers, %d FPs each%n", numLbs, fpsPerLb);
    }

    public void startAll() {
        lbs.forEach(LoadBalancer::start);
    }

    public void stopAll() {
        lbs.forEach(LoadBalancer::stop);
    }

    public LoadBalancer getLb(int id) {
        return lbs.get(id);
    }

    public int getNumLbs() {
        return lbs.size();
    }

    /** Select the target LB for the given packet via five-tuple hash. */
    public LoadBalancer getLbForPacket(FiveTuple tuple) {
        int idx = (int) (Integer.toUnsignedLong(tuple.hashCode()) % lbs.size());
        return lbs.get(idx);
    }

    public record AggregatedStats(long totalReceived, long totalDispatched) {
    }

    public AggregatedStats getAggregatedStats() {
        long recv = 0, disp = 0;
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LbStats s = lb.getStats();
            recv += s.packetsReceived();
            disp += s.packetsDispatched();
        }
        return new AggregatedStats(recv, disp);
    }
}
