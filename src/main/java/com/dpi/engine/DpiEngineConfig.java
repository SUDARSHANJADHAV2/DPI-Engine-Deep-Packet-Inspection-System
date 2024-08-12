package com.dpi.engine;

/**
 * DPI Engine configuration.
 * Equivalent to C++ struct DPIEngine::Config.
 */
public class DpiEngineConfig {

    public int numLoadBalancers = 2;
    public int fpsPerLb = 2;
    public int queueSize = 10_000;
    public String rulesFile = "";
    public boolean verbose = false;

    /** Convenience constructor. */
    public DpiEngineConfig() {
    }

    public DpiEngineConfig(int numLoadBalancers, int fpsPerLb) {
        this.numLoadBalancers = numLoadBalancers;
        this.fpsPerLb = fpsPerLb;
    }
}
