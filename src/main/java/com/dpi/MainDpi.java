package com.dpi;

import com.dpi.engine.DpiEngine;
import com.dpi.engine.DpiEngineConfig;

/**
 * Full DPI Engine entry point.
 * Runs the complete multithreaded DPI pipeline on a PCAP file.
 * Equivalent to C++ src/main_dpi.cpp.
 *
 * Usage:
 * java com.dpi.MainDpi <input.pcap> [output.pcap] [rules_file]
 *
 * Examples:
 * java com.dpi.MainDpi test_dpi.pcap output.pcap
 * java com.dpi.MainDpi test_dpi.pcap output.pcap rules.txt
 */
public class MainDpi {

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args.length >= 2 ? args[1] : "output_java.pcap";
        String rulesFile = args.length >= 3 ? args[2] : "";

        // ---- Engine Configuration ----
        DpiEngineConfig config = new DpiEngineConfig();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.queueSize = 10_000;
        config.rulesFile = rulesFile;
        config.verbose = false;

        DpiEngine engine = new DpiEngine(config);

        // ---- Example blocking rules (mirror C++ demo) ----
        // Uncomment to activate:
        // engine.initialize();
        // engine.blockApp(AppType.YOUTUBE);
        // engine.blockDomain("*.ads.google.com");

        // ---- Process ----
        boolean success = engine.processFile(inputFile, outputFile);

        if (!success) {
            System.err.println("[MainDpi] Processing failed.");
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java com.dpi.MainDpi <input.pcap> [output.pcap] [rules_file]");
        System.out.println("\nArguments:");
        System.out.println("  input.pcap   - Source PCAP file to inspect");
        System.out.println("  output.pcap  - (Optional) Output PCAP (forwarded packets). Default: output_java.pcap");
        System.out.println("  rules_file   - (Optional) Blocking rules file");
        System.out.println("\nExamples:");
        System.out.println("  java com.dpi.MainDpi test_dpi.pcap");
        System.out.println("  java com.dpi.MainDpi test_dpi.pcap output.pcap");
        System.out.println("  java com.dpi.MainDpi test_dpi.pcap output.pcap rules.txt");
    }
}
