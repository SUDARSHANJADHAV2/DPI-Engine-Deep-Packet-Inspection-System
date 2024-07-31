package com.dpi.rules;

import com.dpi.types.AppType;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages IP/application/domain/port blocking rules.
 * Equivalent to C++ class RuleManager.
 *
 * Thread-safe for concurrent reads from multiple FP threads.
 * Uses ReentrantReadWriteLock (equivalent to C++ std::shared_mutex).
 */
public class RuleManager {

    // ---- Blocked IPs: stored as long (unsigned 32-bit) ----
    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Long> blockedIps = new HashSet<>();

    // ---- Blocked Apps ----
    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = EnumSet.noneOf(AppType.class);

    // ---- Blocked Domains (exact + wildcard patterns) ----
    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();

    // ---- Blocked Ports ----
    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    // =========================================================================
    // IP Blocking
    // =========================================================================

    public void blockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip & 0xFFFFFFFFL);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIp(String ip) {
        blockIp(parseIp(ip));
    }

    public void unblockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip & 0xFFFFFFFFL);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
    }

    public void unblockIp(String ip) {
        unblockIp(parseIp(ip));
    }

    public boolean isIpBlocked(long ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip & 0xFFFFFFFFL);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIps() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedIps.size());
            for (long ip : blockedIps)
                result.add(ipToString(ip));
            return result;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // =========================================================================
    // App Blocking
    // =========================================================================

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked app: " + app.getDisplayName());
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked app: " + app.getDisplayName());
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // =========================================================================
    // Domain Blocking
    // =========================================================================

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain.toLowerCase(Locale.ROOT));
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain.toLowerCase(Locale.ROOT));
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty())
            return false;
        String lower = domain.toLowerCase(Locale.ROOT);

        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(lower))
                return true;
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase(Locale.ROOT)))
                    return true;
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    // =========================================================================
    // Port Blocking
    // =========================================================================

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port & 0xFFFF);
        } finally {
            portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked port: " + (port & 0xFFFF));
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port & 0xFFFF);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port & 0xFFFF);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // =========================================================================
    // Combined check
    // =========================================================================

    public enum BlockReasonType {
        IP, APP, DOMAIN, PORT
    }

    public record BlockReason(BlockReasonType type, String detail) {
    }

    /**
     * Returns a BlockReason if the packet should be dropped, or null if allowed.
     */
    public BlockReason shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp))
            return new BlockReason(BlockReasonType.IP, ipToString(srcIp));
        if (isPortBlocked(dstPort))
            return new BlockReason(BlockReasonType.PORT, String.valueOf(dstPort & 0xFFFF));
        if (isAppBlocked(app))
            return new BlockReason(BlockReasonType.APP, app.getDisplayName());
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain))
            return new BlockReason(BlockReasonType.DOMAIN, domain);
        return null;
    }

    // =========================================================================
    // Persistence (save / load rules file)
    // =========================================================================

    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIps())
                pw.println(ip);

            pw.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps())
                pw.println(app.getDisplayName());

            pw.println("\n[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains())
                pw.println(d);

            pw.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int p : blockedPorts)
                    pw.println(p);
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty())
                    continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]" -> blockIp(line);
                    case "[BLOCKED_APPS]" -> {
                        AppType a = AppType.fromString(line);
                        if (a != AppType.UNKNOWN)
                            blockApp(a);
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> {
                        try {
                            blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        try {
            blockedIps.clear();
        } finally {
            ipLock.writeLock().unlock();
        }
        appLock.writeLock().lock();
        try {
            blockedApps.clear();
        } finally {
            appLock.writeLock().unlock();
        }
        domainLock.writeLock().lock();
        try {
            blockedDomains.clear();
            domainPatterns.clear();
        } finally {
            domainLock.writeLock().unlock();
        }
        portLock.writeLock().lock();
        try {
            blockedPorts.clear();
        } finally {
            portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] All rules cleared");
    }

    // ---- Inner stats record ----
    public record RuleStats(long blockedIps, long blockedApps, long blockedDomains, long blockedPorts) {
    }

    public RuleStats getStats() {
        return new RuleStats(
                getBlockedIps().size(),
                getBlockedApps().size(),
                getBlockedDomains().size(),
                blockedPorts.size());
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    public static long parseIp(String ip) {
        if (ip == null || ip.isEmpty())
            return 0L;
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4)
            return 0L;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            try {
                result |= (Long.parseLong(parts[i].trim()) & 0xFF) << (i * 8);
            } catch (NumberFormatException ignored) {
            }
        }
        return result;
    }

    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip) & 0xFF,
                (ip >> 8) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 24) & 0xFF);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            if (domain.endsWith(suffix))
                return true;
            if (domain.equals(pattern.substring(2)))
                return true; // bare match
        }
        return false;
    }
}
