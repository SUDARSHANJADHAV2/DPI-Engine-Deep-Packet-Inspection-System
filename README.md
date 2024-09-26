# DPI Engine - Deep Packet Inspection System (Java)

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the multithreaded Java DPI Engine.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Multithreaded Version)](#5-the-journey-of-a-packet-multithreaded-version)
6. [Deep Dive: Each Component](#6-deep-dive-each-component)
7. [How SNI Extraction Works](#7-how-sni-extraction-works)
8. [How Blocking Works](#8-how-blocking-works)
9. [Building and Running](#9-building-and-running)
10. [Understanding the Output](#10-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │ (Java)      │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Modes

| Mode | Entry Point | Use Case |
|---------|------|----------|
| Packet Analyzer | `com.dpi.Main` | Fast packet header inspection & printing |
| Full DPI Engine | `com.dpi.MainDpi` | Complete multithreaded DPI, classification, blocking, and output generation |

---

## 4. File Structure

This project is written purely in **Java** with no external dependencies (only standard Java modules).

```
DPI-Engine-Deep-Packet-Inspection-System/
├── pom.xml                    # Maven build file (optional, pure javac also supported)
├── src/main/java/com/dpi/
│   ├── Main.java              # Packet analyzer entry point
│   ├── MainDpi.java           # Full DPI engine entry point
│   │
│   ├── types/                 # Data structures
│   │   ├── AppType.java       # Application classification enums & SNI mapping
│   │   ├── FiveTuple.java     # Hashable 5-tuple record
│   │   ├── Connection.java    # Flow tracker state
│   │   └── PacketJob.java     # Payload wrapper
│   │
│   ├── pcap/                  # Binary PCAP handling (endianness aware)
│   │   ├── PcapReader.java    # Reads PCAP packet by packet
│   │   └── PcapWriter.java    # Writes output PCAP
│   │
│   ├── parser/                # Protocol dissection
│   │   └── PacketParser.java  # Ethernet, IPv4, TCP, UDP parser
│   │
│   ├── extractor/             # Layer 7 payload parsing
│   │   ├── SniExtractor.java  # TLS SNI from Client Hello
│   │   ├── HttpHostExtractor.java
│   │   └── DnsExtractor.java
│   │
│   ├── tracker/               # Flow state management
│   │   └── ConnectionTracker.java # Per-thread flow table with LRU eviction
│   │
│   ├── rules/                 # Filtering logic
│   │   └── RuleManager.java   # IP, Domain, App, Port blocking (Thread-safe)
│   │
│   ├── queue/                 # Thread-safe bounds
│   │   └── ThreadSafeQueue.java # Wraps ArrayBlockingQueue for concurrency
│   │
│   ├── pipeline/              # Concurrency / Multithreading
│   │   ├── LoadBalancer.java  # Dispatches packets to FP using consistent hashing
│   │   └── FastPathProcessor.java # DPI worker thread (tracks, inspects, rules)
│   │
│   └── engine/                # Main orchestrator
│       └── DpiEngine.java     # Ties everything together + stats reporting
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Multithreaded Version)

The engine uses a highly concurrent architecture to process maximum throughput:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │ hash(5-tuple) % NumLBs      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % fps   │               │hash % fps   │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(FastPath)│ │(FastPath)│   │(FastPath)│ │(FastPath)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Receive packets from the reader and dispatch quickly.
2. **Fast Paths (FPs):** Do the actual heavy lifting (parsing, DPI inspection, tracking, rule enforcement).
3. **Consistent Hashing:** Ensuring the same 5-tuple *always* maps to the same FP thread.

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)
```
All packets of this connection go to FP2. This means FP2 can simply use a non-thread-safe local `HashMap` for lightning fast connection tracking, without incurring lock contention.

---

## 6. Deep Dive: Each Component

### PCAP Handling (`PcapReader.java`, `PcapWriter.java`)

**Purpose:** Read network captures saved by Wireshark directly from binary bytes. The reader handles endian-swapping transparently if you're loading a PCAP from a different architecture.

### Packet Parsing (`PacketParser.java`)

**Purpose:** Extract protocol fields from raw byte arrays using careful bit-shifting and masking logic to bypass Java's lack of unsigned types.

```java
// Example: Converting unsigned bits from a byte array
long seqNumber = ((data[offset + 4] & 0xFFL) << 24) |
                 ((data[offset + 5] & 0xFFL) << 16) |
                 ((data[offset + 6] & 0xFFL) <<  8) |
                  (data[offset + 7] & 0xFFL);
```

### SNI Extraction (`SniExtractor.java`)

**Purpose:** Deep packet inspection of TLS Client Hello structures. Parses the raw bytes to skip past the handshake types, session ID, cipher suites, etc., directly to the Extensions array to pull out SNI (Server Name Indication).

### Data Types (`FiveTuple.java`, `AppType.java`)

- `FiveTuple`: A precise Java `record` implementation containing IPs, Ports, and Protocol. Provides a highly mixed `hashCode()` to ensure even distribution across threads.
- `AppType`: Contains mappings from parsed SNI domains to identified apps (e.g. SNI `*.youtube.com` maps to `AppType.YOUTUBE`).

### Concurrency primitives (`ThreadSafeQueue.java`, `AtomicLong`)

A bounded queue using `ArrayBlockingQueue` connects the threads. Global statistics use standard `AtomicLong` to prevent racing across multiple FP threads when recording results. Filtering rules use `ReentrantReadWriteLock` so reading rules is contention-free but writing a new rule safely locks correctly.

---

## 7. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the very first data packet!**
Once extracted, we save the result in the `ConnectionTracker`.

### Extraction Steps (Simplified)
1. Verify TLS record header (Content Type `0x16`).
2. Verify Handshake type (Client Hello `0x01`).
3. Skip structural fields (Session Length, Cipher Suites Length).
4. Parse Extensions array until `Type 0x00` (SNI) is found.
5. Parse string length and extract ASCII string.

---

## 8. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from/to this IP |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |
| Port | `8080` | Any port 8080 traffic |

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello (packet 4).
- Once identified, we cache the result on the `Connection` object itself. Next time we process a packet matching that 5-tuple, we instantly drop it without inspecting the payload further.

---

## 9. Building and Running

### Prerequisites
- **Java 17+** (tested natively with Java 25)
- **No external libraries** — pure Java standard library only
- Optional: **Maven 3.6+** for `mvn compile` support

### Compile

**Using `javac` (fastest, no config required):**
```bash
# Linux / macOS
javac --release 17 -d out $(find src -name "*.java")

# Windows (PowerShell)
javac --release 17 -d out (Get-ChildItem -Recurse src -Filter *.java).FullName
```

**Using Maven (optional):**
```bash
mvn compile
```

### Running the Output

**Packet Analyzer mode** — prints packet headers (diagnostic mode):
```bash
java -cp out com.dpi.Main test_dpi.pcap [max_packets]

# Example: show first 10 packets
java -cp out com.dpi.Main test_dpi.pcap 10
```

**Full DPI Engine mode** — run the DPI multithreaded engine end-to-end:
```bash
java -cp out com.dpi.MainDpi <input.pcap> [output.pcap] [rules_file]

# Example: run the DPI pipeline against sample data
java -cp out com.dpi.MainDpi test_dpi.pcap output_java.pcap

# Example: with a blocking rules text file
java -cp out com.dpi.MainDpi test_dpi.pcap output_java.pcap rules.txt
```

### Blocking Rules File Format (`rules.txt`)

Create a plain-text file to feed to the engine:
```ini
[BLOCKED_IPS]
192.168.1.50
10.0.0.5

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.ads.google.com
facebook.com

[BLOCKED_PORTS]
8080
```

---

## 10. Understanding the Output

### Sample Engine Output

```text
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                           ║
║               Deep Packet Inspection System                  ║
╠══════════════════════════════════════════════════════════════╣
║ Configuration:                                               ║
║   Load Balancers:      2                                     ║
║   FPs per LB:          2                                     ║
║   Total FP threads:    4                                     ║
╚══════════════════════════════════════════════════════════════╝

[DpiEngine] Processing: test_dpi.pcap
[Reader] Starting packet processing...
[Reader] Finished reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE STATISTICS                     ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                            ║
║   Total Packets:                77                           ║
║   Total Bytes:                5738                           ║
║   TCP Packets:                  73                           ║
║   UDP Packets:                   4                           ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                         ║
║   Forwarded:                    77                           ║
║   Dropped/Blocked:               0                           ║
║   Drop Rate:                  0.00%                          ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                 APPLICATION CLASSIFICATION REPORT            ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:            43                             ║
║ Classified:                   22 (51.2%)                     ║
║ Unidentified:                 21 (48.8%)                     ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION DISTRIBUTION                  ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown               21  48.8% #########                    ║
║ DNS                    4   9.3% #                            ║
║ Twitter/X              3   7.0% #                            ║
║ HTTPS                  2   4.7%                              ║
║ Google                 1   2.3%                              ║
║ YouTube                1   2.3%                              ║
║ Facebook               1   2.3%                              ║
╚══════════════════════════════════════════════════════════════╝
```

### What Each Section Means

- **Configuration**: Shows the thread topology generated by your settings.
- **Packet/Filtering Statistics**: Aggregated across all `AtomicLong` counters from the threads.
- **Application Report**: Extracted from the `GlobalConnectionTable`, shows exactly what traffic passed through the system by extracting the SNI/DNS/Host payload strings and cross-referencing them with known app patterns.

Happy inspecting! 🚀
