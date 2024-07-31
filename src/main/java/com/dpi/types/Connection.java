package com.dpi.types;

import java.time.Instant;

/**
 * A tracked network connection / flow entry.
 * Equivalent to C++ struct Connection.
 *
 * Instances are owned by a single FastPathProcessor thread, so no
 * synchronization is needed on individual fields.
 */
public class Connection {

    public FiveTuple      tuple;
    public ConnectionState state    = ConnectionState.NEW;
    public AppType         appType  = AppType.UNKNOWN;
    public String          sni      = "";

    public long packetsIn  = 0;
    public long packetsOut = 0;
    public long bytesIn    = 0;
    public long bytesOut   = 0;

    public Instant firstSeen = Instant.now();
    public Instant lastSeen  = Instant.now();

    public PacketAction action = PacketAction.FORWARD;

    // TCP state flags
    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    public Connection(FiveTuple tuple) {
        this.tuple     = tuple;
        this.firstSeen = Instant.now();
        this.lastSeen  = this.firstSeen;
    }
}
