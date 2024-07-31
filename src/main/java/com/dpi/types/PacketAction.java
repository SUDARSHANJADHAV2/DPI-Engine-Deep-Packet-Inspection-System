package com.dpi.types;

/**
 * Disposition of a packet after DPI inspection.
 * Equivalent to C++ enum class PacketAction.
 */
public enum PacketAction {
    FORWARD,    // Pass to internet
    DROP,       // Block / discard
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
