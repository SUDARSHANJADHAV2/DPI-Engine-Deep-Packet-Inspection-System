package com.dpi.types;

/**
 * Connection state machine states.
 * Equivalent to C++ enum class ConnectionState.
 */
public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
}
