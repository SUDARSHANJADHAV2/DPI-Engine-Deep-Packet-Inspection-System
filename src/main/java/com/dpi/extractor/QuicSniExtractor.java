package com.dpi.extractor;

import java.util.Optional;

/**
 * Simplified QUIC SNI extractor.
 * Equivalent to C++ class QUICSNIExtractor.
 *
 * QUIC Initial packets embed a TLS Client Hello in CRYPTO frames.
 * Full parsing is complex; we do a best-effort search for the TLS CH pattern.
 */
public class QuicSniExtractor {

    public static boolean isQuicInitial(byte[] payload, int offset, int length) {
        if (length < 5)
            return false;
        // Long header: bit 7 of first byte must be set
        return (payload[offset] & 0x80) != 0;
    }

    /**
     * Try to extract an SNI from a QUIC Initial packet by searching for
     * an embedded TLS Client Hello.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQuicInitial(payload, offset, length))
            return Optional.empty();

        // Scan for a Client Hello handshake type byte (0x01)
        // and attempt TLS SNI extraction starting 5 bytes before it
        for (int i = offset; i + 50 < offset + length; i++) {
            if ((payload[i] & 0xFF) == 0x01) {
                int tryOffset = i - 5;
                if (tryOffset < offset)
                    tryOffset = offset;
                int tryLen = offset + length - tryOffset;

                Optional<String> result = SniExtractor.extract(payload, tryOffset, tryLen);
                if (result.isPresent())
                    return result;
            }
        }
        return Optional.empty();
    }
}
