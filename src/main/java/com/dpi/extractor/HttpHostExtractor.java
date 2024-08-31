package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the HTTP "Host:" header from unencrypted HTTP/1.x requests.
 * Equivalent to C++ class HTTPHostExtractor.
 */
public class HttpHostExtractor {

    private static final byte[][] HTTP_METHODS = {
            "GET ".getBytes(), "POST".getBytes(), "PUT ".getBytes(),
            "HEAD".getBytes(), "DELE".getBytes(), "PATC".getBytes(), "OPTI".getBytes()
    };

    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4)
            return false;
        for (byte[] method : HTTP_METHODS) {
            if (offset + 4 <= payload.length
                    && (payload[offset] & 0xFF) == (method[0] & 0xFF)
                    && (payload[offset + 1] & 0xFF) == (method[1] & 0xFF)
                    && (payload[offset + 2] & 0xFF) == (method[2] & 0xFF)
                    && (payload[offset + 3] & 0xFF) == (method[3] & 0xFF)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract the "Host" header value from an HTTP request payload.
     * 
     * @return Optional host string (without port)
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length))
            return Optional.empty();

        int end = offset + length;

        // Scan for "host:" (case-insensitive)
        for (int i = offset; i + 5 < end; i++) {
            int b0 = payload[i] & 0xFF;
            int b1 = payload[i + 1] & 0xFF;
            int b2 = payload[i + 2] & 0xFF;
            int b3 = payload[i + 3] & 0xFF;
            int b4 = payload[i + 4] & 0xFF;

            boolean h = (b0 == 'H' || b0 == 'h');
            boolean o = (b1 == 'O' || b1 == 'o');
            boolean s = (b2 == 'S' || b2 == 's');
            boolean t = (b3 == 'T' || b3 == 't');
            boolean c = (b4 == ':');

            if (h && o && s && t && c) {
                // Skip whitespace after ':'
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t'))
                    start++;

                // Find end of line
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n')
                    lineEnd++;

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start).trim();
                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos >= 0)
                        host = host.substring(0, colonPos);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }
}
