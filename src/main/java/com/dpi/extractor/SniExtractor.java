package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from a TLS Client Hello message.
 * Equivalent to C++ class SNIExtractor.
 *
 * TLS Client Hello format (brief):
 * Record Layer (5 bytes): content_type=0x16, version, length
 * Handshake (4 bytes): type=0x01, length (3 bytes)
 * Client Hello body: version(2), random(32), session_id, cipher_suites,
 * compression_methods, extensions
 * SNI extension type = 0x0000
 */
public class SniExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9)
            return false;
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE)
            return false;

        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304)
            return false;

        int recordLen = readUint16BE(payload, offset + 3);
        if (recordLen > length - 5)
            return false;

        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    /**
     * Extract SNI from a TLS Client Hello.
     * 
     * @param payload raw byte array
     * @param offset  start of TCP payload within the array
     * @param length  number of bytes of payload
     * @return Optional SNI hostname string
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length))
            return Optional.empty();

        int pos = offset + 5; // skip TLS record header

        // Handshake header: type(1) + length(3)
        if (pos + 4 > offset + length)
            return Optional.empty();
        // Skip handshake type (1 byte) + 3-byte length
        pos += 4;

        // Client Hello body
        pos += 2; // client version
        pos += 32; // random

        if (pos >= offset + length)
            return Optional.empty();

        // Session ID
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher suites
        if (pos + 2 > offset + length)
            return Optional.empty();
        int cipherSuitesLen = readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLen;

        // Compression methods
        if (pos >= offset + length)
            return Optional.empty();
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;

        // Extensions
        if (pos + 2 > offset + length)
            return Optional.empty();
        int extensionsLen = readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = Math.min(pos + extensionsLen, offset + length);

        // Iterate extensions
        while (pos + 4 <= extensionsEnd) {
            int extType = readUint16BE(payload, pos);
            int extLen = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extLen > extensionsEnd)
                break;

            if (extType == EXTENSION_SNI) {
                // SNI list: list_len(2) + type(1) + name_len(2) + name
                if (extLen < 5)
                    break;
                // sni_list_length at pos (skip it)
                int sniType = payload[pos + 2] & 0xFF;
                int sniLen = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME)
                    break;
                if (sniLen > extLen - 5)
                    break;

                String sni = new String(payload, pos + 5, sniLen);
                return Optional.of(sni);
            }
            pos += extLen;
        }

        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Big-endian helpers
    // -------------------------------------------------------------------------
    static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset + 2] & 0xFF);
    }
}
