package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS request packet.
 * Equivalent to C++ class DNSExtractor.
 *
 * DNS header is 12 bytes; QNAME starts at byte 12.
 */
public class DnsExtractor {

    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12)
            return false;
        // QR bit (bit 7 of byte 2) should be 0 for query
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0)
            return false; // response, not query
        // QDCOUNT > 0
        int qdcount = SniExtractor.readUint16BE(payload, offset + 4);
        return qdcount > 0;
    }

    /**
     * Extract the queried domain name from a DNS request.
     */
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length))
            return Optional.empty();

        int pos = offset + 12; // skip DNS header
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLen = payload[pos] & 0xFF;
            if (labelLen == 0)
                break; // end of QNAME

            if (labelLen > 63)
                break; // compression pointer or invalid

            pos++;
            if (pos + labelLen > end)
                break;

            if (domain.length() > 0)
                domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        if (domain.length() == 0)
            return Optional.empty();
        return Optional.of(domain.toString());
    }
}
