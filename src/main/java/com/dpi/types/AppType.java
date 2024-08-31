package com.dpi.types;

/**
 * Application types identified by the DPI engine via SNI / HTTP Host / port heuristics.
 * Equivalent to C++ enum class AppType.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    /** Look up AppType by display name string (case-insensitive). */
    public static AppType fromString(String name) {
        if (name == null) return UNKNOWN;
        for (AppType t : values()) {
            if (t.displayName.equalsIgnoreCase(name) || t.name().equalsIgnoreCase(name)) {
                return t;
            }
        }
        return UNKNOWN;
    }

    /**
     * Map an SNI / HTTP Host string to the best-matching AppType.
     * Equivalent to C++ sniToAppType().
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be")
                || s.contains("yt3.ggpht")) return YOUTUBE;

        if (s.contains("instagram") || s.contains("cdninstagram")) return INSTAGRAM;

        if (s.contains("whatsapp") || s.contains("wa.me")) return WHATSAPP;

        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com")
                || s.contains("fbsbx") || s.contains("meta.com")) return FACEBOOK;

        if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com")
                || s.contains("t.co")) return TWITTER;

        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg")) return NETFLIX;

        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront")
                || s.contains("aws")) return AMAZON;

        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office")
                || s.contains("azure") || s.contains("live.com") || s.contains("outlook")
                || s.contains("bing")) return MICROSOFT;

        if (s.contains("apple") || s.contains("icloud") || s.contains("mzstatic")
                || s.contains("itunes")) return APPLE;

        if (s.contains("telegram") || s.contains("t.me")) return TELEGRAM;

        if (s.contains("tiktok") || s.contains("tiktokcdn") || s.contains("musical.ly")
                || s.contains("bytedance")) return TIKTOK;

        if (s.contains("spotify") || s.contains("scdn.co")) return SPOTIFY;

        if (s.contains("zoom")) return ZOOM;

        if (s.contains("discord") || s.contains("discordapp")) return DISCORD;

        if (s.contains("github") || s.contains("githubusercontent")) return GITHUB;

        if (s.contains("cloudflare") || s.contains("cf-")) return CLOUDFLARE;

        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis")
                || s.contains("ggpht") || s.contains("gvt1")) return GOOGLE;

        // SNI present but unrecognized — still TLS-encrypted
        return HTTPS;
    }
}
