#pragma once

#include <cstdint>
#include <optional>
#include <string>

// ─── SNI / Host extraction from raw TCP payloads ────────────────────────
//
// Extracts the Server Name Indication (SNI) from TLS Client Hello messages
// and the Host header from plaintext HTTP requests.
//
// Only the FIRST packet of an HTTPS flow carries the Client Hello;
// subsequent packets are encrypted application data (Content Type 0x17)
// and will correctly return std::nullopt.

class SNIExtractor {
public:
    // ── TLS ────────────────────────────────────────────────────────────

    /// Quick check: is this a TLS Client Hello?
    /// Returns true if payload[0] == 0x16 (Handshake) and
    ///                payload[5] == 0x01 (Client Hello).
    static bool isTLSClientHello(const uint8_t* payload, size_t len);

    /// Walk the TLS Client Hello extensions and return the SNI hostname.
    /// Returns std::nullopt if the payload is not a Client Hello, is
    /// truncated, or does not contain an SNI extension.
    static std::optional<std::string> extractTLS(
        const uint8_t* payload, size_t len);

    // ── HTTP ───────────────────────────────────────────────────────────

    /// Quick check: does the payload start with an HTTP method verb?
    static bool isHTTPRequest(const uint8_t* payload, size_t len);

    /// Extract the value of the "Host:" header from an HTTP request.
    /// Returns std::nullopt if the header is absent.
    static std::optional<std::string> extractHTTPHost(
        const uint8_t* payload, size_t len);
};
