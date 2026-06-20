#include "sni_extractor.h"

#include <cstring>    // strncmp
#include <algorithm>  // std::min

#ifdef _WIN32
  #include <winsock2.h>   // ntohs
#else
  #include <arpa/inet.h>  // ntohs
#endif

// ═══════════════════════════════════════════════════════════════════════════
// isTLSClientHello — quick 2-byte gate
// ═══════════════════════════════════════════════════════════════════════════

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t len)
{
    // Need at least 6 bytes: TLS Record Header (5) + Handshake Type (1)
    if (len < 6) return false;

    // Content Type 0x16 = Handshake
    if (payload[0] != 0x16) return false;

    // Handshake Type 0x01 = Client Hello
    if (payload[5] != 0x01) return false;

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// extractTLS — full Client Hello walk → SNI hostname
// ═══════════════════════════════════════════════════════════════════════════
//
// TLS Record Layout (all multi-byte fields are big-endian):
//
//   [0]       Content Type    (0x16 = Handshake)
//   [1-2]     TLS Version
//   [3-4]     Record Length
//   ---- Handshake Header ----
//   [5]       Handshake Type  (0x01 = Client Hello)
//   [6-8]     Handshake Length (3 bytes)
//   ---- Client Hello Body ----
//   [9-10]    Client Version
//   [11-42]   Random          (32 bytes, fixed size)
//   [43]      Session ID Length (S)
//   [44..44+S-1] Session ID
//   ...cipher suites, compression, extensions...

std::optional<std::string> SNIExtractor::extractTLS(
    const uint8_t* payload, size_t len)
{
    // Step 1: need at least through the Random block
    if (len < 10) return std::nullopt;

    // Step 2: Content Type must be Handshake (0x16)
    if (payload[0] != 0x16) return std::nullopt;

    // Step 3: Handshake Type must be Client Hello (0x01)
    if (payload[5] != 0x01) return std::nullopt;

    // Step 4: offset points at Session ID Length byte
    size_t offset = 43;

    // Step 5: bounds check
    if (offset >= len) return std::nullopt;

    // Step 6: read Session ID Length
    uint8_t session_id_len = payload[offset++];

    // Step 7: skip Session ID
    offset += session_id_len;

    // Step 8: need 2 bytes for Cipher Suites Length
    if (offset + 2 > len) return std::nullopt;

    // Step 9: read & skip Cipher Suites
    uint16_t cipher_len;
    std::memcpy(&cipher_len, payload + offset, 2);
    cipher_len = ntohs(cipher_len);
    offset += 2 + cipher_len;

    // Step 10: need 1 byte for Compression Methods Length
    if (offset + 1 > len) return std::nullopt;

    // Step 11: read & skip Compression Methods
    uint8_t comp_len = payload[offset++];
    offset += comp_len;

    // Step 12: need 2 bytes for Extensions Total Length
    if (offset + 2 > len) return std::nullopt;

    // Step 13: read Extensions Total Length
    uint16_t extensions_total;
    std::memcpy(&extensions_total, payload + offset, 2);
    extensions_total = ntohs(extensions_total);
    offset += 2;

    // Step 14: compute end-of-extensions boundary
    size_t ext_end = offset + extensions_total;

    // Step 15: walk extensions one by one
    while (offset + 4 <= ext_end && offset + 4 <= len)
    {
        // (a) Extension Type
        uint16_t ext_type;
        std::memcpy(&ext_type, payload + offset, 2);
        ext_type = ntohs(ext_type);
        offset += 2;

        // (b) Extension Data Length
        uint16_t ext_len;
        std::memcpy(&ext_len, payload + offset, 2);
        ext_len = ntohs(ext_len);
        offset += 2;

        // (c) SNI extension (type 0x0000)
        if (ext_type == 0x0000)
        {
            // Need at least 3 bytes: SNI List Length (2) + SNI Type (1)
            if (offset + 3 > len) return std::nullopt;

            // Skip SNI List Length (2 bytes) + SNI Type (1 byte)
            offset += 3;

            // Need 2 bytes for SNI Name Length
            if (offset + 2 > len) return std::nullopt;

            uint16_t name_len;
            std::memcpy(&name_len, payload + offset, 2);
            name_len = ntohs(name_len);
            offset += 2;

            // Need name_len bytes for the actual hostname
            if (offset + name_len > len) return std::nullopt;

            // The hostname is NOT null-terminated — construct directly
            return std::string(
                reinterpret_cast<const char*>(payload + offset),
                name_len);
        }

        // (d) Not SNI — skip this extension's data
        offset += ext_len;
    }

    // Step 16: walked all extensions, no SNI found
    return std::nullopt;
}

// ═══════════════════════════════════════════════════════════════════════════
// isHTTPRequest — checks for standard HTTP method prefix
// ═══════════════════════════════════════════════════════════════════════════

bool SNIExtractor::isHTTPRequest(const uint8_t* payload, size_t len)
{
    if (len < 4) return false;

    const char* p = reinterpret_cast<const char*>(payload);

    return std::strncmp(p, "GET ",  4) == 0 ||
           std::strncmp(p, "POST",  4) == 0 ||
           std::strncmp(p, "PUT ",  4) == 0 ||
           std::strncmp(p, "HEAD",  4) == 0 ||
           std::strncmp(p, "DELE",  4) == 0 ||
           std::strncmp(p, "OPTI",  4) == 0 ||
           std::strncmp(p, "PATC",  4) == 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// extractHTTPHost — pull "Host: <value>" from plaintext HTTP
// ═══════════════════════════════════════════════════════════════════════════

std::optional<std::string> SNIExtractor::extractHTTPHost(
    const uint8_t* payload, size_t len)
{
    // Build a string carefully — payload may contain stray null bytes
    std::string data(reinterpret_cast<const char*>(payload), len);

    // Try canonical "Host: " first, then lowercase "host: "
    std::string::size_type pos = data.find("Host: ");
    if (pos == std::string::npos) {
        pos = data.find("host: ");
    }
    if (pos == std::string::npos) {
        return std::nullopt;
    }

    // Advance past the "Host: " (6 chars)
    pos += 6;

    // Find end-of-line: \r\n or \n
    std::string::size_type end = data.find("\r\n", pos);
    if (end == std::string::npos) {
        end = data.find('\n', pos);
    }
    if (end == std::string::npos) {
        // No newline — take the rest of the payload
        end = data.size();
    }

    return data.substr(pos, end - pos);
}
