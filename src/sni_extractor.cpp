#include "sni_extractor.h"

#include <cstring>
#include <algorithm>

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t len)
{
    if (len < 6) return false;
    if (payload[0] != 0x16) return false;
    if (payload[5] != 0x01) return false;
    return true;
}

std::optional<std::string> SNIExtractor::extractTLS(
    const uint8_t* payload, size_t len)
{
    if (len < 10) return std::nullopt;
    if (payload[0] != 0x16) return std::nullopt;
    if (payload[5] != 0x01) return std::nullopt;

    // TLS Record Length
    uint16_t record_len;
    std::memcpy(&record_len, payload + 3, 2);
    record_len = ntohs(record_len);
    
    // Check if TLS record claims length > payload
    if (static_cast<size_t>(record_len) + 5 > len) return std::nullopt;

    size_t offset = 43;
    if (offset >= len) return std::nullopt;

    uint8_t session_id_len = payload[offset++];

    // Prevent offset from exceeding payload bounds due to Session ID
    if (offset + session_id_len > len) return std::nullopt;
    offset += session_id_len;

    if (offset + 2 > len) return std::nullopt;

    uint16_t cipher_len;
    std::memcpy(&cipher_len, payload + offset, 2);
    cipher_len = ntohs(cipher_len);
    offset += 2;
    
    if (offset + cipher_len > len) return std::nullopt;
    offset += cipher_len;

    if (offset + 1 > len) return std::nullopt;

    uint8_t comp_len = payload[offset++];
    if (offset + comp_len > len) return std::nullopt;
    offset += comp_len;

    if (offset + 2 > len) return std::nullopt;

    uint16_t extensions_total;
    std::memcpy(&extensions_total, payload + offset, 2);
    extensions_total = ntohs(extensions_total);
    offset += 2;

    // Extensions total length exceeds payload bounds
    if (offset + extensions_total > len) return std::nullopt;

    size_t ext_end = offset + extensions_total;

    while (offset + 4 <= ext_end)
    {
        uint16_t ext_type;
        std::memcpy(&ext_type, payload + offset, 2);
        ext_type = ntohs(ext_type);
        offset += 2;

        uint16_t ext_len;
        std::memcpy(&ext_len, payload + offset, 2);
        ext_len = ntohs(ext_len);
        offset += 2;

        if (offset + ext_len > ext_end) return std::nullopt;

        if (ext_type == 0x0000)
        {
            if (ext_len < 5) return std::nullopt;
            
            size_t sni_offset = offset;
            sni_offset += 3; // SNI List length + SNI type

            uint16_t name_len;
            std::memcpy(&name_len, payload + sni_offset, 2);
            name_len = ntohs(name_len);
            sni_offset += 2;

            if (sni_offset + name_len > offset + ext_len) return std::nullopt;

            return std::string(reinterpret_cast<const char*>(payload + sni_offset), name_len);
        }

        offset += ext_len;
    }

    return std::nullopt;
}

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

std::optional<std::string> SNIExtractor::extractHTTPHost(
    const uint8_t* payload, size_t len)
{
    std::string data(reinterpret_cast<const char*>(payload), len);
    std::string::size_type pos = data.find("Host: ");
    if (pos == std::string::npos) {
        pos = data.find("host: ");
    }
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    pos += 6;
    std::string::size_type end = data.find("\r\n", pos);
    if (end == std::string::npos) {
        end = data.find('\n', pos);
    }
    if (end == std::string::npos) {
        end = data.size();
    }
    return data.substr(pos, end - pos);
}
