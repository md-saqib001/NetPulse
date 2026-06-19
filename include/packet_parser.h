#pragma once

#include "types.h"

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& out);

private:
    static bool parseEthernet(const RawPacket& raw, ParsedPacket& out);
    static bool parseIPv4(const RawPacket& raw, ParsedPacket& out);
    static bool parseTCP(const RawPacket& raw, ParsedPacket& out);
    static bool parseUDP(const RawPacket& raw, ParsedPacket& out);
};
