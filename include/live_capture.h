#pragma once
#include <string>
#include <pcap.h>
#include "types.h"
#include <vector>

struct CaptureStats {
    uint32_t received = 0;
    uint32_t dropped = 0;
    uint32_t if_dropped = 0;
    bool success = false;
};

class LiveCapture {
public:
    LiveCapture();
    ~LiveCapture();

    bool open(const std::string& interfaceName);
    bool enablePcapDump(const std::string& filename);
    bool captureOne(RawPacket& outPacket);
    CaptureStats getStats();
    void close();

    static std::string promptForInterface();
    static std::vector<std::pair<std::string, std::string>> getAvailableInterfaces();

private:
    pcap_t* pcap_handle;
    pcap_dumper_t* pcap_dumper = nullptr;
};
