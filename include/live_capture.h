#pragma once
#include <string>
#include <pcap.h>
#include "types.h"

class LiveCapture {
public:
    LiveCapture();
    ~LiveCapture();

    bool open(const std::string& interfaceName);
    bool captureOne(RawPacket& outPacket);
    void close();

private:
    pcap_t* pcap_handle;
};
