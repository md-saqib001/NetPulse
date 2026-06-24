#include "live_capture.h"
#include <iostream>
#include <chrono>
#include <csignal>

bool running = true;

void signalHandler(int signum) {
    std::cout << "\nInterrupt signal (" << signum << ") received. Stopping..." << std::endl;
    running = false;
}

int main() {
    signal(SIGINT, signalHandler);

    LiveCapture capture;
    
    // Replace this string with your actual interface name found on Day 1
    // Examples: "\\Device\\NPF_{...}" (Windows), "eth0" (Linux), "en0" (Mac)
    std::string interfaceName = "\\Device\\NPF_{E46C58A1-0216-44D4-8280-33F748407337}"; 

    std::cout << "Starting live capture on: " << interfaceName << std::endl;
    if (!capture.open(interfaceName)) {
        return 1;
    }

    RawPacket packet;
    uint32_t packetCount = 0;
    auto startTime = std::chrono::steady_clock::now();

    while (running) {
        if (capture.captureOne(packet)) {
            packetCount++;
            std::cout << "Packet captured: " << packet.header.incl_len << " bytes" << std::endl;
        }

        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

        if (elapsed >= 30) {
            std::cout << "30 seconds elapsed. Stopping..." << std::endl;
            break;
        }
    }

    capture.close();
    std::cout << "Total packets captured: " << packetCount << std::endl;

    return 0;
}
