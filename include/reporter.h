#pragma once

#include <string>
#include "types.h"
#include "config.h"

class Reporter {
public:
    void generate(const Config& config,
                  const FlowTable& flows,
                  uint32_t total_packets,
                  uint64_t total_bytes);

    void generateCSV(const Config& config,
                     const FlowTable& flows,
                     uint32_t total_packets,
                     uint64_t total_bytes);

private:
    std::string formatBytes(uint64_t bytes) const;
    std::string formatCount(uint64_t n) const;
    double pct(uint64_t part, uint64_t total) const;
    std::string bar(double percent, int width = 20) const;
};
