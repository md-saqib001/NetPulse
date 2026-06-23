#include <iostream>
#include <algorithm>
#include <set>
#include <fstream>
#include <sstream>
#include <cmath>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "classifier.h"
#include "types.h"
#include "reporter.h"
#include "cli_parser.h"
#include "colors.h"

/*
 * NETPULSE — Interview Talking Points
 * ════════════════════════════════════
 *
 * Q: "What was the hardest part to implement?"
 * A: The TLS SNI extractor. The Client Hello has 5 
 *    variable-length fields before reaching extensions.
 *    Session ID (1+N bytes), Cipher Suites (2+M bytes),
 *    Compression (1+K bytes), then extensions. One 
 *    off-by-one anywhere corrupts every subsequent read.
 *    I added a --debug-tls flag to print every offset
 *    value which made bugs immediately visible.
 *
 * Q: "Why did you build this?"
 * A: My CN textbook said HTTPS leaks domain names in the
 *    TLS Client Hello because SNI is plaintext (RFC 6066).
 *    I didn't want to accept that as a fact — I wanted to
 *    verify it on real traffic. After building this, I 
 *    captured my own HTTPS traffic and confirmed: every
 *    connection to youtube.com, instagram.com, github.com
 *    reveals the domain name before a single encrypted
 *    byte is sent. The textbook was right.
 *
 * Q: "What is network byte order and why does it matter?"
 * A: TCP/IP uses big-endian (most significant byte first).
 *    x86/ARM CPUs use little-endian. Every 16-bit port and
 *    32-bit IP address read from the packet must be 
 *    converted with ntohs() / ntohl(). Miss one call and
 *    you get a garbage port number. This project has 
 *    exactly 8 places where this conversion is required.
 *
 * Q: "How does flow tracking work?"
 * A: A flow is uniquely identified by a FiveTuple: 
 *    src_ip, dst_ip, src_port, dst_port, protocol.
 *    Stored in std::unordered_map with a custom hash that
 *    XOR-combines all 5 fields using the boost hash_combine
 *    technique (0x9e3779b9 constant). All packets from the
 *    same TCP connection map to the same Flow entry, so 
 *    when we find the SNI in packet 1, it's stored in the
 *    flow and applies to all subsequent packets.
 *
 * Q: "What does #pragma pack do?"
 * A: Tells the compiler not to add padding between struct
 *    fields. Without it, sizeof(EthernetHeader) might be
 *    16 bytes due to alignment, but we need exactly 14 to
 *    match the wire format. With #pragma pack(1), the 
 *    struct layout matches the byte sequence in the file.
 *
 * CN Theory verified by this project:
 * - OSI Layer 2 (Ethernet): MAC addresses, EtherType
 * - OSI Layer 3 (IP): addressing, IHL, protocol field
 * - OSI Layer 4 (TCP): ports, data offset, flags
 * - OSI Layer 7 (TLS): Client Hello, SNI extension
 * - Big-endian network byte order throughout
 * - 5-tuple flow identification
 * - RFC 6066: Server Name Indication
 */

// Helper to format IP for the report/verbose
static std::string maskIP(uint32_t ip) {
    uint8_t bytes[4];
    bytes[0] = (ip >> 24) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[3] = ip & 0xFF;
    
    std::ostringstream oss;
    oss << (int)bytes[0] << "." << (int)bytes[1] << ".x.x";
    return oss.str();
}

void printProgress(uint32_t packets, size_t current_bytes, size_t total_bytes) {
    if (total_bytes == 0) return;
    double percent = (double)current_bytes / total_bytes * 100.0;
    int width = 20;
    int filled = std::round((percent / 100.0) * width);
    std::string b;
    for (int i = 0; i < width; ++i) {
        if (i < filled) b += "█";
        else b += "░";
    }
    
    // Split the bar into filled and empty to colorize the filled part
    std::string bar_str;
    if (useColors && filled > 0) {
        bar_str += Colors::GREEN;
        for (int i = 0; i < filled; ++i) bar_str += "█";
        bar_str += Colors::RESET;
        for (int i = filled; i < width; ++i) bar_str += "░";
    } else {
        bar_str = b;
    }
    
    std::string s_packets = std::to_string(packets);
    int insertPosition = s_packets.length() - 3;
    while (insertPosition > 0) {
        s_packets.insert(insertPosition, ",");
        insertPosition -= 3;
    }

    std::cout << "\rProcessing: " << s_packets << " packets... [" << bar_str << "] " 
              << (int)percent << "%" << std::flush;
}

int main(int argc, char* argv[]) {
    Config config = CLIParser::parse(argc, argv);
    
    if (config.demo) {
        std::cout << "To capture your own traffic:\n\n"
                  << "Linux/Mac:\n"
                  << "  sudo tcpdump -i eth0 -w my_traffic.pcap &\n"
                  << "  # Browse YouTube, Instagram, GitHub for 60 seconds\n"
                  << "  sudo pkill tcpdump\n"
                  << "  ./netpulse my_traffic.pcap\n\n"
                  << "Mac (find your interface first):\n"
                  << "  networksetup -listallhardwareports\n"
                  << "  sudo tcpdump -i en0 -w my_traffic.pcap &\n\n"
                  << "Windows:\n"
                  << "  Open Wireshark → select your network interface\n"
                  << "  → start capture → browse → stop → \n"
                  << "  File → Export as pcap → run ./netpulse on it\n";
        return 0;
    }

    if (config.help) {
        CLIParser::printHelp(argv[0]);
        return 0;
    }
    
    if (config.no_color) {
        useColors = false;
    }

    // Check file size for progress bar and empty check
    std::ifstream file(config.filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << c(Colors::RED, "Error: cannot open file: " + config.filename) << "\n";
        return 1;
    }
    size_t file_size = file.tellg();
    file.close();

    PcapReader reader;
    if (!reader.open(config.filename)) {
        return 1;
    }

    Classifier classifier;
    FlowTable flows;
    RawPacket packet;
    uint32_t total_count = 0;
    uint64_t total_bytes = 0;
    size_t current_file_pos = 24; // PCAP global header is 24 bytes
    ParseStats stats;

    while (reader.readNextPacket(packet)) {
        total_count++;
        current_file_pos += 16 + packet.data.size();

        if (total_count % 5000 == 0) {
            printProgress(total_count, current_file_pos, file_size);
        }

        ParsedPacket parsed;
        if (!PacketParser::parse(packet, parsed, stats)) {
            if (parsed.parse_error) {
                // We increment parse_errors or short_packets inside parse()
            }
            continue;
        }

        FiveTuple tuple;
        tuple.src_ip   = parsed.src_ip;
        tuple.dst_ip   = parsed.dst_ip;
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dst_port;
        tuple.protocol = parsed.protocol;

        Flow& flow = flows[tuple];
        flow.packet_count++;
        flow.byte_count += parsed.payload_len;
        total_bytes += parsed.payload_len;

        if (parsed.payload_len > 5 && flow.sni.empty())
        {
            bool extracted = false;
            if (parsed.dst_port == 443 || parsed.src_port == 443)
            {
                auto sni = SNIExtractor::extractTLS(
                    parsed.payload, parsed.payload_len);
                if (sni.has_value()) {
                    flow.sni        = sni.value();
                    extracted       = true;
                }
            }
            else if (parsed.dst_port == 80 || parsed.src_port == 80)
            {
                if (SNIExtractor::isHTTPRequest(
                        parsed.payload, parsed.payload_len))
                {
                    auto host = SNIExtractor::extractHTTPHost(
                        parsed.payload, parsed.payload_len);
                    if (host.has_value()) {
                        flow.sni        = host.value();
                        extracted       = true;
                    }
                }
            }

            if (extracted) {
                flow.app_type   = classifier.classify(flow.sni);
                flow.app_name   = classifier.appName(flow.app_type);
                flow.classified = (flow.app_type != AppType::UNKNOWN);

                if (config.verbose) {
                    std::string proto = tuple.protocol == 6 ? "TCP" : (tuple.protocol == 17 ? "UDP" : std::to_string(tuple.protocol));
                    std::string app_c = flow.app_type == AppType::UNKNOWN ? c(Colors::GRAY, flow.app_name) : c(Colors::GREEN, flow.app_name);
                    std::string dom_c = c(Colors::CYAN, flow.sni);
                    std::cout << "\n→ [" << proto << "  " << ipToString(tuple.src_ip) << ":" << tuple.src_port 
                              << " → " << maskIP(tuple.dst_ip) << ":" << tuple.dst_port << "]\n";
                    std::cout << "  SNI: " << dom_c << " → " << app_c << " [" << classifier.category(flow.app_type) << "]\n";
                }
            }
        }
    }

    if (total_count > 0) {
        printProgress(total_count, file_size, file_size);
        std::cout << "\n";
    } else {
        // Empty pcap case
        std::cout << "\n";
    }

    reader.close();

    Reporter reporter;
    if (config.csv_output) {
        reporter.generateCSV(config, flows, total_count, total_bytes);
    } else {
        reporter.generate(config, flows, total_count, total_bytes);
    }

    // Print parse warnings at the end
    if (stats.short_packets > 0 || stats.parse_errors > 0 || stats.non_ipv4_skipped > 0) {
        std::cout << "\n  " << c(Colors::CYAN + Colors::BOLD, "PARSE WARNINGS") << "\n";
        std::cout << "  ─────────────────────────────────────────────────\n";
        if (stats.short_packets > 0) {
            std::cout << c(Colors::RED, "  Short packets skipped:  " + std::to_string(stats.short_packets)) << "\n";
        }
        if (stats.parse_errors > 0) {
            std::cout << c(Colors::RED, "  Invalid headers:        " + std::to_string(stats.parse_errors)) << "\n";
        }
        if (stats.non_ipv4_skipped > 0) {
            std::cout << c(Colors::GRAY, "  Non-IPv4 packets:       " + std::to_string(stats.non_ipv4_skipped)) << "\n";
        }
        std::cout << "\n";
    }

    return 0;
}
