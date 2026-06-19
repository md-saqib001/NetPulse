# NetPulse

NetPulse is a high-performance, command-line Deep Packet Inspection (DPI) engine written from scratch in C++17. Designed to analyze raw network traffic from `.pcap` files, it performs zero-copy payload extraction and stateful flow tracking by natively parsing the TCP/IP stack.

## Core Capabilities

### 1. PCAP Ingestion & Binary Parsing
* **Direct I/O:** Reads raw `.pcap` capture files directly into memory buffers.
* **Architecture Agnostic:** Automatically detects capture Endianness via PCAP magic numbers and normalizes timestamps and packet lengths into Host Byte Order.

### 2. Zero-Copy Protocol Parsing (L2 - L4)
The parsing engine uses strict pointer arithmetic to slide a cursor through the network envelope, entirely avoiding the memory overhead of copying nested array data.
* **Data Link Layer (L2):** Extracts MAC addresses and isolates 14-byte IEEE 802.3 Ethernet frames.
* **Network Layer (L3 - IPv4):** Validates IPv4 headers, applies bitwise masking to dynamically calculate Internet Header Length (IHL), and converts Network Byte Order to Host Byte Order for IP addresses.
* **Transport Layer (L4 - TCP/UDP):** * Parses static 8-byte UDP headers.
  * Dynamically calculates variable-length TCP headers using the data offset nibble.
  * Successfully isolates the final Application Layer (L7) payload for downstream analysis.

### 3. Stateful Flow Tracking
NetPulse upgrades from stateless packet counting to true state-tracking (similar to enterprise firewalls) by managing unidirectional connections.
* **The 5-Tuple:** Uniquely maps connections using `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, and `Protocol`.
* **High-Efficiency Hashing:** Implements a custom, Boost-inspired mathematical hash combiner utilizing the golden ratio (`0x9e3779b9`) and bit-shifting. This destroys tuple symmetry, preventing hash collisions and ensuring pure $O(1)$ lookup times in the internal C++ `std::unordered_map`.
* **Traffic Analytics:** Accumulates real-time packet counts and payload byte sizes for every unique flow across the network.

## Technical Architecture
* **Language:** C++17
* **Memory Management:** Zero-copy application payload referencing via `const uint8_t*`.
* **Standard Libraries:** `#pragma pack` for hardware-accurate structs, bitwise operators for protocol flags, and standard library algorithms for fast execution.

## Build Instructions

NetPulse uses CMake for its build system.

```bash
# Clone the repository
git clone [https://github.com/yourusername/netpulse.git](https://github.com/yourusername/netpulse.git)
cd netpulse

# Create build directory
mkdir build && cd build

# Compile the engine
cmake ..
make

## Usage

Provide a `.pcap` file as the single argument to run the analysis engine.

```bash
$ ./netpulse test/sample.pcap
Reading: test/sample.pcap
Total packets:    1432
Unique flows:     47
TCP flows:        41
UDP flows:        6
Port 443 flows:   23
Port 80 flows:    4
