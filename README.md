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

### 4. Application Layer (L7) Deep Packet Inspection
NetPulse natively peers into application payloads to identify the exact services being accessed, completely bypassing the need for DNS logs.
* **TLS SNI Extraction (RFC 6066):** Safely parses the TLS handshake to extract the Server Name Indication (SNI) in plaintext before the connection encrypts. 
* **Variable-Length TLV Navigation:** Mathematically navigates the dynamic, variable-length minefield of the TLS Client Hello (Session IDs, Cipher Suites, Compression) without triggering segmentation faults.
* **Forward-Compatible Parsing:** Utilizes the Type-Length-Value (TLV) design pattern to blindly skip unknown TLS extensions and zero in strictly on Type `0x0000` (SNI).
* **Plaintext HTTP Fallback:** Dynamically detects standard web traffic on Port 80 and extracts the `Host` header via zero-copy string extraction.
* **Safe String Handling:** Extracts network-style length-prefixed strings without relying on C-style null-terminators, guaranteeing memory safety.

### 5. Deterministic Application Classification
Converts raw extracted network domains into semantic application profiles (e.g., "YouTube", "Instagram") using a high-performance classification engine.
* **Deterministic Substring Matching:** Utilizes a strictly ordered `std::vector` of patterns to prevent the "Substring Trap" (ensuring `googlevideo` matches before `google`), prioritizing logical accuracy and CPU cache-locality over hash-map scattering.
* **Data Normalization:** Sanitizes incoming network data to lowercase using safe `unsigned char` casting, preventing undefined behavior and eliminating case-sensitivity misses.
* **Enum State Machine:** Translates heavy string data into an `AppType` enum class immediately upon classification. This guarantees $O(1)$ single-cycle integer comparisons during downstream processing and provides strict compile-time safety.
* **Semantic Grouping:** Groups classified applications into broader analytical categories (Streaming, Social Media, Productivity, etc.) utilizing optimized `switch` jump tables.

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
SNI: www.youtube.com
CLASSIFIED: www.youtube.com → YouTube [Streaming]
SNI: cdninstagram.com
CLASSIFIED: cdninstagram.com → Instagram [Social Media]
HTTP Host: neverssl.com
SNI: api.github.com
CLASSIFIED: api.github.com → GitHub [Development]

──────────── Summary ────────────
Total packets:      1432
Unique flows:       47
TCP flows:          41
UDP flows:          6
Port 443 flows:     23
Port 80 flows:      4
SNI extractions:    4
Classified flows:   3 / 47
Unique domains:     4

Domains found:
  api.github.com
  cdninstagram.com
  neverssl.com
  www.youtube.com
