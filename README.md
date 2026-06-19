# NetPulse

NetPulse is a custom, high-performance Deep Packet Inspection (DPI) engine written in C++17. It reads binary PCAP files, parses network packets across the OSI layers, extracts TLS Server Name Indication (SNI) data, classifies applications, and generates traffic analysis reports.

## Architecture

The project is structured into distinct modules:
* **PCAP Reader:** Handles binary file I/O and byte-order conversions.
* **Packet Parser:** Peels back Ethernet, IPv4, TCP, and UDP layers.
* **SNI Extractor:** Parses TLS Client Hello records to extract domain names.
* **Classifier:** Maps domains to known applications (e.g., YouTube, Instagram).

## Build Instructions

NetPulse uses CMake as its build system. To compile from source:

```bash
mkdir build
cd build
cmake ..
make


## Core Capabilities

**1. PCAP Binary Parsing**
* Reads raw `.pcap` files in strict binary mode.
* Auto-detects and corrects cross-platform Endianness mismatches (Host vs Network byte order) using magic number validation (`0xa1b2c3d4` vs `0xd4c3b2a1`).
* Extracts variable-length packet payloads accurately using the `incl_len` header field.


**2. Network Layer Parsing (IPv4)**
* Slices standard 14-byte Ethernet frames (IEEE 802.3).
* Extracts and validates IPv4 headers, dynamically calculating the Internet Header Length (IHL) via bitwise masking.
* Normalizes Big-Endian Network Byte Order for accurate IP address logging.
* Performs zero-copy pointer arithmetic to locate inner protocol payloads.