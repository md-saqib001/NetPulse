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