# NetPulse
## Deep Packet Inspection Engine (C++17)

A CLI tool that reads PCAP network captures, parses the 
complete network stack (Ethernet → IP → TCP/TLS), extracts 
Server Name Indication (SNI) from TLS Client Hello packets, 
classifies applications, and generates a traffic report.

**Key insight:** Even though HTTPS is encrypted, the 
destination domain name is transmitted in plaintext in the 
TLS Client Hello handshake (RFC 6066). NetPulse verifies 
this on real traffic.

## Build
```bash
mkdir build
cd build
cmake ..
make
```

## Usage
Basic usage, analyzing a PCAP file:
```bash
./netpulse capture.pcap
```

Show top 5 connections (default is 10):
```bash
./netpulse capture.pcap --top 5
```

Filter for a specific app (e.g. youtube):
```bash
./netpulse capture.pcap --filter youtube
```

Print classified packets in real-time:
```bash
./netpulse capture.pcap --verbose
```

Output as CSV instead of formatted terminal table:
```bash
./netpulse capture.pcap --csv > results.csv
```

Disable ANSI colors (useful for logging):
```bash
./netpulse capture.pcap --no-color
```

Show capture instructions for your own traffic:
```bash
./netpulse --demo
```

Show all commands:
```bash
./netpulse --help
```

## Live Capture
NetPulse can capture and parse packets directly from your network interface in real time, sharing the exact same inspection and reporting pipeline as the file-based mode.

Start live capture (it will prompt you to select an interface):
```bash
./netpulse --live
```

Specify interface directly:
```bash
./netpulse --live eth0
```

Print a real-time stream of newly discovered domains as they happen:
```bash
./netpulse --live eth0 --verbose-live
```

Output a machine-readable JSON-lines stream of new domains (great for piping to dashboards):
```bash
./netpulse --live eth0 --json-stream
```

Capture for exactly 60 seconds and auto-exit:
```bash
./netpulse --live eth0 --duration 60
```

Filter real-time stream to only show a specific app (e.g. youtube):
```bash
./netpulse --live eth0 --filter youtube --verbose-live
```

Quiet mode: suppress real-time announcements and status updates, just silently capture and print the final report:
```bash
./netpulse --live eth0 --duration 30 --quiet
```

Save the live captured packets to a PCAP file simultaneously while analyzing:
```bash
./netpulse --live eth0 --output-pcap saved.pcap
```

## Capturing Your Own Traffic
To capture your own traffic to test with NetPulse:

**Linux/Mac:**
```bash
sudo tcpdump -i eth0 -w my_traffic.pcap &
# Browse YouTube, Instagram, GitHub for 60 seconds
sudo pkill tcpdump
./netpulse my_traffic.pcap
```

**Mac (find your interface first):**
```bash
networksetup -listallhardwareports
sudo tcpdump -i en0 -w my_traffic.pcap &
```

**Windows:**
1. Open Wireshark → select your network interface
2. Start capture → browse → stop
3. File → Export as pcap → run `./netpulse` on it

## Architecture
```text
┌───────────────────────────────────────────────────────────────┐
│                       NetPulse Pipeline                       │
├───────────────┬──────────────┬──────────────┬─────────────────┤
│ Packet Source │PacketParser  │SNIExtractor  │Classifier       │
│               │              │              │                 │
│ ┌───────────┐ │ Ethernet hdr │ TLS record   │ Domain →        │
│ │PcapReader │ │ (14 bytes)   │ header check │ AppType         │
│ │(Offline)  │ │              │              │                 │
│ └─────┬─────┘ │ IPv4 header  │ Client Hello │ Pattern         │
│       │       │ (IHL*4 bytes)│ verification │ matching        │
│      OR       │              │              │                 │
│       │       │ TCP header   │ Walk 5 var-  │ 30+ app         │
│ ┌─────▼─────┐ │ (DO*4 bytes) │ length fields│ patterns        │
│ │LiveCapture│ │              │              │                 │
│ │(Real-time)│ │ Set payload  │ Find SNI ext │ Return          │
│ └─────┬─────┘ │ pointer      │ type 0x0000  │ AppType         │
└───────┴───────┴──────┬───────┴──────┬───────┴──────┬──────────┘
                       │              │              │
                       └──────────────┴──────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   FlowTable        │
                    │ FiveTuple → Flow   │
                    │ (unordered_map     │
                    │  custom hash)      │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │    Reporter        │
                    │ App breakdown      │
                    │ Category groups    │
                    │ Top connections    │
                    │ Domain list        │
                    │ RFC 6066 footer    │
                    └────────────────────┘
```

## How SNI Extraction Works
The TLS Client Hello message structure contains 5 variable-length fields before reaching the extensions block:
1. Session ID (1+N bytes)
2. Cipher Suites (2+M bytes)
3. Compression Methods (1+K bytes)
4. Extensions Total Length (2 bytes)
5. Extensions

NetPulse carefully computes length bounds and walks each of these fields manually byte-by-byte in big-endian. By safely calculating offsets to reach the extensions, it loops through each until finding extension type `0x0000` (SNI). Once identified, the trailing byte values correspond directly to the unencrypted plaintext domain string that the client is requesting to connect to.

## Sample Output
```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NetPulse v1.0 — Deep Packet Inspection Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  FILE SUMMARY
  ─────────────────────────────────────────────────
  File:              capture.pcap
  Total packets:     28,451
  Total flows:       412
  Classified flows:  285  (69.1%)
  Unclassified:      127  (30.9%)
  Total data:        3.2 MB

  APPLICATION BREAKDOWN
  ─────────────────────────────────────────────────
  App              Packets     %      Category
  YouTube            8,452   29.7%   Streaming
  Instagram          4,213   14.8%   Social Media
  GitHub             2,104    7.3%   Development
  Unknown           13,682   48.1%   —

  CATEGORY BREAKDOWN
  ─────────────────────────────────────────────────
  Unknown           13,682   48.1%
  Streaming          8,452   29.7%
  Social Media       4,213   14.8%
  Development        2,104    7.3%

  TOP HTTPS CONNECTIONS  (port 443)
  ─────────────────────────────────────────────────
  Source IP           Destination       App         Pkts
  192.168.1.10   →  142.250.x.x:443  YouTube     4,521
  192.168.1.10   →  157.240.x.x:443  Instagram   2,100
  192.168.1.10   →  140.82.x.x:443   GitHub      1,850

  UNIQUE DOMAINS SEEN
  ─────────────────────────────────────────────────
  googlevideo.com              [YouTube]
  cdninstagram.com             [Instagram]
  api.github.com               [GitHub]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  VERIFIED: TLS SNI reveals destination domain
  even on encrypted HTTPS connections (RFC 6066)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Technical Implementation

### Q: "Why did I build this?"
A: While studying Computer Networks, I wanted to move beyond the theory and build something that interacts with real, messy internet traffic. I knew HTTPS encrypted payloads, but I learned that the initial TLS handshake (SNI) leaves the destination domain in plaintext. I wanted to see if I could write a C++ engine from scratch to actually catch that in the wild. Capturing my own traffic and watching the engine extract "youtube.com" from raw, encrypted bytes was the moment the OSI model truly clicked for me.

### Q: "How does flow tracking work?"
A: A flow is uniquely identified by a FiveTuple: src_ip, dst_ip, src_port, dst_port, protocol. This is stored in a `std::unordered_map` with a custom hash that XOR-combines all 5 fields using the boost `hash_combine` technique (0x9e3779b9 constant). Because of this O(1) tracking, all packets from the same TCP connection map to the same Flow entry. When we find the SNI in packet 1, it's stored in the flow state and automatically applies to all subsequent packets in that connection.

### Q: "What is network byte order and why does it matter?"
A: TCP/IP uses big-endian (most significant byte first) format. However, x86/ARM CPUs use little-endian. This means every 16-bit port and 32-bit IP address read from the raw packet must be explicitly converted using `ntohs()` / `ntohl()`. If you miss even one call, you get a completely garbage port number or IP address. This project carefully implements these conversions at exactly the 8 places where they are required in the network stack.

### Q: "What does #pragma pack(1) do?"
A: It tells the compiler not to add padding between struct fields. Without it, `sizeof(EthernetHeader)` might be padded to 16 bytes by the C++ compiler to optimize CPU alignment, but we need it to be exactly 14 bytes to correctly match the raw wire format. Using `#pragma pack(1)` guarantees that our C++ struct layout perfectly matches the byte sequence in the PCAP file, allowing zero-copy memory mapping.


## What I Learned
While taking my Computer Networks course, I wanted to bridge the gap between academic theory and practical systems engineering. Rather than just learning about the OSI model abstractly, I built NetPulse to parse it directly off the wire. By navigating raw memory, handling big-endian network byte order, and manually traversing packet payloads, I successfully verified that any passive observer can extract destination domains from completely encrypted HTTPS connections via the plaintext TLS Client Hello (SNI). Building this engine proved to me that textbook network theory perfectly translates into raw traffic reality.

## Verified on real traffic
- [ ] Ran on own HTTPS capture
- [ ] YouTube SNI extracted: googlevideo.com / youtube.com
- [ ] Instagram SNI extracted: cdninstagram.com
- [ ] GitHub SNI extracted: api.github.com
- [ ] Report generated with correct percentages
- [ ] --filter youtube shows only YouTube flows
- [ ] --csv produces valid CSV importable to spreadsheet
- [ ] Handles empty PCAP gracefully
- [ ] Handles non-PCAP file gracefully

## Interview Demo Script
1. Open terminal and start the tool:
   `./netpulse --live <interface> --verbose-live --output-pcap demo.pcap`
2. Open a browser and visit `youtube.com`, `instagram.com`, `github.com` one at a time.
3. Point out each real-time classification appearing within 1-2 seconds of the page load.
4. Press `Ctrl+C` and show the final summary report generated immediately on exit.
5. Emphasize the `--output-pcap` flag: "I can simultaneously record to disk. Because my pipeline treats live sockets and PCAP files identically, I can instantly replay this exact capture offline using `./netpulse demo.pcap`."



## Installation

NetPulse is distributed as a standalone, pre-compiled binary for macOS, Linux, and Windows. 

### 🍎 macOS & 🐧 Linux (Recommended)
The easiest way to install the latest version of NetPulse is by using our automated installation script. Open your terminal and run:

```bash
curl -sSL https://raw.githubusercontent.com/md-saqib001/NetPulse/main/install.sh | bash
```

*(This script detects your OS, downloads the correct binary, and moves it to your system PATH so you can run `netpulse` from anywhere).*

### 🪟 Windows (Recommended)
Windows users can easily install NetPulse using the Scoop package manager.

**Prerequisite:** You must have the [Npcap SDK](https://npcap.com/) installed on your system to capture live network packets.

Open PowerShell and run:

```powershell
scoop bucket add netpulse https://github.com/md-saqib001/scoop-netpulse
scoop install netpulse
```

### 🛠️ Manual Installation (Advanced)
If you prefer not to use package managers or install scripts, you can download the binaries directly from the [GitHub Releases](https://github.com/md-saqib001/NetPulse/releases) page, or fetch them manually via your terminal.

#### macOS:
```bash
curl -L -o netpulse https://github.com/md-saqib001/NetPulse/releases/latest/download/netpulse-macOS
chmod +x netpulse
sudo mv netpulse /usr/local/bin/
```

#### Linux:
```bash
curl -L -o netpulse https://github.com/md-saqib001/NetPulse/releases/latest/download/netpulse-Linux
chmod +x netpulse
sudo mv netpulse /usr/local/bin/
```

#### Windows:
1. Download `netpulse-Windows.exe` from the latest release.
2. Rename it to `netpulse.exe`.
3. Move it to a permanent folder and add that folder to your Windows System `PATH` environment variable.