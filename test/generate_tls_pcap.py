#!/usr/bin/env python3
"""
Generate a synthetic PCAP file containing TLS Client Hello packets with SNI.
This creates a valid pcap that NetPulse can parse to verify SNI extraction.
"""

import struct
import socket

def write_pcap(filename, packets):
    """Write a list of raw ethernet frames to a pcap file."""
    with open(filename, "wb") as f:
        # PCAP Global Header
        f.write(struct.pack("<IHHiIII",
            0xa1b2c3d4,  # magic number
            2, 4,         # version 2.4
            0,            # timezone (UTC)
            0,            # sigfigs
            65535,        # snaplen
            1             # link type: Ethernet
        ))
        
        ts_sec = 1700000000  # arbitrary timestamp
        for i, frame in enumerate(packets):
            # PCAP Packet Header
            f.write(struct.pack("<IIII",
                ts_sec + i,   # ts_sec
                0,             # ts_usec
                len(frame),    # incl_len
                len(frame)     # orig_len
            ))
            f.write(frame)


def build_tls_client_hello(sni_hostname):
    """Build a minimal TLS 1.2 Client Hello with SNI extension."""
    hostname_bytes = sni_hostname.encode("ascii")
    
    # SNI extension data:
    #   2 bytes: SNI list length
    #   1 byte:  SNI type (0x00 = hostname)
    #   2 bytes: hostname length
    #   N bytes: hostname
    sni_entry = struct.pack(">BH", 0x00, len(hostname_bytes)) + hostname_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    
    # Extensions block
    extensions = sni_ext
    extensions_block = struct.pack(">H", len(extensions)) + extensions
    
    # Client Hello body
    client_version = struct.pack(">BB", 0x03, 0x03)  # TLS 1.2
    random_bytes = b'\x00' * 32
    session_id = b'\x00'  # session_id_len = 0
    cipher_suites = struct.pack(">HHH", 4, 0x1301, 0x1302)  # 2 suites
    compression = struct.pack(">BB", 1, 0x00)  # 1 method: null
    
    client_hello_body = (client_version + random_bytes + session_id +
                         cipher_suites + compression + extensions_block)
    
    # Handshake header: type 0x01 (Client Hello) + 3-byte length
    handshake = struct.pack(">B", 0x01) + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body
    
    # TLS Record header: type 0x16 (Handshake), version 0x0301, length
    tls_record = struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake
    
    return tls_record


def build_http_request(host):
    """Build a minimal HTTP GET request with Host header."""
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")


def build_ethernet_ipv4_tcp(src_mac, dst_mac, src_ip, dst_ip,
                              src_port, dst_port, payload):
    """Wrap payload in Ethernet + IPv4 + TCP headers."""
    # TCP header (20 bytes, no options)
    tcp_data_offset = 5 << 4  # 5 x 32-bit words
    tcp_flags = 0x18  # PSH + ACK
    tcp_header = struct.pack(">HHIIBBHHH",
        src_port, dst_port,
        1000, 1,          # seq, ack
        tcp_data_offset, tcp_flags,
        65535,             # window
        0, 0               # checksum (0 = skip), urgent
    )
    
    # IPv4 header (20 bytes)
    total_length = 20 + 20 + len(payload)
    ip_header = struct.pack(">BBHHHBBH4s4s",
        0x45, 0,           # version/IHL, DSCP
        total_length,
        0, 0x4000,         # identification, flags+fragment
        64, 6,             # TTL, protocol=TCP
        0,                 # checksum (0 = skip)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    
    # Ethernet header (14 bytes)
    eth_header = dst_mac + src_mac + struct.pack(">H", 0x0800)
    
    return eth_header + ip_header + tcp_header + payload


def main():
    src_mac = b'\xaa\xbb\xcc\xdd\xee\x01'
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\x02'
    
    domains = [
        "www.youtube.com",
        "api.instagram.com",
        "www.github.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
    ]
    
    http_hosts = [
        "example.com",
        "httpbin.org",
    ]
    
    packets = []
    
    # TLS Client Hello packets → port 443
    for i, domain in enumerate(domains):
        tls_payload = build_tls_client_hello(domain)
        src_ip = f"192.168.1.{10 + i}"
        frame = build_ethernet_ipv4_tcp(
            src_mac, dst_mac,
            src_ip, "93.184.216.34",
            50000 + i, 443,
            tls_payload
        )
        packets.append(frame)
    
    # HTTP GET requests → port 80
    for i, host in enumerate(http_hosts):
        http_payload = build_http_request(host)
        src_ip = f"192.168.1.{100 + i}"
        frame = build_ethernet_ipv4_tcp(
            src_mac, dst_mac,
            src_ip, "93.184.216.34",
            60000 + i, 80,
            http_payload
        )
        packets.append(frame)
    
    # Also add a regular encrypted data packet (Content Type 0x17)
    # to verify it does NOT produce an SNI extraction
    encrypted = struct.pack(">BHH", 0x17, 0x0303, 32) + b'\xff' * 32
    frame = build_ethernet_ipv4_tcp(
        src_mac, dst_mac,
        "192.168.1.50", "93.184.216.34",
        50099, 443,
        encrypted
    )
    packets.append(frame)
    
    outfile = "test/tls_test.pcap"
    write_pcap(outfile, packets)
    print(f"Written {len(packets)} packets to {outfile}")


if __name__ == "__main__":
    main()
