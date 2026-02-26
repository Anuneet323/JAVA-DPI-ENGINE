import struct

PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHIIII',
    0xa1b2c3d4,  # magic
    2, 4,        # version
    0, 0,        # timezone, accuracy
    65535,       # snaplen
    1            # Ethernet
)

def write_packet(f, payload):
    pkt_header = struct.pack('<IIII',
                             0, 0,
                             len(payload),
                             len(payload))
    f.write(pkt_header)
    f.write(payload)

def fake_eth_ip_tcp(payload_data, dst_port):
    eth = b'\x00'*14

    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6  # TCP

    tcp = bytearray(20)
    tcp[2] = (dst_port >> 8) & 0xFF
    tcp[3] = dst_port & 0xFF
    tcp[12] = 0x50  # header len 20

    return eth + ip + tcp + payload_data

with open("test_dpi.pcap", "wb") as f:
    f.write(PCAP_GLOBAL_HEADER)

    # HTTPS YouTube
    https_payload = b"\x16\x03\x01youtube.com"
    pkt = fake_eth_ip_tcp(https_payload, 443)
    write_packet(f, pkt)

    # HTTP
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = fake_eth_ip_tcp(http_payload, 80)
    write_packet(f, pkt)

    # DNS (just marked by port)
    dns_payload = b"\x00\x01"
    pkt = fake_eth_ip_tcp(dns_payload, 53)
    write_packet(f, pkt)

print("Generated test_dpi.pcap")