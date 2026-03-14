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
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'
    ether_type_ipv4 = b'\x08\x00'
    eth = dst_mac + src_mac + ether_type_ipv4

    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6  # TCP
    total_len = 20 + 20 + len(payload_data)
    ip[2] = (total_len >> 8) & 0xFF
    ip[3] = total_len & 0xFF

    tcp = bytearray(20)
    tcp[2] = (dst_port >> 8) & 0xFF
    tcp[3] = dst_port & 0xFF
    tcp[12] = 0x50  # header len 20

    return eth + ip + tcp + payload_data


def fake_eth_ip_udp(payload_data, dst_port):
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'
    ether_type_ipv4 = b'\x08\x00'
    eth = dst_mac + src_mac + ether_type_ipv4

    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 17  # UDP
    total_len = 20 + 8 + len(payload_data)
    ip[2] = (total_len >> 8) & 0xFF
    ip[3] = total_len & 0xFF

    udp = bytearray(8)
    udp[2] = (dst_port >> 8) & 0xFF
    udp[3] = dst_port & 0xFF
    udp_len = 8 + len(payload_data)
    udp[4] = (udp_len >> 8) & 0xFF
    udp[5] = udp_len & 0xFF

    return eth + ip + udp + payload_data


def tls_client_hello_with_sni(domain):
    host = domain.encode('ascii')

    # SNI extension payload: server_name_list_len + name_type + name_len + name
    server_name = b'\x00' + len(host).to_bytes(2, 'big') + host
    server_name_list = len(server_name).to_bytes(2, 'big') + server_name
    sni_extension = (
        b'\x00\x00' +
        len(server_name_list).to_bytes(2, 'big') +
        server_name_list
    )

    body = bytearray()
    body += b'\x03\x03'          # ClientHello version
    body += b'\x00' * 32          # Random
    body += b'\x00'               # Session ID length
    body += b'\x00\x02\x00\x2f'  # Cipher suites length + one suite
    body += b'\x01\x00'          # Compression methods length + null compression
    body += len(sni_extension).to_bytes(2, 'big') + sni_extension

    handshake = b'\x01' + len(body).to_bytes(3, 'big') + bytes(body)
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    return record

with open("test_dpi.pcap", "wb") as f:
    f.write(PCAP_GLOBAL_HEADER)

    # HTTPS YouTube
    https_payload = tls_client_hello_with_sni("youtube.com")
    pkt = fake_eth_ip_tcp(https_payload, 443)
    write_packet(f, pkt)

    # HTTP
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = fake_eth_ip_tcp(http_payload, 80)
    write_packet(f, pkt)

    # DNS (just marked by port)
    dns_payload = b"\x00\x01"
    pkt = fake_eth_ip_udp(dns_payload, 53)
    write_packet(f, pkt)

print("Generated test_dpi.pcap")