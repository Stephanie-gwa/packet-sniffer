import struct

from packetanalyzer.parser import parse_ethernet_frame
from packetanalyzer.builders import (
    build_tcp_packet, build_udp_packet, build_icmp_echo_packet, build_arp_packet,
    TCP_SYN, TCP_ACK, TCP_FIN,
)


# ---------------------------------------------------------------- hand-crafted bytes
# These do not use the builders module at all, so they independently verify the
# parser reads the wire format correctly rather than just round-tripping our own encoder.

def test_parse_hand_crafted_tcp_syn():
    eth = struct.pack("!6s6sH",
                       bytes.fromhex("020000000001"), bytes.fromhex("020000000002"), 0x0800)
    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
        bytes([192, 168, 1, 10]), bytes([192, 168, 1, 20]),
    )
    tcp = struct.pack("!HHIIBBHHH", 5000, 80, 111, 0, 5 << 4, 0x02, 8192, 0, 0)  # SYN only
    frame = eth + ip_no_csum + tcp

    pkt = parse_ethernet_frame(frame, timestamp=123.0)

    assert pkt.eth_src == "02:00:00:00:00:02"
    assert pkt.eth_dst == "02:00:00:00:00:01"
    assert pkt.ethertype == 0x0800
    assert pkt.protocol == "TCP"
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "192.168.1.20"
    assert pkt.src_port == 5000
    assert pkt.dst_port == 80
    assert pkt.tcp_flags == ["SYN"]
    assert pkt.length == len(frame)


def test_parse_hand_crafted_udp():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x0800)
    payload = b"hello-udp"
    udp = struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    frame = eth + ip + udp

    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.protocol == "UDP"
    assert pkt.src_port == 12345
    assert pkt.dst_port == 53
    assert pkt.payload == payload


def test_parse_hand_crafted_icmp_echo_request():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x0800)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"pingdata"
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    frame = eth + ip + icmp

    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.protocol == "ICMP"
    assert pkt.icmp_type == 8
    assert pkt.icmp_type_name == "echo-request"
    assert pkt.payload == b"pingdata"


def test_parse_arp_request():
    frame = build_arp_packet("02:00:00:00:00:01", "192.168.1.10",
                              "00:00:00:00:00:00", "192.168.1.1")
    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.protocol == "ARP"
    assert pkt.arp_op == "request"
    assert pkt.arp_sender_ip == "192.168.1.10"
    assert pkt.arp_sender_mac == "02:00:00:00:00:01"
    assert pkt.arp_target_ip == "192.168.1.1"
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "192.168.1.1"


def test_parse_arp_reply():
    frame = build_arp_packet("02:00:00:00:00:02", "192.168.1.1",
                              "02:00:00:00:00:01", "192.168.1.10", is_reply=True)
    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.arp_op == "reply"


# ---------------------------------------------------------------- via builders (broader coverage)

def test_tcp_flags_multiple_bits():
    frame = build_tcp_packet(
        src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
        src_ip="192.168.1.10", dst_ip="192.168.1.20",
        src_port=1000, dst_port=2000, flags=TCP_SYN | TCP_ACK,
    )
    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert set(pkt.tcp_flags) == {"SYN", "ACK"}


def test_tcp_payload_extracted():
    frame = build_tcp_packet(
        src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
        src_ip="192.168.1.10", dst_ip="203.0.113.20",
        src_port=52050, dst_port=21, flags=TCP_ACK, payload=b"USER alice\r\n",
    )
    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.payload == b"USER alice\r\n"
    assert pkt.dst_port == 21


def test_icmp_echo_reply_type_name():
    frame = build_icmp_echo_packet(
        src_mac="02:00:00:00:00:02", dst_mac="02:00:00:00:00:01",
        src_ip="192.168.1.1", dst_ip="192.168.1.10", is_reply=True,
    )
    pkt = parse_ethernet_frame(frame, timestamp=1.0)
    assert pkt.icmp_type == 0
    assert pkt.icmp_type_name == "echo-reply"


def test_ipv6_reports_protocol_but_not_deeply_parsed():
    # Minimal IPv6 header: version(4)+traffic class(8)+flow label(20) = 4 bytes,
    # payload_len(2), next_header(1), hop_limit(1), src(16), dst(16) = 40 bytes total
    version_tc_flow = (6 << 28)
    ipv6 = struct.pack("!IHBB16s16s", version_tc_flow, 0, 59, 64,
                        bytes([0x20] + [0] * 15), bytes([0x20] + [0] * 14 + [1]))
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x86DD)
    pkt = parse_ethernet_frame(eth + ipv6, timestamp=1.0)
    assert pkt.protocol == "IPv6"
    assert pkt.src_ip is not None
    assert pkt.dst_ip is not None


def test_unknown_ethertype_is_other():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x9999)
    pkt = parse_ethernet_frame(eth + b"\x00" * 10, timestamp=1.0)
    assert pkt.protocol == "Other"


# ---------------------------------------------------------------- malformed input

def test_frame_too_short_is_malformed():
    pkt = parse_ethernet_frame(b"\x00" * 5, timestamp=1.0)
    assert pkt.protocol == "Malformed"
    assert pkt.is_malformed
    assert pkt.error is not None


def test_truncated_ip_header_is_malformed():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x0800)
    pkt = parse_ethernet_frame(eth + b"\x45\x00\x00\x01", timestamp=1.0)
    assert pkt.protocol == "Malformed"
    assert pkt.is_malformed


def test_truncated_tcp_header_is_malformed():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 25, 0, 0, 64, 6, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    pkt = parse_ethernet_frame(eth + ip + b"\x00\x50\x00\x50", timestamp=1.0)  # only 4 TCP bytes
    assert pkt.protocol == "Malformed"


def test_wrong_ip_version_is_malformed():
    eth = struct.pack("!6s6sH", b"\x02" * 6, b"\x03" * 6, 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x65, 0, 20, 0, 0, 64, 6, 0,  # 0x6 in the version nibble, not 0x4
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    pkt = parse_ethernet_frame(eth + ip, timestamp=1.0)
    assert pkt.protocol == "Malformed"
    assert "version" in pkt.error
