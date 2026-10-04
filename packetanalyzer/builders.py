"""
builders.py — construct raw Ethernet frames byte-by-byte.

This module only ever returns `bytes`. Nothing here opens a socket or
sends anything on the wire — it exists to build the offline sample
capture and to give the test suite realistic, hand-verifiable packets
to parse. (Live capture, in live_capture.py, only *receives*; sending
crafted packets is out of scope for this project.)
"""
from __future__ import annotations
import socket as _socket
import struct

from .checksums import checksum16, ipv4_pseudo_header

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def ip_to_bytes(ip: str) -> bytes:
    return _socket.inet_aton(ip)


def build_ethernet_frame(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    header = struct.pack("!6s6sH", mac_to_bytes(dst_mac), mac_to_bytes(src_mac), ethertype)
    return header + payload


def build_arp_packet(
    src_mac: str, src_ip: str, dst_mac: str, dst_ip: str, *, is_reply: bool = False,
) -> bytes:
    """ARP request (op=1) or reply (op=2). dst_mac in a request is conventionally
    ff:ff:ff:ff:ff:ff / 00:00:00:00:00:00 for the unknown target hardware address."""
    op = 2 if is_reply else 1
    target_hw = mac_to_bytes(dst_mac)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, ETHERTYPE_IPV4, 6, 4, op,
        mac_to_bytes(src_mac), ip_to_bytes(src_ip),
        target_hw, ip_to_bytes(dst_ip),
    )
    eth_dst = "ff:ff:ff:ff:ff:ff" if not is_reply else dst_mac
    return build_ethernet_frame(eth_dst, src_mac, ETHERTYPE_ARP, arp)


def _build_ipv4_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int, *, ttl: int = 64, ident: int = 0) -> bytes:
    total_len = 20 + payload_len
    header_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, ttl, protocol, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    csum = checksum16(header_no_csum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, ttl, protocol, csum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )


def _build_tcp_segment(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, *,
    seq: int = 0, ack: int = 0, flags: int = 0, window: int = 8192, payload: bytes = b"",
) -> bytes:
    data_offset_reserved = (5 << 4)  # 5 * 4-byte words, no options
    header_no_csum = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_reserved, flags, window, 0, 0,
    )
    segment_no_csum = header_no_csum + payload
    pseudo = ipv4_pseudo_header(ip_to_bytes(src_ip), ip_to_bytes(dst_ip), IPPROTO_TCP, len(segment_no_csum))
    csum = checksum16(pseudo + segment_no_csum)
    header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_reserved, flags, window, csum, 0,
    )
    return header + payload


def _build_udp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    header_no_csum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ipv4_pseudo_header(ip_to_bytes(src_ip), ip_to_bytes(dst_ip), IPPROTO_UDP, length)
    csum = checksum16(pseudo + header_no_csum + payload)
    csum = csum or 0xFFFF  # per RFC 768, an all-zero computed checksum is sent as all-ones
    header = struct.pack("!HHHH", src_port, dst_port, length, csum)
    return header + payload


def _build_icmp_echo(icmp_type: int, code: int, ident: int, seq: int, payload: bytes = b"") -> bytes:
    header_no_csum = struct.pack("!BBHHH", icmp_type, code, 0, ident, seq)
    csum = checksum16(header_no_csum + payload)
    header = struct.pack("!BBHHH", icmp_type, code, csum, ident, seq)
    return header + payload


def build_tcp_packet(
    *, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    seq: int = 0, ack: int = 0, flags: int = TCP_SYN, payload: bytes = b"",
) -> bytes:
    tcp = _build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq=seq, ack=ack, flags=flags, payload=payload)
    ip = _build_ipv4_header(src_ip, dst_ip, IPPROTO_TCP, len(tcp))
    return build_ethernet_frame(dst_mac, src_mac, ETHERTYPE_IPV4, ip + tcp)


def build_udp_packet(
    *, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"",
) -> bytes:
    udp = _build_udp_segment(src_ip, dst_ip, src_port, dst_port, payload=payload)
    ip = _build_ipv4_header(src_ip, dst_ip, IPPROTO_UDP, len(udp))
    return build_ethernet_frame(dst_mac, src_mac, ETHERTYPE_IPV4, ip + udp)


def build_icmp_echo_packet(
    *, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
    is_reply: bool = False, ident: int = 1, seq: int = 1, payload: bytes = b"pingdata",
) -> bytes:
    icmp_type = 0 if is_reply else 8
    icmp = _build_icmp_echo(icmp_type, 0, ident, seq, payload=payload)
    ip = _build_ipv4_header(src_ip, dst_ip, IPPROTO_ICMP, len(icmp))
    return build_ethernet_frame(dst_mac, src_mac, ETHERTYPE_IPV4, ip + icmp)
