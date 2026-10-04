"""
parser.py — decode a raw captured Ethernet frame into a structured Packet.

Supported: Ethernet II framing; ARP; IPv4 with TCP, UDP, or ICMP payloads.
IPv6 frames are recognized (ethertype 0x86DD) and reported with protocol
"IPv6", but their payload is not decoded further — see README limitations.
Anything else is reported as protocol "Other".

This module does not validate checksums (see checksums.py docstring and
the README) — it only extracts header fields.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FLAG_BITS = [
    ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
    ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
]

ICMP_TYPE_NAMES = {
    0: "echo-reply", 3: "dest-unreachable", 5: "redirect",
    8: "echo-request", 11: "time-exceeded",
}


@dataclass
class Packet:
    timestamp: float
    length: int                       # length captured off the wire (orig_len)
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    ethertype: Optional[int] = None
    protocol: str = "Other"           # "ARP" | "TCP" | "UDP" | "ICMP" | "IPv6" | "Other" | "Malformed"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: list[str] = field(default_factory=list)
    icmp_type: Optional[int] = None
    icmp_type_name: Optional[str] = None
    arp_op: Optional[str] = None      # "request" | "reply"
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    payload: bytes = b""
    error: Optional[str] = None       # set if parsing stopped early due to malformed data

    @property
    def is_malformed(self) -> bool:
        return self.error is not None


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def parse_ethernet_frame(data: bytes, timestamp: float, orig_len: Optional[int] = None) -> Packet:
    """Parse one raw Ethernet II frame. `orig_len` defaults to len(data)
    (i.e. assume the capture was not snaplen-truncated) if not given."""
    length = orig_len if orig_len is not None else len(data)

    if len(data) < 14:
        return Packet(timestamp=timestamp, length=length, protocol="Malformed",
                       error="Frame shorter than a minimum Ethernet header (14 bytes).")

    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", data[:14])
    pkt = Packet(
        timestamp=timestamp, length=length,
        eth_dst=_mac_str(dst_mac), eth_src=_mac_str(src_mac), ethertype=ethertype,
    )
    payload = data[14:]

    if ethertype == ETHERTYPE_ARP:
        _parse_arp(pkt, payload)
    elif ethertype == ETHERTYPE_IPV4:
        _parse_ipv4(pkt, payload)
    elif ethertype == ETHERTYPE_IPV6:
        pkt.protocol = "IPv6"
        if len(payload) >= 40:
            pkt.src_ip = _ipv6_str(payload[8:24])
            pkt.dst_ip = _ipv6_str(payload[24:40])
    else:
        pkt.protocol = "Other"

    return pkt


def _ipv6_str(raw: bytes) -> str:
    groups = [raw[i:i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(groups)


def _parse_arp(pkt: Packet, payload: bytes) -> None:
    pkt.protocol = "ARP"
    if len(payload) < 28:
        pkt.error = "ARP payload shorter than expected (28 bytes)."
        return
    htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", payload[:28])
    pkt.arp_op = "reply" if oper == 2 else "request"
    pkt.arp_sender_mac = _mac_str(sha)
    pkt.arp_sender_ip = _ip_str(spa)
    pkt.arp_target_ip = _ip_str(tpa)
    pkt.src_ip = pkt.arp_sender_ip
    pkt.dst_ip = pkt.arp_target_ip


def _parse_ipv4(pkt: Packet, payload: bytes) -> None:
    if len(payload) < 20:
        pkt.protocol = "Malformed"
        pkt.error = "IPv4 payload shorter than a minimum header (20 bytes)."
        return

    version_ihl = payload[0]
    version = version_ihl >> 4
    ihl_words = version_ihl & 0x0F
    ihl_bytes = ihl_words * 4
    if version != 4:
        pkt.protocol = "Malformed"
        pkt.error = f"Expected IPv4 (version 4), got version {version}."
        return
    if ihl_bytes < 20 or len(payload) < ihl_bytes:
        pkt.protocol = "Malformed"
        pkt.error = "IPv4 header length (IHL) invalid or longer than captured data."
        return

    total_length, _ident, _flags_frag, ttl, protocol_num, _csum = struct.unpack(
        "!xxHHHBBH", payload[:12]
    )
    src_ip = _ip_str(payload[12:16])
    dst_ip = _ip_str(payload[16:20])
    pkt.src_ip = src_ip
    pkt.dst_ip = dst_ip

    transport = payload[ihl_bytes:]

    if protocol_num == IPPROTO_TCP:
        _parse_tcp(pkt, transport)
    elif protocol_num == IPPROTO_UDP:
        _parse_udp(pkt, transport)
    elif protocol_num == IPPROTO_ICMP:
        _parse_icmp(pkt, transport)
    else:
        pkt.protocol = "Other"


def _parse_tcp(pkt: Packet, data: bytes) -> None:
    pkt.protocol = "TCP"
    if len(data) < 20:
        pkt.protocol = "Malformed"
        pkt.error = "TCP segment shorter than a minimum header (20 bytes)."
        return
    src_port, dst_port, _seq, _ack, offset_flags = struct.unpack("!HHIIH", data[:14])
    data_offset_words = (offset_flags >> 12) & 0x0F
    flags_byte = offset_flags & 0xFF
    header_len = data_offset_words * 4
    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.tcp_flags = [name for name, bit in TCP_FLAG_BITS if flags_byte & bit]
    if header_len >= 20 and len(data) >= header_len:
        pkt.payload = data[header_len:]


def _parse_udp(pkt: Packet, data: bytes) -> None:
    pkt.protocol = "UDP"
    if len(data) < 8:
        pkt.protocol = "Malformed"
        pkt.error = "UDP segment shorter than a minimum header (8 bytes)."
        return
    src_port, dst_port, length, _csum = struct.unpack("!HHHH", data[:8])
    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.payload = data[8:]


def _parse_icmp(pkt: Packet, data: bytes) -> None:
    pkt.protocol = "ICMP"
    if len(data) < 8:
        pkt.protocol = "Malformed"
        pkt.error = "ICMP payload shorter than a minimum header (8 bytes)."
        return
    icmp_type, _code = struct.unpack("!BB", data[:2])
    pkt.icmp_type = icmp_type
    pkt.icmp_type_name = ICMP_TYPE_NAMES.get(icmp_type, f"type-{icmp_type}")
    pkt.payload = data[8:]
