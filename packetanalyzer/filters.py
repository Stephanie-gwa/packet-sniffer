"""
filters.py — simple, explicit filters over a list of parsed Packets.

This intentionally does not implement full BPF/Wireshark display-filter
syntax; it supports the common cases (protocol, source, destination,
port) as plain function arguments, which keeps behavior easy to read,
test, and reason about.
"""
from __future__ import annotations
from typing import Optional

from .parser import Packet

VALID_PROTOCOLS = {"ARP", "TCP", "UDP", "ICMP", "IPv6", "Other", "Malformed"}


def apply_filters(
    packets: list[Packet],
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    ip: Optional[str] = None,      # matches either source OR destination
    port: Optional[int] = None,    # matches either source OR destination port
) -> list[Packet]:
    result = packets

    if protocol:
        proto = protocol.upper() if protocol.upper() in {"ARP", "TCP", "UDP", "ICMP", "OTHER"} else protocol
        proto = "Other" if proto == "OTHER" else proto
        result = [p for p in result if p.protocol == proto]

    if src_ip:
        result = [p for p in result if p.src_ip == src_ip]

    if dst_ip:
        result = [p for p in result if p.dst_ip == dst_ip]

    if ip:
        result = [p for p in result if p.src_ip == ip or p.dst_ip == ip]

    if port is not None:
        result = [p for p in result if p.src_port == port or p.dst_port == port]

    return result
