"""
analyzer.py — turn a list of parsed Packets into summary statistics.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .parser import Packet


@dataclass
class CaptureSummary:
    total_packets: int
    total_bytes: int
    start_time: Optional[float]
    end_time: Optional[float]
    protocol_counts: dict = field(default_factory=dict)
    top_talkers: list = field(default_factory=list)       # [(ip, packet_count), ...]
    top_conversations: list = field(default_factory=list)  # [((src, dst), packet_count), ...]
    top_ports: list = field(default_factory=list)           # [(port, packet_count), ...]
    malformed_count: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 6),
            "protocol_counts": self.protocol_counts,
            "top_talkers": [{"ip": ip, "packets": n} for ip, n in self.top_talkers],
            "top_conversations": [
                {"src": src, "dst": dst, "packets": n} for (src, dst), n in self.top_conversations
            ],
            "top_ports": [{"port": port, "packets": n} for port, n in self.top_ports],
            "malformed_count": self.malformed_count,
        }


def summarize(packets: list[Packet], top_n: int = 10) -> CaptureSummary:
    if not packets:
        return CaptureSummary(total_packets=0, total_bytes=0, start_time=None, end_time=None)

    protocol_counts = Counter(p.protocol for p in packets)
    ip_counts = Counter()
    conversation_counts = Counter()
    port_counts = Counter()
    malformed = 0
    total_bytes = 0

    for p in packets:
        total_bytes += p.length
        if p.is_malformed:
            malformed += 1
        if p.src_ip:
            ip_counts[p.src_ip] += 1
        if p.dst_ip:
            ip_counts[p.dst_ip] += 1
        if p.src_ip and p.dst_ip:
            conversation_counts[(p.src_ip, p.dst_ip)] += 1
        if p.protocol in ("TCP", "UDP"):
            if p.src_port is not None:
                port_counts[p.src_port] += 1
            if p.dst_port is not None:
                port_counts[p.dst_port] += 1

    timestamps = [p.timestamp for p in packets]

    return CaptureSummary(
        total_packets=len(packets),
        total_bytes=total_bytes,
        start_time=min(timestamps),
        end_time=max(timestamps),
        protocol_counts=dict(protocol_counts.most_common()),
        top_talkers=ip_counts.most_common(top_n),
        top_conversations=conversation_counts.most_common(top_n),
        top_ports=port_counts.most_common(top_n),
        malformed_count=malformed,
    )
