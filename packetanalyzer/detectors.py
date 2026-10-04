"""
detectors.py — a small set of clearly defined, deterministic suspicious-
pattern checks. Each is a heuristic over the packets actually present in
the capture, not a signature database or ML model, and each is
documented precisely so the results are easy to reason about (and to
falsify) — see README "Limitations" for what these do NOT catch.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .parser import Packet

CLEARTEXT_ALWAYS_PORTS = {21: "FTP", 23: "Telnet"}
HTTP_PORT = 80
CREDENTIAL_MARKERS = (b"password=", b"authorization: basic")


@dataclass
class Alert:
    type: str            # "port_scan" | "icmp_flood" | "cleartext_credentials"
    severity: str          # "low" | "medium" | "high"
    summary: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"type": self.type, "severity": self.severity, "summary": self.summary, "details": self.details}


def detect_port_scans(packets: list[Packet], port_threshold: int = 15) -> list[Alert]:
    """Flags a (source IP -> destination IP) pair where the source sent
    TCP SYN packets (SYN set, ACK not set — i.e. connection attempts, not
    replies) to `port_threshold` or more *distinct* destination ports.

    Rationale: a single host legitimately contacting many different ports
    on another single host in one capture is unusual; sequential/rapid
    connection attempts across many ports from one source is the classic
    signature of port scanning tools (nmap, masscan, etc.).

    This is a real but simple heuristic: it will not catch a slow scan
    spread across a long time window if you only look at a short capture,
    and a very chatty legitimate client talking to many services on one
    host in a short window could in principle trigger it too.
    """
    attempts: dict[tuple[str, str], set[int]] = defaultdict(set)
    first_seen: dict[tuple[str, str], float] = {}
    last_seen: dict[tuple[str, str], float] = {}

    for p in packets:
        if p.protocol != "TCP" or not p.src_ip or not p.dst_ip or p.dst_port is None:
            continue
        if "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags:
            key = (p.src_ip, p.dst_ip)
            attempts[key].add(p.dst_port)
            first_seen[key] = min(first_seen.get(key, p.timestamp), p.timestamp)
            last_seen[key] = max(last_seen.get(key, p.timestamp), p.timestamp)

    alerts = []
    for (src, dst), ports in attempts.items():
        if len(ports) >= port_threshold:
            span = last_seen[(src, dst)] - first_seen[(src, dst)]
            alerts.append(Alert(
                type="port_scan", severity="high",
                summary=(
                    f"{src} sent SYN packets to {len(ports)} distinct ports on {dst} "
                    f"in {span:.3f}s — consistent with a port scan."
                ),
                details={
                    "src_ip": src, "dst_ip": dst, "distinct_ports": len(ports),
                    "ports": sorted(ports), "span_seconds": round(span, 6),
                    "threshold": port_threshold,
                },
            ))
    return alerts


def detect_icmp_floods(packets: list[Packet], count_threshold: int = 20) -> list[Alert]:
    """Flags a source IP that sent `count_threshold` or more ICMP echo
    requests (type 8) to the same destination within the capture.

    Rationale: a burst of echo requests from one host to another, all
    within a single (often short) capture, is consistent with an ICMP
    flood / "ping flood". A handful of pings from a normal `ping` command
    will not trigger this at the default threshold.
    """
    counts: dict[tuple[str, str], int] = defaultdict(int)
    first_seen: dict[tuple[str, str], float] = {}
    last_seen: dict[tuple[str, str], float] = {}

    for p in packets:
        if p.protocol != "ICMP" or p.icmp_type != 8 or not p.src_ip or not p.dst_ip:
            continue
        key = (p.src_ip, p.dst_ip)
        counts[key] += 1
        first_seen[key] = min(first_seen.get(key, p.timestamp), p.timestamp)
        last_seen[key] = max(last_seen.get(key, p.timestamp), p.timestamp)

    alerts = []
    for (src, dst), count in counts.items():
        if count >= count_threshold:
            span = last_seen[(src, dst)] - first_seen[(src, dst)]
            alerts.append(Alert(
                type="icmp_flood", severity="medium",
                summary=(
                    f"{src} sent {count} ICMP echo requests to {dst} in {span:.3f}s."
                ),
                details={
                    "src_ip": src, "dst_ip": dst, "count": count,
                    "span_seconds": round(span, 6), "threshold": count_threshold,
                },
            ))
    return alerts


def detect_cleartext_credentials(packets: list[Packet]) -> list[Alert]:
    """Flags TCP payloads that indicate an unencrypted, credential-bearing
    protocol is in use:

      - ANY payload on FTP (port 21) or Telnet (port 23) — these protocols
        are unencrypted by design, so their mere use is worth flagging.
      - HTTP (port 80) payloads, but ONLY when the payload contains a
        recognizable credential marker (an "Authorization: Basic" header
        or a "password=" form field) — plain HTTP GETs are not flagged,
        to keep this signal meaningful rather than firing on every web
        request.

    This looks at literal bytes in the payload; it will miss credentials
    split across multiple TCP segments, and it says nothing about
    protocols that are encrypted by design (HTTPS, SSH, etc.).
    """
    alerts = []
    seen_ftp_telnet_conversations = set()

    for p in packets:
        if p.protocol != "TCP" or not p.payload:
            continue
        port = p.dst_port if p.dst_port in CLEARTEXT_ALWAYS_PORTS else (
            p.src_port if p.src_port in CLEARTEXT_ALWAYS_PORTS else None
        )
        if port is not None:
            # Normalize by unordered endpoint pair so a request and its reply
            # (opposite src/dst) don't produce two alerts for one conversation.
            key = (frozenset((p.src_ip, p.dst_ip)), port)
            if key in seen_ftp_telnet_conversations:
                continue
            seen_ftp_telnet_conversations.add(key)
            proto_name = CLEARTEXT_ALWAYS_PORTS[port]
            alerts.append(Alert(
                type="cleartext_credentials", severity="medium",
                summary=f"{proto_name} traffic between {p.src_ip} and {p.dst_ip} is unencrypted by design.",
                details={
                    "protocol": proto_name, "src_ip": p.src_ip, "dst_ip": p.dst_ip,
                    "port": port, "sample": _safe_snippet(p.payload),
                },
            ))
            continue

        if p.dst_port == HTTP_PORT or p.src_port == HTTP_PORT:
            lowered = p.payload.lower()
            if any(marker in lowered for marker in CREDENTIAL_MARKERS):
                alerts.append(Alert(
                    type="cleartext_credentials", severity="high",
                    summary=(
                        f"Possible credentials sent in cleartext over HTTP "
                        f"between {p.src_ip} and {p.dst_ip}."
                    ),
                    details={
                        "protocol": "HTTP", "src_ip": p.src_ip, "dst_ip": p.dst_ip,
                        "port": HTTP_PORT, "sample": _safe_snippet(p.payload),
                    },
                ))
    return alerts


def _safe_snippet(payload: bytes, max_len: int = 80) -> str:
    text = payload[:max_len].decode("latin-1", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def run_all_detectors(
    packets: list[Packet],
    *, port_scan_threshold: int = 15, icmp_flood_threshold: int = 20,
) -> list[Alert]:
    alerts: list[Alert] = []
    alerts += detect_port_scans(packets, port_threshold=port_scan_threshold)
    alerts += detect_icmp_floods(packets, count_threshold=icmp_flood_threshold)
    alerts += detect_cleartext_credentials(packets)
    return alerts
