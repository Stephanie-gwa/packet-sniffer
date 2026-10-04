"""
reporter.py — render a CaptureSummary + list[Alert] as a human-readable
text report or a JSON-serializable dict.
"""
from __future__ import annotations
import json
from typing import Optional

from .analyzer import CaptureSummary
from .detectors import Alert

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def to_dict(summary: CaptureSummary, alerts: list[Alert], source: Optional[str] = None) -> dict:
    return {
        "source": source,
        "summary": summary.to_dict(),
        "alerts": [a.to_dict() for a in sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))],
        "alert_count": len(alerts),
    }


def save_json(summary: CaptureSummary, alerts: list[Alert], path: str, source: Optional[str] = None) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_dict(summary, alerts, source=source), f, indent=2)


def to_json_string(summary: CaptureSummary, alerts: list[Alert], source: Optional[str] = None) -> str:
    return json.dumps(to_dict(summary, alerts, source=source), indent=2)


def format_summary(summary: CaptureSummary) -> str:
    lines = []
    lines.append(f"Packets:   {summary.total_packets}   Bytes: {summary.total_bytes}")
    lines.append(f"Duration:  {summary.duration_seconds:.3f}s")
    if summary.malformed_count:
        lines.append(f"Malformed: {summary.malformed_count} packet(s) could not be fully parsed")
    lines.append("")
    lines.append("Protocol breakdown:")
    total = summary.total_packets or 1
    for proto, count in summary.protocol_counts.items():
        pct = 100 * count / total
        lines.append(f"  {proto:<10} {count:>6}  ({pct:5.1f}%)")
    lines.append("")
    lines.append("Top talkers (by packet count):")
    for ip, count in summary.top_talkers:
        lines.append(f"  {ip:<18} {count:>6}")
    lines.append("")
    lines.append("Top conversations:")
    for (src, dst), count in summary.top_conversations:
        lines.append(f"  {src:<18} -> {dst:<18} {count:>6}")
    if summary.top_ports:
        lines.append("")
        lines.append("Most active ports:")
        for port, count in summary.top_ports:
            lines.append(f"  {port:<6} {count:>6}")
    return "\n".join(lines)


def format_alerts(alerts: list[Alert]) -> str:
    if not alerts:
        return "No suspicious patterns flagged."
    lines = [f"{len(alerts)} alert(s):", ""]
    for a in sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9)):
        lines.append(f"[{a.severity.upper():<6}] {a.type}: {a.summary}")
    return "\n".join(lines)
