"""
cli.py — command-line entry point.

    python -m packetanalyzer analyze --pcap sample_data/sample_capture.pcap
    python -m packetanalyzer analyze --pcap capture.pcap --protocol TCP --port 443
    python -m packetanalyzer list-interfaces
    python -m packetanalyzer capture --iface lo --count 50 --save out.pcap
"""
from __future__ import annotations
import argparse
import sys

from .pcap_io import read_pcap, PcapFormatError, write_pcap
from .parser import parse_ethernet_frame, Packet
from .analyzer import summarize
from .filters import apply_filters
from .detectors import run_all_detectors
from .reporter import format_summary, format_alerts, save_json, to_json_string
from .live_capture import list_interfaces as _list_ifaces, capture_packets, LiveCaptureError

CAPTURE_AUTHORIZATION_NOTICE = """\
Live capture reads every packet that reaches this interface, including
traffic from other people/devices on a shared network segment.
Only capture on an interface and network you own or are explicitly
authorized to monitor. Capturing others' traffic without consent may
be illegal where you live and typically violates network/employer
acceptable-use policies.
"""


def load_pcap(path: str) -> list[Packet]:
    try:
        raw_packets = list(read_pcap(path))
    except PcapFormatError as e:
        raise SystemExit(f"Error: {e}")
    except FileNotFoundError:
        raise SystemExit(f"Error: file not found: {path}")
    return [
        parse_ethernet_frame(rp.data, rp.timestamp, orig_len=rp.orig_len)
        for rp in raw_packets
    ]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packetanalyzer",
        description="Offline (and optional live) packet capture analysis.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze an offline .pcap file")
    analyze.add_argument("--pcap", required=True, help="Path to a classic .pcap file")
    analyze.add_argument("--protocol", default=None, help="Filter: ARP, TCP, UDP, ICMP, IPv6, Other")
    analyze.add_argument("--src", default=None, help="Filter: source IP")
    analyze.add_argument("--dst", default=None, help="Filter: destination IP")
    analyze.add_argument("--ip", default=None, help="Filter: source OR destination IP")
    analyze.add_argument("--port", type=int, default=None, help="Filter: source OR destination port")
    analyze.add_argument("--top", type=int, default=10, help="How many top talkers/conversations/ports to show")
    analyze.add_argument("--port-scan-threshold", type=int, default=15,
                          help="Distinct ports from one source that trigger a port-scan alert (default: 15)")
    analyze.add_argument("--icmp-flood-threshold", type=int, default=20,
                          help="ICMP echo requests from one source that trigger a flood alert (default: 20)")
    analyze.add_argument("--no-alerts", action="store_true", help="Skip suspicious-pattern detection")
    analyze.add_argument("--output", "-o", default=None, help="Write full results as JSON to this file")
    analyze.add_argument("--json-stdout", action="store_true", help="Print JSON to stdout instead of a table")
    analyze.add_argument("--quiet", "-q", action="store_true", help="Suppress informational messages")

    listifaces = sub.add_parser("list-interfaces", help="List available network interfaces")
    listifaces.add_argument("--quiet", "-q", action="store_true")

    capture = sub.add_parser("capture", help="OPTIONAL: capture live traffic on an interface you control")
    capture.add_argument("--iface", required=True, help="Interface name to capture on (see list-interfaces)")
    capture.add_argument("--count", type=int, default=None, help="Stop after this many packets")
    capture.add_argument("--duration", type=float, default=None, help="Stop after this many seconds")
    capture.add_argument("--save", default=None, help="Write captured packets to this .pcap file")
    capture.add_argument("--analyze", action="store_true", help="Run the same analysis on the capture afterwards")
    capture.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation")
    capture.add_argument("--quiet", "-q", action="store_true")

    return p


def _confirm_capture_authorization(assume_yes: bool, quiet: bool) -> bool:
    if not quiet:
        print(CAPTURE_AUTHORIZATION_NOTICE, file=sys.stderr)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to capture without --yes in a non-interactive session.", file=sys.stderr)
        return False
    try:
        answer = input("Type 'yes' to confirm you are authorized to capture on this interface: ")
    except EOFError:
        return False
    return answer.strip().lower() == "yes"


def cmd_analyze(args) -> int:
    packets = load_pcap(args.pcap)

    alerts = [] if args.no_alerts else run_all_detectors(
        packets,
        port_scan_threshold=args.port_scan_threshold,
        icmp_flood_threshold=args.icmp_flood_threshold,
    )

    filtered = apply_filters(
        packets, protocol=args.protocol, src_ip=args.src, dst_ip=args.dst, ip=args.ip, port=args.port,
    )
    is_filtered = any([args.protocol, args.src, args.dst, args.ip, args.port is not None])
    summary = summarize(filtered, top_n=args.top)

    if args.output:
        save_json(summary, alerts, args.output, source=args.pcap)
        if not args.quiet:
            print(f"Full results written to {args.output}", file=sys.stderr)

    if args.json_stdout:
        print(to_json_string(summary, alerts, source=args.pcap))
        return 0

    if not args.quiet:
        print(f"Source: {args.pcap}")
        if is_filtered:
            print(f"(filters applied — showing {len(filtered)} of {len(packets)} packets; "
                  f"alerts below are computed over the FULL capture, not just the filtered view)")
        print()
    print(format_summary(summary))
    if not args.no_alerts:
        print()
        print(format_alerts(alerts))
    return 0


def cmd_list_interfaces(args) -> int:
    try:
        ifaces = _list_ifaces()
    except LiveCaptureError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    for name in ifaces:
        print(name)
    return 0


def cmd_capture(args) -> int:
    if not _confirm_capture_authorization(args.yes, args.quiet):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 1

    progress = {"n": 0}

    def on_packet(_ts, _data):
        progress["n"] += 1
        if not args.quiet:
            print(f"\rCaptured {progress['n']} packet(s)...", end="", file=sys.stderr, flush=True)

    try:
        packets = capture_packets(
            args.iface, count=args.count, duration=args.duration, on_packet=on_packet,
        )
    except LiveCaptureError as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(file=sys.stderr)

    if args.save:
        write_pcap(args.save, iter(packets))
        if not args.quiet:
            print(f"Wrote {len(packets)} packets to {args.save}", file=sys.stderr)

    if args.analyze:
        parsed = [parse_ethernet_frame(data, ts) for ts, data in packets]
        summary = summarize(parsed)
        alerts = run_all_detectors(parsed)
        print(format_summary(summary))
        print()
        print(format_alerts(alerts))
    elif not args.save:
        print(f"Captured {len(packets)} packet(s). Use --save to write a .pcap file "
              f"or --analyze to summarize immediately.")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "list-interfaces":
        return cmd_list_interfaces(args)
    if args.command == "capture":
        return cmd_capture(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
