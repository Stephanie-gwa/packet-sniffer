import socket
import threading
import time
from unittest.mock import patch

import pytest

from packetanalyzer.live_capture import (
    list_interfaces, capture_packets, capture_to_pcap, LiveCaptureError, _has_af_packet,
)
from packetanalyzer.parser import parse_ethernet_frame
from packetanalyzer.pcap_io import read_pcap


def test_capture_requires_count_or_duration():
    with pytest.raises(LiveCaptureError):
        capture_packets("lo")


def test_list_interfaces_includes_loopback_or_skips():
    try:
        ifaces = list_interfaces()
    except LiveCaptureError as e:
        pytest.skip(f"Cannot list interfaces in this environment: {e}")
    assert any(name.lower() in ("lo", "loopback", "lo0") for name in ifaces), ifaces


@pytest.mark.skipif(not _has_af_packet(), reason="AF_PACKET raw sockets are Linux-only")
def test_real_capture_on_loopback_sees_a_udp_packet():
    """A genuine end-to-end capture: sends one real UDP datagram over the
    loopback interface while capturing on it, and confirms the capture
    engine actually observes and correctly parses it. Requires root /
    CAP_NET_RAW; skips (rather than fails) if that isn't available here."""
    marker_port = 44444
    payload = b"packetanalyzer-live-capture-selftest"

    def send_after_delay():
        time.sleep(0.4)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", marker_port))
        s.close()

    threading.Thread(target=send_after_delay, daemon=True).start()

    try:
        packets = capture_packets("lo", duration=2.0)
    except LiveCaptureError as e:
        pytest.skip(f"Live capture unavailable in this environment (needs root): {e}")

    matching = None
    for ts, raw in packets:
        pkt = parse_ethernet_frame(raw, ts)
        if pkt.protocol == "UDP" and pkt.dst_port == marker_port:
            matching = pkt
            break

    assert matching is not None, "expected UDP test packet was not observed in the capture"
    assert matching.src_ip == "127.0.0.1"
    assert matching.dst_ip == "127.0.0.1"
    assert matching.payload == payload


def test_capture_to_pcap_writes_captured_packets(tmp_path):
    fake_packets = [(1000.0, b"\x00" * 20), (1000.5, b"\x01" * 30)]
    with patch("packetanalyzer.live_capture.capture_packets", return_value=fake_packets):
        out_path = tmp_path / "live.pcap"
        count = capture_to_pcap("lo", str(out_path), count=2)

    assert count == 2
    read_back = list(read_pcap(out_path))
    assert [rp.data for rp in read_back] == [b"\x00" * 20, b"\x01" * 30]


def test_scapy_backend_raises_clear_error_when_not_installed():
    from packetanalyzer.live_capture import _capture_scapy
    try:
        import scapy  # noqa: F401
        pytest.skip("scapy is installed in this environment; nothing to test here")
    except ImportError:
        pass
    with pytest.raises(ImportError):
        _capture_scapy("lo", 1, None, None)


def test_permission_error_produces_helpful_message():
    with patch("packetanalyzer.live_capture.socket.socket", side_effect=PermissionError("Operation not permitted")):
        with pytest.raises(LiveCaptureError, match="setcap|sudo"):
            capture_packets("lo", count=1)
