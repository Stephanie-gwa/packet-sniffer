from packetanalyzer.parser import Packet
from packetanalyzer.detectors import (
    detect_port_scans, detect_icmp_floods, detect_cleartext_credentials, run_all_detectors,
)


def tcp_syn(src_ip, dst_ip, dst_port, ts, ack=False):
    flags = ["SYN"] + (["ACK"] if ack else [])
    return Packet(timestamp=ts, length=60, protocol="TCP", src_ip=src_ip, dst_ip=dst_ip,
                   src_port=40000, dst_port=dst_port, tcp_flags=flags)


def icmp_echo_request(src_ip, dst_ip, ts):
    return Packet(timestamp=ts, length=60, protocol="ICMP", src_ip=src_ip, dst_ip=dst_ip, icmp_type=8)


def tcp_payload(src_ip, dst_ip, src_port, dst_port, payload, ts=1.0):
    return Packet(timestamp=ts, length=60 + len(payload), protocol="TCP", src_ip=src_ip, dst_ip=dst_ip,
                   src_port=src_port, dst_port=dst_port, payload=payload)


# ---------------------------------------------------------------- port scan

def test_port_scan_detected_above_threshold():
    packets = [tcp_syn("9.9.9.9", "1.1.1.1", port, ts=100.0 + i * 0.01) for i, port in enumerate(range(20, 40))]
    alerts = detect_port_scans(packets, port_threshold=15)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.type == "port_scan"
    assert a.details["src_ip"] == "9.9.9.9"
    assert a.details["dst_ip"] == "1.1.1.1"
    assert a.details["distinct_ports"] == 20


def test_port_scan_not_flagged_below_threshold():
    packets = [tcp_syn("9.9.9.9", "1.1.1.1", port, ts=100.0 + i) for i, port in enumerate(range(20, 25))]
    alerts = detect_port_scans(packets, port_threshold=15)
    assert alerts == []


def test_port_scan_ignores_syn_ack_replies():
    # SYN-ACK packets are replies, not scan attempts, even across many ports
    packets = [tcp_syn("1.1.1.1", "9.9.9.9", port, ts=100.0 + i, ack=True) for i, port in enumerate(range(20, 45))]
    alerts = detect_port_scans(packets, port_threshold=15)
    assert alerts == []


def test_port_scan_repeated_port_not_counted_twice():
    packets = [tcp_syn("9.9.9.9", "1.1.1.1", 80, ts=100.0 + i) for i in range(20)]  # same port, 20 times
    alerts = detect_port_scans(packets, port_threshold=15)
    assert alerts == []  # only 1 distinct port, however many times it's hit


def test_port_scan_threshold_is_configurable():
    packets = [tcp_syn("9.9.9.9", "1.1.1.1", port, ts=100.0 + i) for i, port in enumerate(range(20, 25))]
    assert detect_port_scans(packets, port_threshold=3) != []
    assert detect_port_scans(packets, port_threshold=10) == []


# ---------------------------------------------------------------- icmp flood

def test_icmp_flood_detected_above_threshold():
    packets = [icmp_echo_request("9.9.9.9", "1.1.1.1", ts=100.0 + i * 0.01) for i in range(25)]
    alerts = detect_icmp_floods(packets, count_threshold=20)
    assert len(alerts) == 1
    assert alerts[0].details["count"] == 25
    assert alerts[0].details["src_ip"] == "9.9.9.9"


def test_icmp_flood_not_flagged_for_normal_ping():
    packets = [icmp_echo_request("9.9.9.9", "1.1.1.1", ts=100.0 + i) for i in range(4)]
    alerts = detect_icmp_floods(packets, count_threshold=20)
    assert alerts == []


def test_icmp_flood_ignores_echo_replies():
    replies = [Packet(timestamp=100.0 + i, length=60, protocol="ICMP", src_ip="9.9.9.9",
                       dst_ip="1.1.1.1", icmp_type=0) for i in range(30)]
    alerts = detect_icmp_floods(replies, count_threshold=20)
    assert alerts == []


# ---------------------------------------------------------------- cleartext credentials

def test_ftp_traffic_flagged():
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 21, b"USER alice\r\n")]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1
    assert alerts[0].details["protocol"] == "FTP"


def test_telnet_traffic_flagged():
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 23, b"login: root\r\n")]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1
    assert alerts[0].details["protocol"] == "Telnet"


def test_ftp_conversation_flagged_once_not_per_packet():
    packets = [
        tcp_payload("1.1.1.1", "2.2.2.2", 52000, 21, b"USER alice\r\n", ts=1.0),
        tcp_payload("1.1.1.1", "2.2.2.2", 52000, 21, b"PASS hunter2\r\n", ts=1.1),
    ]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1


def test_ftp_conversation_flagged_once_across_both_directions():
    packets = [
        tcp_payload("1.1.1.1", "2.2.2.2", 52000, 21, b"USER alice\r\n", ts=1.0),
        tcp_payload("2.2.2.2", "1.1.1.1", 21, 52000, b"331 password required\r\n", ts=1.1),
    ]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1


def test_plain_http_get_not_flagged():
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 80, b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n")]
    alerts = detect_cleartext_credentials(packets)
    assert alerts == []


def test_http_with_password_field_flagged():
    body = b"username=alice&password=hunter2"
    payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 80, payload)]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_http_basic_auth_header_flagged():
    payload = b"GET /admin HTTP/1.1\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n"
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 80, payload)]
    alerts = detect_cleartext_credentials(packets)
    assert len(alerts) == 1


def test_https_traffic_not_flagged():
    packets = [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 443, b"\x16\x03\x03binary-tls-bytes")]
    alerts = detect_cleartext_credentials(packets)
    assert alerts == []


def test_no_payload_not_flagged():
    packets = [Packet(timestamp=1.0, length=60, protocol="TCP", src_ip="1.1.1.1",
                       dst_ip="2.2.2.2", src_port=1, dst_port=21, payload=b"")]
    alerts = detect_cleartext_credentials(packets)
    assert alerts == []


# ---------------------------------------------------------------- run_all_detectors / negatives

def test_normal_traffic_triggers_no_alerts():
    packets = [
        tcp_syn("1.1.1.1", "2.2.2.2", 443, ts=1.0),
        tcp_syn("1.1.1.1", "2.2.2.2", 443, ts=1.1, ack=True),
        icmp_echo_request("1.1.1.1", "2.2.2.2", ts=2.0),
        tcp_payload("1.1.1.1", "2.2.2.2", 5000, 443, b"\x16\x03\x03clienthello"),
    ]
    alerts = run_all_detectors(packets)
    assert alerts == []


def test_run_all_detectors_aggregates_every_type():
    packets = (
        [tcp_syn("9.9.9.9", "1.1.1.1", p, ts=1.0 + i * 0.01) for i, p in enumerate(range(1, 20))]
        + [icmp_echo_request("9.9.9.9", "1.1.1.1", ts=2.0 + i * 0.01) for i in range(25)]
        + [tcp_payload("1.1.1.1", "2.2.2.2", 52000, 21, b"USER alice\r\n", ts=3.0)]
    )
    alerts = run_all_detectors(packets, port_scan_threshold=15, icmp_flood_threshold=20)
    types = {a.type for a in alerts}
    assert types == {"port_scan", "icmp_flood", "cleartext_credentials"}
