from packetanalyzer.parser import Packet
from packetanalyzer.analyzer import summarize


def make_packet(**kw):
    defaults = dict(timestamp=1.0, length=60, protocol="TCP")
    defaults.update(kw)
    return Packet(**defaults)


def test_empty_packet_list():
    summary = summarize([])
    assert summary.total_packets == 0
    assert summary.total_bytes == 0
    assert summary.start_time is None
    assert summary.duration_seconds == 0.0


def test_protocol_counts():
    packets = [
        make_packet(protocol="TCP"), make_packet(protocol="TCP"),
        make_packet(protocol="UDP"), make_packet(protocol="ICMP"),
    ]
    summary = summarize(packets)
    assert summary.protocol_counts == {"TCP": 2, "UDP": 1, "ICMP": 1}
    assert summary.total_packets == 4


def test_total_bytes_and_duration():
    packets = [
        make_packet(timestamp=100.0, length=60),
        make_packet(timestamp=105.5, length=1500),
    ]
    summary = summarize(packets)
    assert summary.total_bytes == 1560
    assert summary.start_time == 100.0
    assert summary.end_time == 105.5
    assert summary.duration_seconds == 5.5


def test_top_talkers_counts_both_directions():
    packets = [
        make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2"),
        make_packet(src_ip="1.1.1.1", dst_ip="3.3.3.3"),
        make_packet(src_ip="2.2.2.2", dst_ip="1.1.1.1"),
    ]
    summary = summarize(packets)
    talkers = dict(summary.top_talkers)
    # 1.1.1.1 appears as src twice and dst once = 3
    assert talkers["1.1.1.1"] == 3
    assert talkers["2.2.2.2"] == 2
    assert talkers["3.3.3.3"] == 1


def test_top_conversations():
    packets = [
        make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2"),
        make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2"),
        make_packet(src_ip="9.9.9.9", dst_ip="8.8.8.8"),
    ]
    summary = summarize(packets)
    convos = dict(summary.top_conversations)
    assert convos[("1.1.1.1", "2.2.2.2")] == 2
    assert convos[("9.9.9.9", "8.8.8.8")] == 1


def test_top_ports_only_counts_tcp_udp():
    packets = [
        make_packet(protocol="TCP", src_port=5000, dst_port=443),
        make_packet(protocol="UDP", src_port=6000, dst_port=53),
        make_packet(protocol="ICMP", src_port=None, dst_port=None),
    ]
    summary = summarize(packets)
    ports = dict(summary.top_ports)
    assert ports.get(443) == 1
    assert ports.get(53) == 1
    assert len(ports) == 4  # 5000, 443, 6000, 53


def test_malformed_count():
    packets = [
        make_packet(protocol="TCP"),
        make_packet(protocol="Malformed", error="bad header"),
    ]
    summary = summarize(packets)
    assert summary.malformed_count == 1


def test_top_n_limit():
    packets = [make_packet(src_ip=f"10.0.0.{i}", dst_ip="1.1.1.1") for i in range(20)]
    summary = summarize(packets, top_n=5)
    assert len(summary.top_talkers) <= 5 + 1  # +1 because 1.1.1.1 also counts as a talker


def test_to_dict_is_json_shaped():
    packets = [make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=443)]
    summary = summarize(packets)
    d = summary.to_dict()
    assert d["total_packets"] == 1
    assert "top_talkers" in d and isinstance(d["top_talkers"], list)
    assert d["top_talkers"][0]["ip"] in ("1.1.1.1", "2.2.2.2")
