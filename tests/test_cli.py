import json
from pathlib import Path

import pytest

from packetanalyzer import cli

SAMPLE_PCAP = str(Path(__file__).resolve().parent.parent / "sample_data" / "sample_capture.pcap")


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_analyze_defaults():
    args = cli.build_parser().parse_args(["analyze", "--pcap", SAMPLE_PCAP])
    assert args.pcap == SAMPLE_PCAP
    assert args.port_scan_threshold == 15
    assert args.icmp_flood_threshold == 20


# ---------------------------------------------------------------- analyze: end to end

def test_analyze_json_stdout_matches_known_sample_capture(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["summary"]["total_packets"] == 80
    assert payload["summary"]["protocol_counts"]["TCP"] == 46
    assert payload["summary"]["protocol_counts"]["ICMP"] == 30
    assert payload["summary"]["protocol_counts"]["ARP"] == 2
    assert payload["summary"]["protocol_counts"]["UDP"] == 2

    alert_types = {a["type"] for a in payload["alerts"]}
    assert alert_types == {"port_scan", "icmp_flood", "cleartext_credentials"}
    assert payload["alert_count"] == 4


def test_analyze_port_scan_alert_details(capsys):
    cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet"])
    payload = json.loads(capsys.readouterr().out)
    scan_alerts = [a for a in payload["alerts"] if a["type"] == "port_scan"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0]["details"]["src_ip"] == "198.51.100.66"
    assert scan_alerts[0]["details"]["dst_ip"] == "192.168.1.10"
    assert scan_alerts[0]["details"]["distinct_ports"] == 25


def test_analyze_higher_thresholds_suppress_alerts(capsys):
    rc = cli.main([
        "analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet",
        "--port-scan-threshold", "1000", "--icmp-flood-threshold", "1000",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    types = {a["type"] for a in payload["alerts"]}
    assert "port_scan" not in types
    assert "icmp_flood" not in types
    assert "cleartext_credentials" in types  # unaffected by these two thresholds


def test_analyze_no_alerts_flag(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet", "--no-alerts"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["alerts"] == []


def test_analyze_protocol_filter_affects_summary_not_alerts(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet", "--protocol", "ICMP"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_packets"] == 30
    assert set(payload["summary"]["protocol_counts"].keys()) == {"ICMP"}
    # alerts still run over the FULL capture, so port_scan is still reported
    assert any(a["type"] == "port_scan" for a in payload["alerts"])


def test_analyze_ip_filter(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet",
                    "--ip", "203.0.113.20"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_packets"] == 8  # the FTP conversation


def test_analyze_port_filter(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--json-stdout", "--quiet", "--port", "21"])
    payload = json.loads(capsys.readouterr().out)
    # The 8 real FTP-session packets, plus 1 port-scan SYN that (realistically)
    # happens to probe port 21 among its 25 targets.
    assert payload["summary"]["total_packets"] == 9


def test_analyze_writes_output_file(tmp_path):
    out = tmp_path / "out.json"
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--quiet", "--output", str(out)])
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["summary"]["total_packets"] == 80
    assert payload["source"] == SAMPLE_PCAP


def test_analyze_table_output_contains_alerts_section(capsys):
    rc = cli.main(["analyze", "--pcap", SAMPLE_PCAP, "--quiet"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "port_scan" in out
    assert "Protocol breakdown" in out


def test_analyze_missing_file_errors():
    with pytest.raises(SystemExit):
        cli.main(["analyze", "--pcap", "/no/such/file.pcap", "--quiet"])


# ---------------------------------------------------------------- list-interfaces

def test_list_interfaces_runs_without_crashing(capsys):
    rc = cli.main(["list-interfaces", "--quiet"])
    assert rc in (0, 2)  # 2 only if the platform genuinely has no way to list interfaces
    out = capsys.readouterr().out
    if rc == 0:
        assert len(out.strip().splitlines()) >= 1


# ---------------------------------------------------------------- capture: authorization gating only
# (Real capture needs root and a live interface — see test_live_capture.py for what
#  IS exercised for real. Here we only test the CLI's consent gate.)

def test_capture_refuses_without_yes_when_non_interactive(capsys):
    rc = cli.main(["capture", "--iface", "lo", "--count", "1", "--quiet"])
    assert rc == 1
    assert "Aborted" in capsys.readouterr().err
