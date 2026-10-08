import pytest

from project import (
    load_logs,
    parse_log,
    analyze_events,
    detect_suspicious_activity,
    generate_report,
)


def test_parse_log():
    line = "2026-10-01 10:21:03 LOGIN_FAILED 192.168.1.20"

    assert parse_log(line) == {
        "date": "2026-10-01",
        "time": "10:21:03",
        "event": "LOGIN_FAILED",
        "ip": "192.168.1.20",
    }


def test_parse_log_invalid():
    with pytest.raises(ValueError):
        parse_log("invalid log")


def test_analyze_events():
    events = [
        {"event": "LOGIN_FAILED", "ip": "192.168.1.20"},
        {"event": "LOGIN_SUCCESS", "ip": "192.168.1.20"},
        {"event": "LOGIN_FAILED", "ip": "10.0.0.5"},
    ]

    assert analyze_events(events) == {
        "total": 3,
        "failed": 2,
        "successful": 1,
    }


def test_detect_suspicious_activity():
    events = [
        {"event": "LOGIN_FAILED", "ip": "192.168.1.20"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.20"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.20"},
        {"event": "LOGIN_FAILED", "ip": "10.0.0.5"},
    ]

    assert detect_suspicious_activity(events) == {
        "192.168.1.20": 3
    }


def test_detect_suspicious_activity_below_threshold():
    events = [
        {"event": "LOGIN_FAILED", "ip": "10.0.0.5"},
        {"event": "LOGIN_FAILED", "ip": "10.0.0.5"},
    ]

    assert detect_suspicious_activity(events) == {}


def test_generate_report():
    stats = {
        "total": 3,
        "failed": 2,
        "successful": 1,
    }

    suspicious = {
        "192.168.1.20": 3
    }

    report = generate_report(stats, suspicious)

    assert "Total events:       3" in report
    assert "Failed logins:      2" in report
    assert "Successful logins:  1" in report
    assert "192.168.1.20" in report

def test_load_logs(tmp_path):
    log_file = tmp_path / "test_logs.txt"
    log_file.write_text("line1\nline2\n")

    assert load_logs(log_file) == ["line1\n", "line2\n"]
    