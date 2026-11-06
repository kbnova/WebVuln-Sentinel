
"""Tests for security assessment report generation."""

import json

from app.report_generator import build_report, save_report


def test_build_report_summary():
    results = [
        {"website": "https://site1.example", "risk": {"risk_level": "HIGH"}},
        {"website": "https://site2.example", "risk": {"risk_level": "LOW"}},
        {"website": "https://site3.example", "risk": {"risk_level": "REVIEW"}}
    ]

    report = build_report(results)

    assert report["project"] == "WebVuln Sentinel"
    assert report["summary"]["total_targets"] == 3
    assert report["summary"]["risk_counts"]["HIGH"] == 1
    assert report["summary"]["risk_counts"]["LOW"] == 1
    assert report["summary"]["risk_counts"]["REVIEW"] == 1


def test_save_report_creates_json_file(tmp_path):
    results = [
        {"website": "https://site1.example", "risk": {"risk_level": "HIGH"}}
    ]

    output_file = tmp_path / "results.json"
    saved_path = save_report(results, output_file)

    assert saved_path.exists()

    with saved_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["total_targets"] == 1
    assert report["results"][0]["website"] == "https://site1.example"


def test_report_contains_safety_limitations():
    report = build_report([])

    assert report["summary"]["total_targets"] == 0
    assert len(report["limitations"]) > 0
    assert any(
        "does not prove vulnerability" in item
        for item in report["limitations"]
    )


def test_multiple_scans_create_separate_reports(tmp_path):
    first_report = save_report(
        [{"website": "https://example.org"}],
        output_path=tmp_path / "scan_one.json"
    )

    second_report = save_report(
        [{"website": "https://example.com"}],
        output_path=tmp_path / "scan_two.json"
    )

    assert first_report.exists()
    assert second_report.exists()
    assert first_report != second_report


def test_existing_report_is_never_overwritten(tmp_path):
    output_file = tmp_path / "scan.json"

    first_report = save_report(
        [{"website": "https://first.example"}],
        output_path=output_file
    )

    second_report = save_report(
        [{"website": "https://second.example"}],
        output_path=output_file
    )

    assert first_report != second_report
    assert first_report.exists()
    assert second_report.exists()

    with first_report.open("r", encoding="utf-8") as file:
        first_data = json.load(file)

    with second_report.open("r", encoding="utf-8") as file:
        second_data = json.load(file)

    assert first_data["results"][0]["website"] == "https://first.example"
    assert second_data["results"][0]["website"] == "https://second.example"


def test_default_scans_create_separate_reports(tmp_path, monkeypatch):
    import app.report_generator as generator

    monkeypatch.setattr(generator, "DEFAULT_REPORT_DIR", tmp_path)

    first_report = save_report(
        [{"website": "https://first.example"}]
    )

    second_report = save_report(
        [{"website": "https://second.example"}]
    )

    assert first_report != second_report
    assert first_report.exists()
    assert second_report.exists()
