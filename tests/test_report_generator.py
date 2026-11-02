
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
