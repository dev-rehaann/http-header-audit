"""Checks for the pure header evaluation and scoring core."""

from http_headers_scanner import (
    RULES,
    HeaderFinding,
    ScanReport,
    evaluate_header,
)


def test_header_evaluation_handles_case_and_required_values() -> None:
    hsts = RULES[0]

    assert evaluate_header(
        hsts, {"strict-transport-security": "max-age=31536000"}
    ).status == "ok"
    assert evaluate_header(
        hsts, {"Strict-Transport-Security": "max-age=0"}
    ).status == "weak"
    assert evaluate_header(hsts, {}).status == "missing"


def test_report_scores_and_grades_findings() -> None:
    findings = tuple(
        HeaderFinding(rule, "ok", "configured", "Present") for rule in RULES
    )
    report = ScanReport(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        findings=findings,
    )

    assert report.score == 100
    assert report.grade == "A"


def test_weak_rules_receive_half_points() -> None:
    report = ScanReport(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        findings=(HeaderFinding(RULES[0], "weak", "max-age=0", "Weak"),),
    )

    assert report.score == 15
    assert report.grade == "F"
