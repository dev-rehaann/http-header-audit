"""Checks for header evaluation, scoring, and network scanning."""

import httpx
import pytest
import respx

from http_headers_scanner import (
    RULES,
    HeaderFinding,
    ScanReport,
    evaluate_header,
    scan,
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


@respx.mock
def test_scan_fetches_and_grades_one_response() -> None:
    route = respx.get("https://safe.example/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            },
        )
    )

    report = scan("https://safe.example/", user_agent="scanner-test")

    assert route.calls.last.request.headers["user-agent"] == "scanner-test"
    assert report.status_code == 200
    assert report.score == 100


@respx.mock
def test_scan_records_the_final_url_after_redirects() -> None:
    respx.get("http://example.test/").mock(
        return_value=httpx.Response(
            301, headers={"Location": "https://example.test/"}
        )
    )
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(200)
    )

    report = scan("http://example.test/")

    assert report.final_url == "https://example.test/"


@respx.mock
def test_scan_leaves_network_errors_for_the_caller() -> None:
    respx.get("https://offline.example/").mock(
        side_effect=httpx.ConnectError("offline")
    )

    with pytest.raises(httpx.RequestError):
        scan("https://offline.example/")
