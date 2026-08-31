"""Fetch, evaluate, score, and report HTTP security headers."""

import argparse
import math
import re
import sys
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """A security header requirement."""

    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Forces future connections to use HTTPS.",
        recommendation=(
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        must_match=r"max-age\s*=\s*[1-9]\d*",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Restricts where page resources may be loaded from.",
        recommendation="Add a Content-Security-Policy suited to this site.",
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="Prevents browsers from guessing response content types.",
        recommendation="Add: X-Content-Type-Options: nosniff",
        must_match=r"^\s*nosniff\s*$",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Prevents other sites from framing the page.",
        recommendation="Add: X-Frame-Options: DENY",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        description="Limits information sent in the Referer header.",
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        description="Restricts access to sensitive browser features.",
        recommendation=(
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    ),
)

SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}

DEFAULT_USER_AGENT = (
    "http-header-audit/0.1 (+https://github.com/dev-rehaann/http-header-audit)"
)

STATUS_COLORS: dict[Status, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

GRADE_COLORS = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    """The result of evaluating one header rule."""

    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Findings and calculated grade for one response."""

    url: str
    final_url: str
    status_code: int
    findings: tuple[HeaderFinding, ...]

    @property
    def score(self) -> int:
        total = sum(SEVERITY_POINTS[rule.severity] for rule in RULES)
        earned = sum(
            SEVERITY_POINTS[finding.rule.severity]
            * (1 if finding.status == "ok" else 0.5)
            for finding in self.findings
            if finding.status != "missing"
        )
        return int(earned / total * 100 + 0.5) if total else 0

    @property
    def grade(self) -> str:
        for minimum, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if self.score >= minimum:
                return grade
        return "F"


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str, str],
) -> HeaderFinding:
    """Apply one rule to a case-insensitive collection of headers."""

    actual_value = next(
        (
            value
            for name, value in response_headers.items()
            if name.casefold() == rule.header.casefold()
        ),
        None,
    )
    if actual_value is None:
        return HeaderFinding(
            rule, "missing", None, f"Header `{rule.header}` is not set"
        )
    if rule.must_match and not re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule,
            "weak",
            actual_value,
            f"Present but does not match `{rule.must_match}`",
        )
    note = f"Present and matches `{rule.must_match}`" if rule.must_match else "Present"
    return HeaderFinding(rule, "ok", actual_value, note)


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    """Fetch one URL and evaluate its response security headers."""

    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    )
    response_headers = dict(response.headers)
    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=tuple(evaluate_header(rule, response_headers) for rule in RULES),
    )


def _render_report(report: ScanReport, console: Console) -> None:
    table = Table(
        title=Text(f"Headers for {report.final_url} (HTTP {report.status_code})")
    )
    table.add_column("header", style="cyan")
    table.add_column("status")
    table.add_column("severity")
    table.add_column("note", overflow="fold")

    for finding in report.findings:
        table.add_row(
            finding.rule.header,
            Text(finding.status, style=STATUS_COLORS[finding.status]),
            finding.rule.severity,
            Text(finding.note),
        )
    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] this response used plain HTTP, so "
            "browsers will ignore any HSTS header."
        )

    result = Text("Grade: ")
    result.append(report.grade, style=f"bold {GRADE_COLORS[report.grade]}")
    result.append(f"\nScore: {report.score} / 100")
    console.print(Panel(result, title="Result"))

    actionable = tuple(finding for finding in report.findings if finding.status != "ok")
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            recommendation = Text("  - ")
            recommendation.append(finding.rule.header, style="bold")
            recommendation.append(f" - {finding.rule.recommendation}")
            console.print(recommendation)


def _http_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            "URL must include http:// or https:// and a host"
        )
    return value


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Grade a URL's HTTP security headers A-F.",
    )
    parser.add_argument(
        "url",
        type=_http_url,
        help="Full URL to scan, including http:// or https://.",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=10.0,
        help="Seconds to wait for the request (default: 10).",
    )
    return parser


def main() -> int:
    args = _build_argument_parser().parse_args()
    console = Console()
    try:
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        console.print(f"[red]Request failed:[/red] {type(exc).__name__}: {exc}")
        return 2

    _render_report(report, console)
    if report.grade in {"A", "B"}:
        return 0
    if report.grade in {"C", "D"}:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
