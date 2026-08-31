# HTTP Header Audit

A small command-line tool that makes one HTTP request, checks six response
security headers, and grades the result from A to F.

It is intentionally a foundations project: one Python module, one test module,
one network boundary, and no framework.

## What it checks

| Header | Severity | What the scanner requires |
| --- | --- | --- |
| `Strict-Transport-Security` | high | A positive `max-age` |
| `Content-Security-Policy` | high | Header is present |
| `X-Content-Type-Options` | medium | Value is exactly `nosniff` (ignoring case/space) |
| `X-Frame-Options` | medium | Header is present |
| `Referrer-Policy` | low | Header is present |
| `Permissions-Policy` | low | Header is present |

`ok` earns full points, `weak` earns half points, and `missing` earns none.

## Requirements

- Python 3.13 or newer
- Internet access for live scans
- macOS/Linux: `install.sh` can install `uv` and `just`
- Windows: install `uv`, then run `uv tool install rust-just`

## Quick start

macOS or Linux:

```bash
./install.sh
just run -- https://example.com
```

Any platform with `uv` already installed:

```bash
uv sync --extra dev
uv run headers https://example.com
uv run headers https://github.com --timeout 5
```

The URL must include `http://` or `https://`. The timeout must be a positive,
finite number.

## Commands

```bash
just run -- https://example.com  # scan one URL
just test                        # run pytest
just lint                        # run Ruff and strict mypy
just format                      # format Python files
just fix                         # apply safe Ruff fixes
```

On Windows, the `justfile` uses PowerShell automatically. On macOS and Linux,
it uses the normal system shell.

## Scores and exit codes

| Score | Grade |
| ---: | :---: |
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

| Exit code | Meaning |
| ---: | --- |
| `0` | Grade A or B |
| `1` | Grade C or D |
| `2` | Grade F or the request failed |

That makes the scanner useful in scripts and CI without parsing colored text.

## Project layout

```text
http-header-audit/
|-- http_headers_scanner.py
|-- test_http_headers_scanner.py
|-- pyproject.toml
|-- uv.lock
|-- justfile
|-- install.sh
|-- README.md
`-- learn/
    |-- 00-OVERVIEW.md
    |-- 01-CONCEPTS.md
    |-- 02-ARCHITECTURE.md
    |-- 03-IMPLEMENTATION.md
    `-- 04-CHALLENGES.md
```

Start with [the overview](learn/00-OVERVIEW.md), then read
[the security concepts](learn/01-CONCEPTS.md) before the code walkthrough.

## Scope

This is a defensive configuration checker, not a vulnerability scanner. It
does not crawl links, exploit targets, inspect TLS configuration, analyze CSP
directives deeply, or prove that a website is secure. A missing header is a
useful signal to investigate, not a complete security verdict.
