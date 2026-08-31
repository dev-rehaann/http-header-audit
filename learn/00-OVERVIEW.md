# Project overview

HTTP Header Audit visits one URL and grades the security instructions returned
with that response. The page body is not analyzed. The scanner only examines
six response headers.

This project sits between pure Python exercises and a larger application. It
has one real network operation, but keeps the evaluation and scoring logic
independent from the network so that most behavior is easy to test.

## What you will learn

### Security

- The difference between an HTTP response body and response headers
- What six common browser security headers are intended to control
- Why a present but ineffective value can be worse than a missing value
- How weighted findings become a percentage and letter grade
- Why a header report is evidence, not proof that a site is secure

### Python

- Making a synchronous request with `httpx`
- Modeling small immutable records with dataclasses
- Restricting strings with `Literal` types
- Separating pure decisions from network and terminal I/O
- Parsing command-line input with `argparse`
- Rendering terminal output with Rich
- Replacing live HTTP calls with `respx` in tests

### Tooling

- Reproducible dependencies with `uv.lock`
- Repeatable commands with `just`
- Tests with pytest, lint/format with Ruff, and types with mypy
- Meaningful process exit codes for scripts and CI

## Prerequisites

You need Python 3.13 or newer, a terminal, Git, and internet access for live
scans. You do not need prior HTTP or security-header knowledge.

Check Python with:

```bash
python --version
```

## Install and run

On macOS or Linux:

```bash
./install.sh
just run -- https://example.com
```

On any platform where `uv` is installed:

```bash
uv sync --extra dev
uv run headers https://example.com
```

Run the checks used by the project:

```bash
just test
just lint
```

## What the report means

Each row has one of three statuses:

- `ok`: the requirement implemented by this project passed.
- `weak`: the header exists, but its required value check failed.
- `missing`: the response did not contain the header.

The report also shows a score, grade, and a recommendation for each non-`ok`
finding. Colors reinforce the words, but meaning never depends on color alone.

## Read the project in this order

1. [Core concepts](01-CONCEPTS.md) explains HTTP and the six headers.
2. [Architecture](02-ARCHITECTURE.md) shows the data flow and I/O boundary.
3. [Implementation](03-IMPLEMENTATION.md) walks through the actual source.
4. [Challenges](04-CHALLENGES.md) suggests focused extensions.

## Common setup issues

### `python` is older than 3.13

Install a current Python release, then rerun `uv sync --extra dev`. The project
metadata deliberately rejects older interpreters.

### `./install.sh: permission denied`

```bash
chmod +x install.sh
./install.sh
```

### `just` is not found

Restart the terminal after installation, or add `$HOME/.local/bin` to `PATH`.
You can always use the equivalent `uv run ...` commands from the README.

### A live scan fails

Confirm the URL includes its scheme and try `https://example.com`. Corporate
proxies, VPNs, DNS failures, certificate errors, and target-side blocking can
all prevent a request even when the scanner itself is working.

### A site looks better or worse than expected

The scanner grades only the final response after redirects. Different paths,
subdomains, proxies, and user agents can receive different headers.
