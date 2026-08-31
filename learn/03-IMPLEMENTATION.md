# Implementation walkthrough

Open `http_headers_scanner.py` beside this guide. The sections below follow the
source from top to bottom.

## 1. Imports and type aliases

The standard library handles argument parsing, numeric validation, regular
expressions, process exit, dataclasses, type aliases, and URL parsing.

Only two runtime dependencies are needed:

- `httpx` performs the HTTP request.
- Rich renders the terminal report.

The aliases restrict two string domains:

```python
Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]
```

These values remain normal strings at runtime, while mypy can catch misspelled
values during development.

## 2. `HeaderRule` and `RULES`

`HeaderRule` is an immutable description of one check. Most rules only require
presence. HSTS and `X-Content-Type-Options` also define `must_match` patterns.

The HSTS expression requires `max-age` to start with a nonzero digit:

```python
r"max-age\s*=\s*[1-9]\d*"
```

That rejects `max-age=0`. It is deliberately not a full HSTS parser.

The `nosniff` expression anchors both ends:

```python
r"^\s*nosniff\s*$"
```

That accepts capitalization and surrounding whitespace because evaluation uses
`re.IGNORECASE`, but rejects unrelated text containing the word.

## 3. Findings and reports

`HeaderFinding.actual_value` is `str | None`: a present header has a string,
while a missing header has no value.

`ScanReport.findings` is a tuple. The dataclass is frozen, and an immutable
collection keeps the report consistent with that intent.

### Score calculation

The score property first sums the available points from `RULES`. It then walks
the findings:

- multiplier `1` for `ok`
- multiplier `0.5` for `weak`
- no contribution for `missing`

The final expression adds `0.5` before converting to `int`, giving familiar
round-half-up behavior for nonnegative scores instead of Python's round-to-even
behavior.

### Grade calculation

The grade property checks descending cutoffs and returns at the first match.
Anything below 60 becomes F.

## 4. `evaluate_header()`

This is the central pure function.

It uses `casefold()` on both the response name and target name because HTTP
field names are case insensitive. `next(..., None)` returns the first matching
value or `None`.

Then three outcomes are possible:

1. No value: return `missing`.
2. Required pattern does not match: return `weak`.
3. Otherwise: return `ok`.

Early returns keep the branches flat. Because the function accepts a plain
dictionary, tests do not need an `httpx.Response` to exercise security logic.

## 5. `scan()`

`scan()` is the network boundary:

```python
response = httpx.get(
    url,
    timeout=timeout,
    follow_redirects=True,
    headers={"User-Agent": user_agent},
)
```

The timeout and User-Agent are keyword-only inputs, so call sites explain what
their values mean. Redirects are followed because the final page is what a
browser normally displays.

The response headers become a plain dictionary, every rule is evaluated, and
the function returns a `ScanReport`. Request errors intentionally propagate to
the caller.

The scanner does not call `raise_for_status()`. A 404 or 500 response still has
headers worth examining, and the report displays its status code.

## 6. `_render_report()`

The renderer builds four columns: header, status, severity, and note. Statuses
use color, but the literal status word remains visible for accessibility.

Dynamic values are wrapped in Rich `Text` objects. This prevents a URL or note
from being interpreted as Rich markup. Long notes use folding rather than an
ambiguous Unicode ellipsis on narrow legacy terminals.

If the final URL is still plain HTTP, the renderer warns that browsers ignore
HSTS delivered over HTTP. The scoring rule remains simple, so the warning makes
that protocol caveat explicit to the user.

Finally, a panel shows grade and score, followed by recommendations for every
finding that is not `ok`.

## 7. Input validation

`_http_url()` uses `urllib.parse.urlsplit()` and accepts only HTTP or HTTPS URLs
with a host.

`_positive_timeout()` converts text to `float`, then rejects zero, negatives,
infinity, and NaN. It raises `argparse.ArgumentTypeError`, allowing argparse to
show normal usage text instead of a traceback.

`_build_argument_parser()` declares one required URL and one optional timeout.
Keeping parser construction separate makes validation directly testable.

## 8. `main()` and exit codes

`main()` is coordination code:

1. Parse arguments.
2. Create a Rich console.
3. Call `scan()`.
4. Translate request failures into a readable error and code 2.
5. Render a successful response.
6. Return 0 for A/B, 1 for C/D, or 2 for F.

The final `if __name__ == "__main__"` block passes that return value to
`sys.exit()`. The console-script declaration in `pyproject.toml` also exposes
the same `main()` function as the `headers` command.

## 9. Tests

`test_http_headers_scanner.py` covers:

- case-insensitive names
- valid, weak, and missing header values
- full and half-point scoring
- a fully configured mocked response
- redirect tracking
- request-error propagation
- URL and timeout validation
- A/B, C/D, and F exit codes
- friendly request errors from `main()`

`respx` intercepts `httpx` calls, so the 11 test cases run without network
access.

## 10. Project tooling

`pyproject.toml` is the single configuration file for packaging and tools.

- `uv sync --extra dev` creates the environment from `uv.lock`.
- `pytest` runs behavior checks.
- Ruff performs linting and formatting.
- mypy checks both Python files in strict mode.
- `justfile` gives short, repeatable commands on Unix and Windows.
- `install.sh` bootstraps `uv`, `just`, and dependencies on macOS/Linux.

Run everything before changing behavior:

```bash
just format
just lint
just test
```

## 11. Debugging

For a live comparison, inspect response headers with your browser developer
tools or:

```bash
curl -I https://example.com
```

Remember that `curl -I` sends HEAD while the scanner sends GET, so a server may
legitimately return different headers. For deterministic debugging, add a
small `respx` test that reproduces the exact response instead of depending on a
live site.
