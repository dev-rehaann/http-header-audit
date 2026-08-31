# Architecture

The scanner is small enough to fit in one Python module, but it still has a
clear boundary between decisions and side effects.

## 1. The pipeline

```text
command line
    |
    v
parse and validate URL/timeout
    |
    v
scan() -- one GET, redirects followed
    |
    v
evaluate_header() x 6
    |
    v
ScanReport.score and .grade
    |
    v
Rich table, recommendations, exit code
```

Each stage passes ordinary Python values to the next. The security rules never
need to know how Rich draws a table, and the renderer never needs to know how
`httpx` opens a connection.

## 2. The data shapes

The project uses three frozen, slotted dataclasses.

### `HeaderRule`

A rule describes what to check:

- canonical header name
- severity
- short explanation
- recommendation
- optional regular expression required in the value

Rules are configuration data. The scanner does not contain six separate
header-specific functions.

### `HeaderFinding`

A finding records one evaluated rule:

- the original `HeaderRule`
- `ok`, `weak`, or `missing`
- the actual value, or `None`
- a display note

Keeping the rule inside the finding means rendering and scoring do not need a
second lookup table.

### `ScanReport`

A report stores:

- the URL requested by the user
- the final URL after redirects
- the final HTTP status code
- a tuple of findings

`score` and `grade` are computed properties. They cannot become stale because
they are derived from the findings whenever read.

`frozen=True` prevents accidental field reassignment. `slots=True` removes the
per-instance attribute dictionary because these records have a fixed shape.

## 3. The single source of truth

`RULES` is one tuple containing all six `HeaderRule` values. Evaluation walks
that tuple, scoring reads each finding's rule, and rendering reads the same
finding. Adding a simple rule therefore changes data rather than control flow.

`SEVERITY_POINTS` is the matching weight table:

```python
{"high": 30, "medium": 15, "low": 5}
```

The current rule mix totals 100, but `ScanReport.score` calculates the total
from `RULES` rather than relying on a separate hard-coded constant.

## 4. Functional core and I/O shell

The pure core contains:

- `evaluate_header()`
- `ScanReport.score`
- `ScanReport.grade`
- rules and point mappings

These parts take values and return values. They do not use the network, read
arguments, or print.

The I/O shell contains:

- `scan()`, which calls `httpx.get()`
- `_build_argument_parser()`, which reads user input through `main()`
- `_render_report()`, which writes terminal output
- `main()`, which coordinates the application

This split is why most tests can use tiny dictionaries and dataclasses. Only
the network boundary needs HTTP mocking.

## 5. End-to-end data flow

For this command:

```bash
uv run headers https://example.com --timeout 5
```

the flow is:

1. The console entry point calls `main()`.
2. `argparse` requires an HTTP(S) URL and a positive finite timeout.
3. `scan()` makes one GET with the scanner User-Agent.
4. `httpx` follows redirects and returns the final response.
5. Response headers are converted to `dict[str, str]`.
6. `evaluate_header()` runs once per rule.
7. A `ScanReport` computes its score and grade.
8. Rich renders the table and recommendations.
9. `main()` returns an exit code based on the grade.

The body may be downloaded by `httpx`, but this project does not inspect it.

## 6. Error ownership

`scan()` does not catch request errors. A library-style function cannot know
whether its caller wants to retry, log, display, or abort.

`main()` does know the context: an interactive command. It catches
`httpx.RequestError`, prints one readable line, and returns exit code 2 instead
of displaying a traceback.

Invalid URL and timeout input is rejected earlier by `argparse`, before any
network request begins.

## 7. Testing strategy

The test module has three layers:

1. Pure evaluation and score tests build values directly.
2. `respx` intercepts `httpx` for success, redirect, and failure tests.
3. CLI tests replace `scan()` with a local function and verify validation,
   rendering paths, and exit-code mapping.

No test requires internet access. That keeps the suite fast and deterministic.

## 8. Why one module

Splitting this project into packages, repositories, services, interfaces, or a
plugin system would add navigation without isolating meaningful complexity.
One source file is the appropriate size until a new feature creates a clear
independent responsibility.

Deliberate omissions include async scanning, caching, configuration files,
history, JSON output, and deep CSP parsing. The challenges guide explains when
those features become justified.
