# Extension challenges

Start each challenge with a failing test, make the smallest change that passes,
then run `just format`, `just lint`, and `just test`.

## 1. Add one more header

Add a `HeaderRule` for one of these:

- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: same-origin`

Use an anchored expression if the exact value matters. Because total score is
calculated from `RULES`, no separate total constant needs updating. Exact score
expectations in tests may change.

Done when a mocked response can produce `ok`, `weak`, and `missing` for the new
rule.

## 2. Add JSON output

Add `--json` and print a standard-library `json` object instead of Rich output.
Include URL, final URL, status, score, grade, and flattened findings.

Keep evaluation unchanged. JSON is a second renderer, not a second scanner.

Done when output can be parsed by `json.loads()` in a test and contains no ANSI
color codes.

## 3. Show raw response headers

Add `--verbose` to display all final response headers before the report. The
current `ScanReport` does not store them, so add one field rather than making a
second request.

Be careful when printing values supplied by a server: use Rich `Text`, not
markup-enabled strings.

## 4. Make the CI threshold configurable

Add `--min-grade C` so teams can decide which grade causes a nonzero exit.
Use argparse `choices` for validation and a small grade ordering.

Do not change how grades are calculated. This challenge changes only the exit
policy.

## 5. Scan several URLs

Change the URL argument to `nargs="+"`, scan each URL, and return the worst exit
code. Decide whether one failed request should stop the run or appear beside
successful reports.

Start sequentially. Add async concurrency only after measuring a real need.

## 6. Analyze CSP values

Parse semicolon-separated directives and mark CSP weak when `script-src`
contains `'unsafe-inline'` or `*`, or when both `script-src` and `default-src`
are absent.

CSP has a substantial grammar. State exactly which subset you support and add
tests for quoted keywords, capitalization, repeated whitespace, and fallback
behavior. Do not claim full CSP validation from a partial parser.

## 7. Recognize modern frame protection

Treat CSP `frame-ancestors` as an alternative to `X-Frame-Options`. This is the
first challenge where one rule depends on another header, so decide whether
`evaluate_header()` should receive the whole response or whether a separate
post-evaluation check is clearer.

Test conflicts, such as a safe `frame-ancestors` policy with a missing legacy
header.

## 8. Import a HAR file

Add an offline mode that reads one selected response from a browser-exported
HTTP Archive file. Use the standard `json` module and feed the extracted header
dictionary into the existing evaluator.

Validate file size and structure at the boundary. Do not require network access
for HAR scans.

## 9. Cache recent results

Cache by URL for a short period using JSON in the platform cache directory.
Store the scan time and enough response data to rebuild a report.

Add this only if repeated live requests are a demonstrated problem. Include a
`--no-cache` escape hatch and write files atomically to avoid corrupting the
cache on interruption.

## 10. Track changes over time

For several URLs and repeated scans, SQLite from the standard library is enough.
Store URL, time, status, score, and grade. Report when a header changes from
`ok` to `weak` or `missing`.

Do not treat a single network timeout as a security regression. Separate scan
failures from completed grades.

## 11. Expose an HTTP API

Only attempt this after the scanner itself is stable. A service that accepts
arbitrary URLs creates a server-side request forgery risk.

Before deployment, validate resolved IP addresses, block loopback/private/link-
local destinations, revalidate every redirect, cap response size and duration,
rate-limit clients, and define who is authorized to scan which targets. URL
syntax validation alone is not SSRF protection.

## 12. Compare user agents

The existing `scan()` already accepts `user_agent`. Scan with the default,
browser-like, and bot-like values, then compare findings side by side.

Keep the User-Agent strings as data and reuse `scan()`. A new networking layer
would duplicate the existing boundary.

## When an extension belongs in another file

Keep a feature in the current module while it remains a few cohesive functions.
Split only when it gains an independent reason to change, such as a real CSP
parser, storage backend, or API service. File count is not an architecture goal.
