# Core concepts

This guide explains what the scanner measures and where its conclusions stop.

## 1. Requests, responses, and headers

An HTTP client sends a request. A server sends a response containing a status,
headers, and usually a body:

```text
client -- request --> server
client <-- response -- server

response = status + headers + blank line + body
```

A simplified response might look like:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff

<!doctype html>
<title>Example</title>
```

The body is the page content. Headers are metadata and instructions interpreted
by clients, intermediaries, and browsers. HTTP header names are case
insensitive, so `X-Frame-Options` and `x-frame-options` name the same field.

## 2. Security headers are browser policy

A security header does not remove a server bug. It tells a supporting browser
to apply an additional rule while handling a response. Missing or weak policy
can make an existing mistake easier to exploit, while good policy can reduce
impact.

This scanner checks six policies.

## 3. Strict-Transport-Security (HSTS)

Example:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

After receiving a valid HSTS header over HTTPS, a browser remembers to use
HTTPS for that host during the `max-age` period. This helps resist downgrade
and SSL-stripping attempts on later visits.

Important limits:

- Browsers ignore HSTS received over plain HTTP.
- HSTS alone does not protect a user's first-ever connection. Preloading or a
  previously stored policy is needed to cover that first contact.
- `max-age=0` removes the remembered policy, so it is not protective.

The scanner marks HSTS `ok` only when it finds a positive integer `max-age`.

## 4. Content-Security-Policy (CSP)

Example:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

CSP limits where a page may load scripts and other resources. A carefully
designed policy can reduce the impact of cross-site scripting by blocking
unexpected script execution.

This project checks presence only. A present CSP can still be weak because of
wildcards, unsafe directives, missing fallbacks, or a report-only deployment.
Deep CSP parsing belongs in a more advanced scanner.

## 5. X-Content-Type-Options

The useful value is:

```http
X-Content-Type-Options: nosniff
```

It tells browsers not to reinterpret certain resources as a different MIME
type. This reduces attacks that rely on a browser treating uploaded or
mislabelled content as executable script or style content.

Because the value matters, the scanner accepts only `nosniff`, ignoring case
and surrounding whitespace. Any other present value is `weak`.

## 6. X-Frame-Options

Typical values are:

```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

The header limits whether a page can be placed in a frame. That helps prevent
clickjacking, where a user is tricked into interacting with a framed page they
cannot clearly see.

Modern sites can express the same policy with CSP `frame-ancestors`. This
foundations scanner checks only that `X-Frame-Options` is present; it does not
validate the value or inspect `frame-ancestors`.

## 7. Referrer-Policy

Example:

```http
Referrer-Policy: strict-origin-when-cross-origin
```

The policy controls how much of the current URL a browser includes in the
`Referer` request header when navigating or loading resources. Restricting it
can reduce leakage of paths and query strings to other origins.

Modern browsers already apply a conservative default, but an explicit policy
makes site intent clear and stable. The scanner checks presence only.

## 8. Permissions-Policy

Example:

```http
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Permissions Policy controls access to selected browser capabilities for the
page and embedded content. Empty parentheses deny that feature to every
origin. This is useful defense in depth when a site does not need sensitive
features.

The scanner checks presence only because the correct allowlist is specific to
each application.

## 9. Scoring

The severity weights total exactly 100 points:

```text
2 high headers   x 30 = 60
2 medium headers x 15 = 30
2 low headers    x  5 = 10
total                  = 100
```

For each finding:

- `ok` earns all points.
- `weak` earns half points.
- `missing` earns zero points.

The implementation calculates a percentage and rounds halves upward. Grades
use these cutoffs:

```text
90+ A
80+ B
70+ C
60+ D
<60 F
```

Only HSTS and `X-Content-Type-Options` currently have value checks, so only
those rules can become `weak`.

## 10. What a grade does not prove

An A means the six implemented checks passed. It does not mean the site has no
XSS, SQL injection, insecure cookies, broken authentication, weak TLS, or
other vulnerabilities. The scanner also checks only one final response, not
every page or redirect response.

Use the grade as a quick configuration signal and starting point for review.

## Self-check

1. Where are response headers located relative to the body?
2. Why is `max-age=0` weak even though HSTS is present?
3. Which header helps prevent framing and clickjacking?
4. Why can a present CSP still be unsafe?
5. What score does one weak high-severity rule earn by itself?
6. Why does an A grade not prove the site is secure?
