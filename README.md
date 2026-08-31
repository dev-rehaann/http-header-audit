# HTTP Header Audit

A small, beginner-friendly HTTP security-header grader.

Milestone 4 adds repeatable install, run, test, lint, type-check, and format
commands.

```bash
uv sync --extra dev
uv run headers https://example.com
uv run headers https://github.com --timeout 5
uv run pytest
```

With `just` installed, the shorter equivalents are `just run -- URL`,
`just test`, `just lint`, and `just format`.
