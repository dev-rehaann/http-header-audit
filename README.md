# HTTP Header Audit

A small, beginner-friendly HTTP security-header grader.

Milestone 3 adds the complete command-line interface with colored output,
input validation, clean network errors, and meaningful exit codes.

```bash
uv sync --extra dev
uv run headers https://example.com
uv run headers https://github.com --timeout 5
uv run pytest
```
