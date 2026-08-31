#!/usr/bin/env bash
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v just >/dev/null 2>&1; then
    uv tool install rust-just
    export PATH="$HOME/.local/bin:$PATH"
fi

uv sync --extra dev
printf 'Ready. Try: just run -- https://example.com\n'
