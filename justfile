set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

install:
    uv sync --extra dev

run _ *args:
    uv run headers {{args}}

test:
    uv run pytest

lint:
    uv run ruff check .
    uv run mypy

format:
    uv run ruff format .

fix:
    uv run ruff check --fix .
