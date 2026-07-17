#!/usr/bin/env bash
set -ex

export ENV="dev"
source .venv/bin/activate
uv run python __main__.py
