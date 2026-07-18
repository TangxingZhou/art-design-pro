#!/usr/bin/env bash
# set -ex

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd $SCRIPT_DIR/..
mkdir -p logs/
export ENV="dev"
# source .venv/bin/activate
uv run __main__.py
