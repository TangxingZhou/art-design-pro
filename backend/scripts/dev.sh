#!/usr/bin/env bash
set -ex

export ENV="dev"
export CORS_ALLOW_ORIGIN="http://localhost:5173;http://localhost:8080"

source .venv/bin/activate
#python app/backend_pre_start.py
#alembic upgrade head
#python app/initial_data.py

uv run python __main__.py
