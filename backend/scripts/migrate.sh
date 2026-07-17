#!/usr/bin/env bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd $SCRIPT_DIR/..
source .venv/bin/activate
mkdir -p migrations/versions
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
deactivate
