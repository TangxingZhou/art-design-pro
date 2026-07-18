#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Container entry point
# Handles secret key generation,
# Launches the gunicorn server.
# ---------------------------------------------------------------------------
export ENV="production"
# Default optional env vars that we test below with bash's `,,` lowercase
# expansion. The two can't be combined inline (`${VAR:-default,,}` makes
# the default literal `,,`), so we normalise once up front and the simple
# `${VAR,,}` form stays safe under `set -u` everywhere else.

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR/.." || exit 1

# ── Secret key setup ─────────────────────────────────────────────────────────

#KEY_FILE="${SECRET_KEY_FILE:-.secret_key}"
#SECRET_KEY_LENGTH="${SECRET_KEY_LENGTH:-24}"
#PORT="${PORT:-8000}"
#HOST="${HOST:-0.0.0.0}"

#if [[ -z "${SECRET_KEY:-}" ]]; then
#  echo "No SECRET_KEY environment variable set, loading from file."
#
#  if [[ ! -f "$KEY_FILE" ]]; then
#    echo "Generating new SECRET_KEY..."
#    if ! [[ "$SECRET_KEY_LENGTH" =~ ^[1-9][0-9]*$ ]]; then
#      echo "SECRET_KEY_LENGTH must be a positive integer." >&2
#      exit 1
#    fi
#    head -c "$SECRET_KEY_LENGTH" /dev/random | base64 > "$KEY_FILE"
#  fi
#
#  echo "Loading SECRET_KEY from ${KEY_FILE}"
#  SECRET_KEY=$(cat "$KEY_FILE")
#fi

#if [[ -n "${SPACE_ID:-}" ]]; then
#  if [[ -n "${ADMIN_USER_EMAIL:-}" && -n "${ADMIN_USER_PASSWORD:-}" ]]; then
#    echo "Creating admin user for Space..."
#    SECRET_KEY="${SECRET_KEY:-}" \
#      # uvicorn open_webui.main:app --host "$HOST" --port "$PORT" --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}" &
#      gunicorn -c gunicorn.conf.py &
#    pid=$!
#
#    echo "Waiting for server to become healthy..."
#    until curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; do
#      sleep 1
#    done
#
#    echo "Registering admin user..."
#    curl -sS -X POST "http://localhost:${PORT}/api/v1/auths/signup" \
#      -H "Accept: application/json" \
#      -H "Content-Type: application/json" \
#      -d "{\"email\": \"${ADMIN_USER_EMAIL}\", \"password\": \"${ADMIN_USER_PASSWORD}\", \"name\": \"Admin\"}"
#
#    echo "Restarting server..."
#    kill "$pid"
#    wait "$pid" 2>/dev/null || true
#  fi
#
#  export WEBUI_URL="${SPACE_HOST}"
#fi

mkdir -p logs/
touch .env
#source .venv/bin/activate
#exec env SECRET_KEY="${SECRET_KEY:-}" \
#  "gunicorn -c gunicorn.conf.py"
exec .venv/bin/gunicorn -c gunicorn.conf.py
