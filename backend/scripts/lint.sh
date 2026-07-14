#!/usr/bin/env bash

set -ex

mypy app
ty check app
ruff check app
ruff format app --check
