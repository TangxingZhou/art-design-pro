import base64
import os
import random
import sys
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from constants import DATA_DIR
from config import parse_settings


app = typer.Typer()

KEY_FILE = DATA_DIR / '.secret_key'
DEFAULT_SECRET_KEY_LENGTH = 24


@app.command()
def main():
    pass


@app.command()
def serve(
    host: str = '0.0.0.0',
    port: int = 8000,
):
    os.environ['ENV'] = 'production'
    parse_settings()
    os.environ['FROM_INIT_PY'] = 'true'
    if os.getenv('SECRET_KEY') is None:
        typer.echo('Loading SECRET_KEY from file, not provided as an environment variable.')
        if not KEY_FILE.exists():
            key_length = int(os.getenv('SECRET_KEY_LENGTH', DEFAULT_SECRET_KEY_LENGTH))
            if key_length < 1:
                raise ValueError('SECRET_KEY_LENGTH must be a positive integer')
            typer.echo(f'Generating a new secret key and saving it to {KEY_FILE}')
            KEY_FILE.write_bytes(base64.b64encode(random.randbytes(key_length)))
        typer.echo(f'Loading SECRET_KEY from {KEY_FILE}')
        os.environ['SECRET_KEY'] = KEY_FILE.read_text()

    # On Windows, uvicorn's default loop factory hardcodes ProactorEventLoop,
    # which is incompatible with psycopg v3 async.  Setting loop='none' lets
    # asyncio.run() respect the WindowsSelectorEventLoopPolicy set in db.py.
    loop = 'none' if sys.platform == 'win32' else 'auto'

    uvicorn.run(
        'main:app',
        host=host,
        port=port,
        forwarded_allow_ips='*',
        workers=1,
        loop=loop,
    )


@app.command()
def dev(
    host: str = '0.0.0.0',
    port: int = 8000,
    reload: bool = True,
):
    os.environ['ENV'] = 'dev'
    parse_settings()
    uvicorn.run(
        'main:app',
        host=host,
        port=port,
        reload=reload,
        forwarded_allow_ips='*',
    )


if __name__ == '__main__':
    app()
