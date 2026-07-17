import os
import yaml
import multiprocessing
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from config import parse_settings, get_settings


wsgi_app = "main:app"
bind = "0.0.0.0:8000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornH11Worker"
threads = 1
reload = False
daemon = False

logconfig_dict = yaml.safe_load(Environment(loader=FileSystemLoader(Path(__file__).resolve().parent)).get_template('logging.yaml').render(**os.environ))

proc_name = "gunicorn"
pidfile = "/run/gunicorn.pid"

raw_env = []

# proxy_protocol = 'v2'
# proxy_allow_ips = '*'
forwarded_allow_ips = "127.0.0.1,::1"
http_protocols = "h1"
keyfile = None
certfile = None
ca_certs = None

preload_app = False


def on_starting(server):
    parse_settings()


def on_reload(server):
    pass


def post_fork(server, worker):
    from utils import db
    server.log.info("Disposing inherited SQLAlchemy pools after fork")
    try:
        db.engine.dispose(close=False)
    except TypeError:
        db.engine.dispose()
    try:
        db.async_engine.sync_engine.dispose(close=False)
    except TypeError:
        db.async_engine.sync_engine.dispose()


def worker_exit(server, worker):
    from utils import db

    server.log.info("Disposing SQLAlchemy pools on worker exit")
    db.engine.dispose()
    db.async_engine.sync_engine.dispose()
