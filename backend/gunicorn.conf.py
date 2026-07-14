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
daemon = True

logconfig_dict = yaml.safe_load(Environment(loader=FileSystemLoader(Path(__file__).resolve().parent)).get_template('logging.yaml').render(**os.environ))

proc_name = "gunicorn"
pidfile = "gunicorn.pid"

raw_env = []

forwarded_allow_ips = "127.0.0.1,::1"
http_protocols = "h1"
keyfile = None
certfile = None
ca_certs = None

preload_app = False

app_config = {}
def on_starting(server):
    """Master启动时一次性加载全局配置"""
    global app_config
    cfg = parse_settings()
    # 将配置挂载到server对象，fork子进程时会拷贝到每个worker
    server.app_config = cfg

def on_reload(server):
    """发送SIGHUP平滑重载时，Master重新加载最新配置"""
    global app_config
    new_cfg = get_settings()
    server.app_config = new_cfg
    server.log.info("全局配置已重载，新worker将使用最新配置")

def post_fork(server, worker):
    """每个worker启动后，从server读取继承来的全局配置"""
    # 直接读取master fork时复制过来的配置
    worker_config = server.app_config
    # 在worker内部初始化DB/Redis等资源（必须在这里！）
    init_db_pool(worker_config["db"])
    worker.log.info(f"Worker {worker.pid} 加载配置完成")

def worker_int(worker):
    global db_engine
    if db_engine:
        db_engine.dispose()
        worker.log.info(f"Worker {worker.pid} 连接池已销毁")

# 业务：用配置初始化数据库
def init_db_pool(db_conf):
    # from sqlalchemy import create_engine
    # global engine
    # engine = create_engine(db_conf["dsn"])
    pass
