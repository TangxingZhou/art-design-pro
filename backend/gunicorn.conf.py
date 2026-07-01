import multiprocessing
import yaml
from jinja2 import Environment, FileSystemLoader


bind = "127.0.0.1:8000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'uvicorn.workers.UvicornH11Worker'
threads = 1

accesslog = None
logger_class = 'logging.Logger'

logging_config = yaml.safe_load(Environment(loader=FileSystemLoader(Path(__file__).resolve().parent)).get_template('logging.yaml').render(**os.environ))


# 进程pid文件
pidfile = "./gunicorn.pid"

http_protocols = 'h1'
reload = False
daemon = True
