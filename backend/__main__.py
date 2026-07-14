import uvicorn
import os
import yaml
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from config import parse_settings


def main():
    # os.environ.setdefault("ENV", "dev")
    _settings = parse_settings()
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        workers=1,
        log_config=yaml.safe_load(Environment(loader=FileSystemLoader(Path(__file__).resolve().parent)).get_template('logging.yaml').
        render(**os.environ)),
        forwarded_allow_ips="*",
        http="h11",
        ssl_keyfile=None,
        ssl_certfile=None,
        ssl_ca_certs=None,
    )

if __name__ == "__main__":
    main()
