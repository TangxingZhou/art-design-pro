import os
import yaml
from typing import Any
from pathlib import Path
import logging.config
import pandas as pd
from pythonjsonlogger.json import JsonFormatter
from jinja2 import Environment, FileSystemLoader


class AuditFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.__dict__.get('auditable', False)


class CustomJsonFormatter(JsonFormatter):

    def process_log_record(self, log_data):
        return log_data

    def add_fields(
        self,
        log_data: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        super().add_fields(log_data, record, message_dict)
        # log_data["datetime"] = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")
        log_data['ts'] = record.created
        if os.getenv('ENABLE_OTEL', 'false').lower() == 'true':
            from opentelemetry import trace

            extras = {}
            context = trace.get_current_span().get_span_context()
            if context.is_valid:
                extras['trace_id'] = trace.format_trace_id(context.trace_id)
                extras['span_id'] = trace.format_span_id(context.span_id)
            log_data.update(extras)


def get_logger(name=None) -> logging.Logger:
    logging_config_template = Environment(loader=FileSystemLoader(Path(__file__).resolve().parent)).get_template('logging.yaml')
    logging_config = yaml.safe_load(logging_config_template.render(**os.environ))
    logging.config.dictConfig(logging_config)
    return logging.getLogger(name or __name__)


logger = get_logger()


def batch_jsonl_to_parquet(chunksize: int = 100_000, delete_source: bool = False):
    logs_path = Path(__file__).resolve().parent / "logs"

    for jsonl_file in logs_path.rglob("*"):
        if not jsonl_file.is_file() or ".jsonl." not in jsonl_file.name:
            continue

        output_stem = jsonl_file.name.rsplit(".jsonl", 1)[0] + jsonl_file.name[len(jsonl_file.name.rsplit(".jsonl", 1)[0]):]
        chunk_iter = pd.read_json(jsonl_file, lines=True, chunksize=chunksize)

        with pd.option_context('mode.string_storage', 'pyarrow'):
            for shard_index, chunk in enumerate(chunk_iter):
                shard_path = jsonl_file.with_name(f"{output_stem}.part{shard_index}.parquet")
                chunk.to_parquet(
                    shard_path,
                    engine="pyarrow",
                    compression="zstd",
                )
                print(f"已转换: {jsonl_file} → {shard_path}")

        if delete_source:
            jsonl_file.unlink()
            print(f"已删除源文件: {jsonl_file}")


if __name__ == '__main__':
    batch_jsonl_to_parquet(100_000, True)
