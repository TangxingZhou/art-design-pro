import logging
from base64 import b64encode

from config import settings
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http._log_exporter import (
    OTLPLogExporter as HttpOTLPLogExporter,
)
from opentelemetry.sdk._logs import (
    LoggerProvider,
    LoggingHandler,
)
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource


def setup_logging():
    headers = []
    if settings.OTEL.LOGS_BASIC_AUTH_USERNAME and settings.OTEL.LOGS_BASIC_AUTH_PASSWORD:
        auth_string = f'{settings.OTEL.LOGS_BASIC_AUTH_USERNAME}:{settings.OTEL.LOGS_BASIC_AUTH_PASSWORD}'
        auth_header = b64encode(auth_string.encode()).decode()
        headers = [('authorization', f'Basic {auth_header}')]
    resource = Resource.create(attributes={SERVICE_NAME: settings.OTEL.SERVICE_NAME})

    if settings.OTEL.LOGS_SPAN_EXPORTER == 'http':
        exporter = HttpOTLPLogExporter(
            endpoint=settings.OTEL.LOGS_EXPORTER_ENDPOINT,
            headers=headers,
        )
    else:
        exporter = OTLPLogExporter(
            endpoint=settings.OTEL.LOGS_EXPORTER_ENDPOINT,
            insecure=settings.OTEL.LOGS_EXPORTER_INSECURE,
            headers=headers,
        )
    logger_provider = LoggerProvider(resource=resource)
    set_logger_provider(logger_provider)

    logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))

    otel_handler = LoggingHandler(logger_provider=logger_provider)

    return otel_handler


otel_handler = setup_logging()
