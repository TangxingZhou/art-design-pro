from base64 import b64encode

from fastapi import FastAPI
from config import settings
from utils.telemetry.instrumentors import Instrumentor
from utils.telemetry.metrics import setup_metrics
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HttpOTLPSpanExporter,
)
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from sqlalchemy import Engine


def setup(app: FastAPI, db_engine: Engine):
    # set up trace
    resource = Resource.create(attributes={SERVICE_NAME: settings.OTEL.SERVICE_NAME})
    if settings.OTEL.ENABLE_TRACES:
        trace.set_tracer_provider(TracerProvider(resource=resource))

        # Add basic auth header only if both username and password are not empty
        headers = []
        if settings.OTEL.BASIC_AUTH_USERNAME and settings.OTEL.BASIC_AUTH_PASSWORD:
            auth_string = f'{settings.OTEL.BASIC_AUTH_USERNAME}:{settings.OTEL.BASIC_AUTH_PASSWORD}'
            auth_header = b64encode(auth_string.encode()).decode()
            headers = [('authorization', f'Basic {auth_header}')]

        # otlp export
        if settings.OTEL.SPAN_EXPORTER == 'http':
            exporter = HttpOTLPSpanExporter(
                endpoint=settings.OTEL.EXPORTER_ENDPOINT,
                headers=headers,
            )
        else:
            exporter = OTLPSpanExporter(
                endpoint=settings.OTEL.EXPORTER_ENDPOINT,
                insecure=settings.OTEL.EXPORTER_INSECURE,
                headers=headers,
            )
        trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(exporter))
        Instrumentor(app=app, db_engine=db_engine).instrument()

    # set up metrics only if enabled
    if settings.OTEL.ENABLE_METRICS:
        setup_metrics(app, resource, db_engine)
