from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import Column, DateTime, Uuid
from sqlmodel import SQLModel, Field, Index, desc


class AccessLog(SQLModel, table=True):
    __tablename__ = 'access_log'
    __table_args__ = (
        Index("idx_access_log_request_dt", 'request_path', 'request_method', desc('date_time')),
        Index("idx_access_log_client_dt", 'client_addr', desc('date_time')),
        {'postgresql_partition_by': 'RANGE (date_time)'},
    )
    id: UUID = Field(
        default_factory=uuid4,
        sa_column=Column(Uuid(as_uuid=True), primary_key=True, default=uuid4),
    )
    client_addr: str
    remote_user: Optional[str] = None
    date_time: datetime = Field(
        sa_column=Column(
            DateTime(timezone=True),
            primary_key=True,
            nullable=False,
        )
    )
    request_line: str
    request_method: str
    request_path: str
    http_version: str
    query_string: Optional[str] = None
    status_code: int
    # response: Optional[str] = None
    referer: Optional[str] = None
    user_agent: Optional[str] = None
    duration_ms: Optional[int] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
