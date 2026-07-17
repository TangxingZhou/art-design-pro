from pydantic import BaseModel


class EventWebhookForm(BaseModel):
    name: str | None = None
    url: str
    enabled: bool = True
    events: list[str] | None = None
    targets: list[dict[str, str]] | None = None


class EventWebhookUpdateForm(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None
    targets: list[dict[str, str]] | None = None
