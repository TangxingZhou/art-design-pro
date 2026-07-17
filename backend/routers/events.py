from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status

from config import settings
from utils.events import EVENTS, publish_event
from utils.auth import (
    get_admin_user,
)
from models.events import EventWebhookForm, EventWebhookUpdateForm
from utils.events import (
    get_event_catalog as get_event_catalog_items,
    get_event_webhooks,
    upsert_event_webhook,
    delete_event_webhook
)

router = APIRouter()

log = logging.getLogger(__name__)


@router.get('/')
async def get_event_catalog(user=Depends(get_admin_user)):
    return {
        'schema': settings.VERSION,
        'events': get_event_catalog_items(),
    }


@router.get('/webhooks')
async def get_event_webhooks_api(user=Depends(get_admin_user)):
    return await get_event_webhooks()


@router.post('/webhooks')
async def create_event_webhook(request: Request, form_data: EventWebhookForm, user=Depends(get_admin_user)):
    try:
        webhook = await upsert_event_webhook(
            {
                'name': form_data.name,
                'url': form_data.url,
                'enabled': form_data.enabled,
                'events': form_data.events,
                'targets': form_data.targets,
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await publish_event(
        request,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook['id'],
        subject_type='config',
        data={
            'action': 'created',
            'enabled': webhook.get('enabled'),
            'events': webhook.get('events'),
            'targets': webhook.get('targets'),
        },
    )
    return webhook


@router.put('/webhooks/{webhook_id}')
async def update_event_webhook(request: Request, webhook_id: str, form_data: EventWebhookUpdateForm, user=Depends(get_admin_user)):
    webhooks = await get_event_webhooks()
    existing = next((webhook for webhook in webhooks if webhook.get('id') == webhook_id), None)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Webhook not found')

    try:
        webhook = await upsert_event_webhook(
            {
                **existing,
                **form_data.model_dump(exclude_unset=True),
                'id': webhook_id,
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await publish_event(
        request,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook_id,
        subject_type='config',
        data={
            'action': 'updated',
            'enabled': webhook.get('enabled'),
            'events': webhook.get('events'),
            'targets': webhook.get('targets'),
        },
    )
    return webhook


@router.delete('/webhooks/{webhook_id}')
async def delete_event_webhook_api(request: Request, webhook_id: str, user=Depends(get_admin_user)):
    deleted = await delete_event_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Webhook not found')

    await publish_event(
        request,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook_id,
        subject_type='config',
        data={'action': 'deleted'},
    )
    return {'status': True}
