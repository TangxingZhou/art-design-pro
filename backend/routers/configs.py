from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Request
from utils.events import EVENTS, publish_event
from models.config import Config
from utils.auth import get_admin_user
from pydantic import BaseModel

router = APIRouter()

log = logging.getLogger(__name__)


async def get_config_values(key_map: dict[str, str]) -> dict:
    values = await Config.get_many(*key_map.values())
    return {field: values[storage_key] for field, storage_key in key_map.items() if storage_key in values}


def config_updates(data: dict, key_map: dict[str, str]) -> dict:
    return {key_map[field]: value for field, value in data.items() if field in key_map}


############################
# ImportConfig
# Thy configuration come, thy settings be done,
# in production as it is in development.
############################


class ImportConfigForm(BaseModel):
    config: dict


@router.post('/import', response_model=dict)
async def import_config(request: Request, form_data: ImportConfigForm, user=Depends(get_admin_user)):
    await Config.upsert(form_data.config)
    await publish_event(
        request,
        EVENTS.CONFIG_IMPORTED,
        actor=user,
        subject_id='import',
        data={'keys': list(form_data.config.keys())},
    )
    return await Config.get_all()


############################
# ExportConfig
############################


@router.get('/export', response_model=dict)
async def export_config(user=Depends(get_admin_user)):
    return await Config.get_all()


@router.get('/namespace/{namespace}', response_model=dict)
async def get_config_namespace(namespace: str, user=Depends(get_admin_user)):
    return await Config.get_namespace(namespace)
