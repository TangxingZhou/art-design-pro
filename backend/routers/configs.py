from __future__ import annotations

import copy
import logging
from typing import Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request
from mcp.shared.auth import OAuthMetadata
# from open_webui.config import BannerModel
# from open_webui.env import AIOHTTP_CLIENT_SESSION_SSL, AIOHTTP_CLIENT_TIMEOUT
from utils.events import EVENTS, publish_event
from models.config import Config
from models.oauth_sessions import OAuthSessions
from utils.auth import get_admin_user, get_verified_user
from pydantic import BaseModel

router = APIRouter()

log = logging.getLogger(__name__)

CONNECTIONS_CONFIG_KEYS = {
    'ENABLE_DIRECT_CONNECTIONS': 'direct.enable',
    'ENABLE_BASE_MODELS_CACHE': 'models.base_models_cache',
}


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


############################
# Connections Config
############################


class ConnectionsConfigForm(BaseModel):
    ENABLE_DIRECT_CONNECTIONS: bool
    ENABLE_BASE_MODELS_CACHE: bool


@router.get('/connections', response_model=ConnectionsConfigForm)
async def get_connections_config(request: Request, user=Depends(get_admin_user)):
    return await get_config_values(CONNECTIONS_CONFIG_KEYS)


@router.post('/connections', response_model=ConnectionsConfigForm)
async def set_connections_config(
    request: Request,
    form_data: ConnectionsConfigForm,
    user=Depends(get_admin_user),
):
    await Config.upsert(config_updates(form_data.model_dump(), CONNECTIONS_CONFIG_KEYS))
    values = await get_config_values(CONNECTIONS_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_CONNECTIONS_UPDATED,
        actor=user,
        subject_id='connections',
        subject_type='config',
        data=values,
    )
    return values


# ############################
# # SetBanners
# ############################
#
#
# class SetBannersForm(BaseModel):
#     banners: list[BannerModel]
#
#
# @router.post('/banners', response_model=list[BannerModel])
# async def set_banners(
#     request: Request,
#     form_data: SetBannersForm,
#     user=Depends(get_admin_user),
# ):
#     data = form_data.model_dump()
#     await Config.upsert({'ui.banners': data['banners']})
#     banners = await Config.get('ui.banners')
#     await publish_event(
#         request,
#         EVENTS.CONFIG_BANNERS_UPDATED,
#         actor=user,
#         subject_id='ui.banners',
#         subject_type='config',
#         data={'count': len(banners or [])},
#     )
#     return banners
#
#
# @router.get('/banners', response_model=list[BannerModel])
# async def get_banners(
#     request: Request,
#     user=Depends(get_verified_user),
# ):
#     return await Config.get('ui.banners')
