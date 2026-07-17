from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from utils.db import get_async_session
from config import settings

router = APIRouter()

log = logging.getLogger(__name__)


@router.get('/{provider}/login')
async def oauth_login(provider: str, request: Request):
    return await request.app.oauth_manager.handle_login(request, provider)


@router.get('/{provider}/login/callback')
@router.get('/{provider}/callback')  # Legacy endpoint
async def oauth_login_callback(
    provider: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_session),
):
    """Handle the OAuth provider callback.

    Resolution order:
    1. Match by subject ID bound to the provider.
    2. If ``OAUTH_MERGE_ACCOUNTS_BY_EMAIL`` is enabled, match by email
       (note: some providers do not verify email addresses).
    3. If no match and ``ENABLE_OAUTH_SIGNUP`` is enabled, create a new user
       (fails if the email is already registered).
    """
    return await request.app.state.oauth_manager.handle_callback(request, provider, response, db=db)


############################
# OIDC Back-Channel Logout
############################
@router.post('/oauth/backchannel-logout')
async def oauth_backchannel_logout(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
):
    if not settings.SYSTEM.OAUTH.ENABLE_BACKCHANNEL_LOGOUT:
        raise HTTPException(status_code=404)
    return await request.app.state.oauth_manager.handle_backchannel_logout(request, db=db)
