from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from utils.auth import (
    get_admin_user,
)
from utils.tasks import list_tasks, stop_task

router = APIRouter()

log = logging.getLogger(__name__)


@router.post('/stop/{task_id}')
async def stop_task_endpoint(request: Request, task_id: str, user=Depends(get_admin_user)):
    try:
        result = await stop_task(request.app.state.redis, task_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get('/')
async def list_tasks_endpoint(request: Request, user=Depends(get_admin_user)):
    return {'tasks': await list_tasks(request.app.state.redis)}
