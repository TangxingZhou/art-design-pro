from fastapi import APIRouter

from .admin import admin_router
from .console import console_router
from .system import router as system_router
from .configs import router as configs_router
from .auths import router as auths_router
from .oauth import router as oauth_router
from .groups import router as groups_router
# from .roles import router as roles_router
from .users import router as users_router
from .files import router as files_router
from .tasks import router as tasks_router
from .events import router as events_router

api_router = APIRouter()
api_router.include_router(admin_router, prefix='/admin', tags=['admin'])
api_router.include_router(admin_router, prefix='/console', tags=['console'])
api_router.include_router(system_router, prefix='', tags=['system'])
api_router.include_router(configs_router, prefix='/configs', tags=['configs'])
api_router.include_router(auths_router, prefix='/auths', tags=['auths'])
api_router.include_router(oauth_router, prefix='/oauth', tags=['oauth'])
api_router.include_router(groups_router, prefix='/groups', tags=['groups'])
# api_router.include_router(roles_router, prefix='/roles', tags=['roles'])
api_router.include_router(users_router, prefix='/users', tags=['users'])
api_router.include_router(files_router, prefix='/files', tags=['files'])
api_router.include_router(tasks_router, prefix='/tasks', tags=['tasks'])
api_router.include_router(events_router, prefix='/events', tags=['events'])

__all__ = ["api_router"]

