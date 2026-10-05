
from layers.app.python.fastapi import Depends
from app.core.security import TenantContext, get_tenant_context
from app.db.repository import WatchlistRepository


def get_repository() -> WatchlistRepository:
    return WatchlistRepository()