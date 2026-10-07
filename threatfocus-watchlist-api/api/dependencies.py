
from fastapi import Depends
from core.security import TenantContext, get_tenant_context
from db.repository import WatchlistRepository


def get_repository() -> WatchlistRepository:
    return WatchlistRepository()