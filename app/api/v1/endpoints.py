import os
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status

from api.dependencies import get_repository
from core.security import TenantContext, get_tenant_context, get_tenant_context_from_param
from db.repository import WatchlistRepository
from platform_auth_client.fastapi.dependencies import require_remote_access
from platform_auth_client import RemoteAuthorizationClient
from platform_auth_client.client import SigV4HttpTransport
from platform_auth_client.config import RemoteClientConfig
from domain.models import (
    IndicatorCreate,
    IndicatorResponse,
    IndicatorType,
    PaginatedIndicatorsResponse,
    PaginatedWatchlistsResponse,
    SnapshotResponse,
    WatchlistCreate,
    WatchlistResponse,
    WatchlistUpdate,
)
from domain.normalizers import IndicatorNormalizer

router = APIRouter(prefix="/v1")

platform_auth = RemoteAuthorizationClient(
    SigV4HttpTransport(
        RemoteClientConfig.from_env(),
        region=os.environ["REGION_NAME"],
    )
)


# WATCHLIST MANAGEMENT
@router.post("/watchlists",
    response_model=WatchlistResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Watchlists"],
    summary="Create a watchlist",
    description="Creates a new watchlist for the authenticated tenant.",
    response_description="The newly created watchlist.",
)
async def create_watchlist(
    payload: WatchlistCreate,
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                        action="credential-leak:statistics:read",
                                        resource_type="statistics"
                                        #resource_id_path_parameter="statistics"
                                    ))
):
    return repo.create_watchlist(tenant_id=ctx.tenant_id, data=payload)


@router.get(
    "/watchlists",
    response_model=PaginatedWatchlistsResponse,
    tags=["Watchlists"],
    summary="List watchlists",
    description="Returns a cursor-paginated list of watchlists for the authenticated tenant.",
    response_description="A page of watchlists and an optional continuation cursor.",
)
async def list_watchlists(
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    items, next_cursor = repo.list_watchlists(
        tenant_id=ctx.tenant_id, limit=limit, cursor=cursor
    )
    return PaginatedWatchlistsResponse(items=items, nextCursor=next_cursor)


@router.get("/watchlists/{watchlist_id}",
    response_model=WatchlistResponse,
    tags=["Watchlists"],
    summary="Get a watchlist",
    description="Returns one watchlist belonging to the authenticated tenant.",
)
async def get_watchlist(
    watchlist_id: str,
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    return repo.get_watchlist(tenant_id=ctx.tenant_id, watchlist_id=watchlist_id)


@router.put("/watchlists/{watchlist_id}",
    response_model=WatchlistResponse,
    tags=["Watchlists"],
    summary="Update a watchlist",
    description="Updates the supplied fields on a watchlist belonging to the authenticated tenant.",
)
async def update_watchlist(
    watchlist_id: str,
    payload: WatchlistUpdate,
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    return repo.update_watchlist(
        tenant_id=ctx.tenant_id, watchlist_id=watchlist_id, data=payload
    )


@router.delete("/watchlists/{watchlist_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Watchlists"],
    summary="Delete a watchlist",
    description="Deletes a watchlist and its tenant-scoped configuration.",
    response_description="The watchlist was deleted successfully.",
)
async def delete_watchlist(
    watchlist_id: str,
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    repo.delete_watchlist(tenant_id=ctx.tenant_id, watchlist_id=watchlist_id)


# INDICATOR MANAGEMENT
@router.post(
    "/watchlists/{watchlist_id}/indicators",
    response_model=IndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Indicators"],
    summary="Create an indicator",
    description="Validates, normalizes, and adds an indicator to a watchlist.",
    response_description="The newly created indicator.",
)
async def create_indicator(
    watchlist_id: str,
    payload: IndicatorCreate,
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    normalized = IndicatorNormalizer.validate_and_normalize(
        indicator_type=payload.type,
        match_type=payload.matchType,
        raw_value=payload.value,
    )
    return repo.create_indicator(
        tenant_id=ctx.tenant_id,
        watchlist_id=watchlist_id,
        data=payload,
        normalized_value=normalized,
    )


@router.get(
    "/watchlists/{watchlist_id}/indicators",
    response_model=PaginatedIndicatorsResponse,
    tags=["Indicators"],
    summary="List indicators",
    description="Returns a cursor-paginated list of indicators in a watchlist.",
    response_description="A page of indicators and an optional continuation cursor.",
)
async def list_indicators(
    watchlist_id: str,
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    items, next_cursor = repo.list_indicators(
        tenant_id=ctx.tenant_id,
        watchlist_id=watchlist_id,
        limit=limit,
        cursor=cursor,
    )
    return PaginatedIndicatorsResponse(items=items, nextCursor=next_cursor)


@router.delete(
    "/watchlists/{watchlist_id}/indicators/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Indicators"],
    summary="Delete an indicator",
    description="Deletes an indicator from a watchlist.",
    response_description="The indicator was deleted successfully.",
)
async def delete_indicator(
    watchlist_id: str,
    indicator_id: str,
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    repo.delete_indicator(
        tenant_id=ctx.tenant_id, watchlist_id=watchlist_id, indicator_id=indicator_id
    )


# CONFIGURATION SNAPSHOT QUERY
@router.get(
    "/snapshots",
    response_model=SnapshotResponse,
    tags=["Snapshots"],
    summary="Get configuration snapshot",
    description=(
        "Returns the effective watchlist and indicator configuration for the "
        "authenticated tenant, optionally filtered by indicator type."
    ),
    response_description="The tenant's current watchlist configuration.",
)
async def get_snapshot(
    indicator_types: Optional[List[IndicatorType]] = Query(None),
    ctx: TenantContext = Depends(get_tenant_context_from_param),
    repo: WatchlistRepository = Depends(get_repository),
    auth = Depends(require_remote_access(client=platform_auth,
                                             action="credential-leak:statistics:read",
                                             resource_type="statistics"
                                             #resource_id_path_parameter="statistics"
                                            ))
):
    return repo.get_snapshot(tenant_id=ctx.tenant_id, indicator_types=indicator_types)