from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from layers.app.python.pydantic import BaseModel, Field, ConfigDict


def current_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class IndicatorType(str, Enum):
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    KEYWORD = "KEYWORD"


class MatchType(str, Enum):
    EXACT = "EXACT"
    SUFFIX = "SUFFIX"
    PREFIX = "PREFIX"
    CONTAINS = "CONTAINS"


# Watchlist DTOs
class WatchlistCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    enabled: bool = True


class WatchlistUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    enabled: Optional[bool] = None


class WatchlistResponse(BaseModel):
    id: str
    tenantId: str
    name: str
    description: Optional[str]
    enabled: bool
    revision: int
    createdAt: str
    updatedAt: str


class PaginatedWatchlistsResponse(BaseModel):
    items: List[WatchlistResponse]
    nextCursor: Optional[str] = None


# Indicator DTOs
class IndicatorCreate(BaseModel):
    type: IndicatorType
    value: str = Field(..., min_length=1)
    description: Optional[str] = Field(None, max_length=512)
    matchType: MatchType
    enabled: bool = True


class IndicatorUpdate(BaseModel):
    description: Optional[str] = Field(None, max_length=512)
    enabled: bool


class IndicatorResponse(BaseModel):
    id: str
    watchlistId: str
    tenantId: str
    type: IndicatorType
    value: str
    normalizedValue: str
    matchType: MatchType
    enabled: bool
    createdAt: str
    updatedAt: str


class PaginatedIndicatorsResponse(BaseModel):
    items: List[IndicatorResponse]
    nextCursor: Optional[str] = None


# Snapshot Models
class SnapshotIndicator(BaseModel):
    id: str
    type: IndicatorType
    normalizedValue: str
    matchType: MatchType


class SnapshotWatchlist(BaseModel):
    id: str
    name: str
    revision: int
    indicators: List[SnapshotIndicator]


class SnapshotResponse(BaseModel):
    tenantId: str
    watchlists: List[SnapshotWatchlist]


# Event Envelope Schema
class EventEnvelope(BaseModel):
    eventId: str
    eventType: str
    eventVersion: int = 1
    occurredAt: str
    tenantId: str
    watchlistId: str
    watchlistRevision: int
    data: Dict[str, Any]