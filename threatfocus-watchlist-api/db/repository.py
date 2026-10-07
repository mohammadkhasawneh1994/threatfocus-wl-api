import base64
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
import boto3
from botocore.exceptions import ClientError

from core.config import settings
from core.exceptions import DuplicateResourceException, EntityNotFoundException, ServiceException
from domain.models import (
    EventEnvelope,
    IndicatorCreate,
    IndicatorResponse,
    IndicatorType,
    WatchlistCreate,
    WatchlistResponse,
    WatchlistUpdate,
    current_utc_timestamp,
)


class WatchlistRepository:
    def __init__(self, table_name: str = settings.TABLE_NAME):
        self.dynamodb = boto3.resource("dynamodb", region_name=settings.AWS_REGION)
        self.table = self.dynamodb.Table(table_name)

    # Key Helpers
    @staticmethod
    def _pk_watchlist(tenant_id: str, watchlist_id: str) -> str:
        return f"TENANT#{tenant_id}#WATCHLIST#{watchlist_id}"

    @staticmethod
    def _sk_watchlist_metadata() -> str:
        return "METADATA"

    @staticmethod
    def _sk_indicator(indicator_id: str) -> str:
        return f"INDICATOR#{indicator_id}"

    @staticmethod
    def _gsi1_pk_indicator_uniq(watchlist_id: str, ind_type: str, normalized_val: str, match_type: str) -> str:
        return f"WATCHLIST#{watchlist_id}#TYPE#{ind_type}#VAL#{normalized_val}#MATCH#{match_type}"

    # WATCHLIST OPERATIONS
    def create_watchlist(self, tenant_id: str, data: WatchlistCreate) -> WatchlistResponse:
        watchlist_id = str(uuid.uuid4())
        now = current_utc_timestamp()
        
        pk = self._pk_watchlist(tenant_id, watchlist_id)
        sk = self._sk_watchlist_metadata()

        wl_item = {
            "PK": pk,
            "SK": sk,
            "GSI1PK": f"TENANT#{tenant_id}",
            "GSI1SK": f"WATCHLIST#{watchlist_id}",
            "entityType": "WATCHLIST",
            "id": watchlist_id,
            "tenantId": tenant_id,
            "name": data.name,
            "description": data.description,
            "enabled": data.enabled,
            "revision": 1,
            "createdAt": now,
            "updatedAt": now,
        }

        event_id = str(uuid.uuid4())
        outbox_item = {
            "PK": "OUTBOX",
            "SK": f"STATUS#PENDING#EVENT#{event_id}",
            "GSI1PK": "OUTBOX_PENDING",
            "GSI1SK": now,
            "entityType": "OUTBOX",
            "eventId": event_id,
            "eventType": "watchlist.created",
            "eventVersion": 1,
            "occurredAt": now,
            "tenantId": tenant_id,
            "watchlistId": watchlist_id,
            "watchlistRevision": 1,
            "status": "PENDING",
            "payload": {
                "id": watchlist_id,
                "tenantId": tenant_id,
                "name": data.name,
                "enabled": data.enabled,
                "revision": 1,
            },
        }

        try:
            self.dynamodb.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": self.table.name,
                            "Item": wl_item,
                            "ConditionExpression": "attribute_not_exists(PK)",
                        }
                    },
                    {"Put": {"TableName": self.table.name, "Item": outbox_item}},
                ]
            )
        except ClientError as e:
            raise ServiceException("DATABASE_ERROR", f"Failed to create watchlist: {str(e)}")

        return WatchlistResponse(**wl_item)

    def get_watchlist(self, tenant_id: str, watchlist_id: str) -> WatchlistResponse:
        response = self.table.get_item(
            Key={
                "PK": self._pk_watchlist(tenant_id, watchlist_id),
                "SK": self._sk_watchlist_metadata(),
            }
        )
        item = response.get("Item")
        if not item or item.get("tenantId") != tenant_id:
            raise EntityNotFoundException("Watchlist", watchlist_id)

        return WatchlistResponse(**item)

    def update_watchlist(self, tenant_id: str, watchlist_id: str, data: WatchlistUpdate) -> WatchlistResponse:
        existing = self.get_watchlist(tenant_id, watchlist_id)
        now = current_utc_timestamp()
        new_revision = existing.revision + 1

        new_name = data.name if data.name is not None else existing.name
        new_desc = data.description if data.description is not None else existing.description
        new_enabled = data.enabled if data.enabled is not None else existing.enabled

        pk = self._pk_watchlist(tenant_id, watchlist_id)
        sk = self._sk_watchlist_metadata()

        event_id = str(uuid.uuid4())
        outbox_item = {
            "PK": "OUTBOX",
            "SK": f"STATUS#PENDING#EVENT#{event_id}",
            "GSI1PK": "OUTBOX_PENDING",
            "GSI1SK": now,
            "entityType": "OUTBOX",
            "eventId": event_id,
            "eventType": "watchlist.updated",
            "eventVersion": 1,
            "occurredAt": now,
            "tenantId": tenant_id,
            "watchlistId": watchlist_id,
            "watchlistRevision": new_revision,
            "status": "PENDING",
            "payload": {
                "id": watchlist_id,
                "tenantId": tenant_id,
                "name": new_name,
                "description": new_desc,
                "enabled": new_enabled,
                "revision": new_revision,
            },
        }

        try:
            self.dynamodb.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": {"PK": pk, "SK": sk},
                            "UpdateExpression": "SET #n = :n, #d = :d, #e = :e, revision = :rev, updatedAt = :u",
                            "ConditionExpression": "attribute_exists(PK) AND tenantId = :authTenantId AND revision = :curRev",
                            "ExpressionAttributeNames": {
                                "#n": "name",
                                "#d": "description",
                                "#e": "enabled",
                            },
                            "ExpressionAttributeValues": {
                                ":n": new_name,
                                ":d": new_desc,
                                ":e": new_enabled,
                                ":rev": new_revision,
                                ":u": now,
                                ":authTenantId": tenant_id,
                                ":curRev": existing.revision,
                            },
                        }
                    },
                    {"Put": {"TableName": self.table.name, "Item": outbox_item}},
                ]
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                raise ServiceException("CONCURRENCY_ERROR", "Watchlist was updated concurrently.")
            raise ServiceException("DATABASE_ERROR", f"Failed to update watchlist: {str(e)}")

        return self.get_watchlist(tenant_id, watchlist_id)

    def delete_watchlist(self, tenant_id: str, watchlist_id: str) -> None:
        existing = self.get_watchlist(tenant_id, watchlist_id)
        now = current_utc_timestamp()
        
        # Scan / Query all indicators belonging to this watchlist to batch delete
        pk = self._pk_watchlist(tenant_id, watchlist_id)
        response = self.table.query(KeyConditionExpression="PK = :pk", ExpressionAttributeValues={":pk": pk})
        items = response.get("Items", [])

        event_id = str(uuid.uuid4())
        outbox_item = {
            "PK": "OUTBOX",
            "SK": f"STATUS#PENDING#EVENT#{event_id}",
            "GSI1PK": "OUTBOX_PENDING",
            "GSI1SK": now,
            "entityType": "OUTBOX",
            "eventId": event_id,
            "eventType": "watchlist.deleted",
            "eventVersion": 1,
            "occurredAt": now,
            "tenantId": tenant_id,
            "watchlistId": watchlist_id,
            "watchlistRevision": existing.revision + 1,
            "status": "PENDING",
            "payload": {"id": watchlist_id, "tenantId": tenant_id},
        }

        transact_items: List[Dict[str, Any]] = [
            {"Put": {"TableName": self.table.name, "Item": outbox_item}}
        ]

        for item in items:
            transact_items.append({
                "Delete": {
                    "TableName": self.table.name,
                    "Key": {"PK": item["PK"], "SK": item["SK"]},
                    "ConditionExpression": "tenantId = :authTenantId",
                    "ExpressionAttributeValues": {":authTenantId": tenant_id},
                }
            })

        # DynamoDB TransactWriteItems supports up to 100 items per request
        if len(transact_items) > 100:
            raise ServiceException("VALIDATION_ERROR", "Cannot delete watchlist with > 98 indicators in a single transaction.")

        try:
            self.dynamodb.meta.client.transact_write_items(TransactItems=transact_items)
        except ClientError as e:
            raise ServiceException("DATABASE_ERROR", f"Failed to delete watchlist: {str(e)}")

    def list_watchlists(
    self, tenant_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[WatchlistResponse], Optional[str]]:
        exclusive_start_key = None
        if cursor:
            try:
                exclusive_start_key = json.loads(base64.b64decode(cursor).decode("utf-8"))
            except Exception:
                raise ServiceException("INVALID_CURSOR", "Invalid pagination token supplied.")

        query_kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": "GSI1PK = :gsi1pk AND begins_with(GSI1SK, :gsi1sk)",
            "ExpressionAttributeValues": {
                ":gsi1pk": f"TENANT#{tenant_id}",
                ":gsi1sk": "WATCHLIST#",
            },
            "Limit": limit,
        }
        if exclusive_start_key:
            query_kwargs["ExclusiveStartKey"] = exclusive_start_key

        response = self.table.query(**query_kwargs)
        items = response.get("Items", [])
        
        watchlists = [WatchlistResponse(**item) for item in items]
        next_cursor = None
        if "LastEvaluatedKey" in response:
            next_cursor = base64.b64encode(json.dumps(response["LastEvaluatedKey"]).encode("utf-8")).decode("utf-8")

        return watchlists, next_cursor

    # INDICATOR OPERATIONS
    def create_indicator(
        self, tenant_id: str, watchlist_id: str, data: IndicatorCreate, normalized_value: str
    ) -> IndicatorResponse:
        watchlist = self.get_watchlist(tenant_id, watchlist_id)
        indicator_id = str(uuid.uuid4())
        now = current_utc_timestamp()
        new_revision = watchlist.revision + 1

        pk = self._pk_watchlist(tenant_id, watchlist_id)
        sk = self._sk_indicator(indicator_id)
        gsi1_pk = self._gsi1_pk_indicator_uniq(
            watchlist_id, data.type.value, normalized_value, data.matchType.value
        )

        indicator_item = {
            "PK": pk,
            "SK": sk,
            "GSI1PK": gsi1_pk,
            "GSI1SK": f"TENANT#{tenant_id}",
            "entityType": "INDICATOR",
            "id": indicator_id,
            "watchlistId": watchlist_id,
            "tenantId": tenant_id,
            "type": data.type.value,
            "value": data.value,
            "normalizedValue": normalized_value,
            "matchType": data.matchType.value,
            "enabled": data.enabled,
            "createdAt": now,
            "updatedAt": now,
        }

        event_id = str(uuid.uuid4())
        outbox_item = {
            "PK": "OUTBOX",
            "SK": f"STATUS#PENDING#EVENT#{event_id}",
            "GSI1PK": "OUTBOX_PENDING",
            "GSI1SK": now,
            "entityType": "OUTBOX",
            "eventId": event_id,
            "eventType": "watchlist.indicator.created",
            "eventVersion": 1,
            "occurredAt": now,
            "tenantId": tenant_id,
            "watchlistId": watchlist_id,
            "watchlistRevision": new_revision,
            "status": "PENDING",
            "payload": {
                "id": indicator_id,
                "watchlistId": watchlist_id,
                "tenantId": tenant_id,
                "type": data.type.value,
                "normalizedValue": normalized_value,
                "matchType": data.matchType.value,
                "enabled": data.enabled,
            },
        }

        try:
            self.dynamodb.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": self.table.name,
                            "Item": indicator_item,
                            "ConditionExpression": "attribute_not_exists(PK)",
                        }
                    },
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": {
                                "PK": pk,
                                "SK": self._sk_watchlist_metadata(),
                            },
                            "UpdateExpression": "SET revision = :rev, updatedAt = :u",
                            "ConditionExpression": "revision = :curRev AND tenantId = :authTenantId",
                            "ExpressionAttributeValues": {
                                ":rev": new_revision,
                                ":u": now,
                                ":curRev": watchlist.revision,
                                ":authTenantId": tenant_id,
                            },
                        }
                    },
                    {"Put": {"TableName": self.table.name, "Item": outbox_item}},
                ]
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                # Check for duplicate indicator via GSI condition/existing match
                dup = self._check_indicator_duplicate(gsi1_pk)
                if dup:
                    raise DuplicateResourceException(
                        f"Indicator with type '{data.type.value}', value '{normalized_value}', and matchType '{data.matchType.value}' already exists in this watchlist."
                    )
            raise ServiceException("DATABASE_ERROR", f"Failed to create indicator: {str(e)}")

        return IndicatorResponse(**indicator_item)

    def _check_indicator_duplicate(self, gsi1_pk: str) -> bool:
        resp = self.table.query(
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :gsi1pk",
            ExpressionAttributeValues={":gsi1pk": gsi1_pk},
            Limit=1,
        )
        return len(resp.get("Items", [])) > 0

    def list_indicators(
    self, tenant_id: str, watchlist_id: str, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[IndicatorResponse], Optional[str]]:
        self.get_watchlist(tenant_id, watchlist_id)  # Validate watchlist exists & tenant access

        exclusive_start_key = None
        if cursor:
            try:
                exclusive_start_key = json.loads(base64.b64decode(cursor).decode("utf-8"))
            except Exception:
                raise ServiceException("INVALID_CURSOR", "Invalid pagination token supplied.")

        query_kwargs: Dict[str, Any] = {
            "KeyConditionExpression": "PK = :pk AND begins_with(SK, :sk_prefix)",
            "ExpressionAttributeValues": {
                ":pk": self._pk_watchlist(tenant_id, watchlist_id),
                ":sk_prefix": "INDICATOR#",
            },
            "Limit": limit,
        }
        if exclusive_start_key:
            query_kwargs["ExclusiveStartKey"] = exclusive_start_key

        response = self.table.query(**query_kwargs)
        items = response.get("Items", [])
        
        indicators = [IndicatorResponse(**item) for item in items]
        next_cursor = None
        if "LastEvaluatedKey" in response:
            next_cursor = base64.b64encode(json.dumps(response["LastEvaluatedKey"]).encode("utf-8")).decode("utf-8")

        return indicators, next_cursor

    def delete_indicator(self, tenant_id: str, watchlist_id: str, indicator_id: str) -> None:
        watchlist = self.get_watchlist(tenant_id, watchlist_id)
        
        pk = self._pk_watchlist(tenant_id, watchlist_id)
        sk = self._sk_indicator(indicator_id)

        # Ensure indicator exists
        ind_resp = self.table.get_item(Key={"PK": pk, "SK": sk})
        ind_item = ind_resp.get("Item")
        if not ind_item or ind_item.get("tenantId") != tenant_id:
            raise EntityNotFoundException("Indicator", indicator_id)

        now = current_utc_timestamp()
        new_revision = watchlist.revision + 1

        event_id = str(uuid.uuid4())
        outbox_item = {
            "PK": "OUTBOX",
            "SK": f"STATUS#PENDING#EVENT#{event_id}",
            "GSI1PK": "OUTBOX_PENDING",
            "GSI1SK": now,
            "entityType": "OUTBOX",
            "eventId": event_id,
            "eventType": "watchlist.indicator.deleted",
            "eventVersion": 1,
            "occurredAt": now,
            "tenantId": tenant_id,
            "watchlistId": watchlist_id,
            "watchlistRevision": new_revision,
            "status": "PENDING",
            "payload": {
                "id": indicator_id,
                "watchlistId": watchlist_id,
                "tenantId": tenant_id,
            },
        }

        try:
            self.dynamodb.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Delete": {
                            "TableName": self.table.name,
                            "Key": {"PK": pk, "SK": sk},
                            "ConditionExpression": "tenantId = :authTenantId",
                            "ExpressionAttributeValues": {":authTenantId": tenant_id},
                        }
                    },
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": {
                                "PK": pk,
                                "SK": self._sk_watchlist_metadata(),
                            },
                            "UpdateExpression": "SET revision = :rev, updatedAt = :u",
                            "ConditionExpression": "revision = :curRev AND tenantId = :authTenantId",
                            "ExpressionAttributeValues": {
                                ":rev": new_revision,
                                ":u": now,
                                ":curRev": watchlist.revision,
                                ":authTenantId": tenant_id,
                            },
                        }
                    },
                    {"Put": {"TableName": self.table.name, "Item": outbox_item}},
                ]
            )
        except ClientError as e:
            raise ServiceException("DATABASE_ERROR", f"Failed to delete indicator: {str(e)}")

    # SNAPSHOT SERVICE-TO-SERVICE QUERY
    def get_snapshot(
    self, tenant_id: str, indicator_types: Optional[List[IndicatorType]] = None
    ) -> Dict[str, Any]:
        # Step 1: Query all watchlists for tenant
        w_items, _ = self.list_watchlists(tenant_id, limit=200)
        active_watchlists = [w for w in w_items if w.enabled]

        snapshot_watchlists = []

        for wl in active_watchlists:
            # Step 2: Retrieve all enabled indicators for active watchlist
            pk = self._pk_watchlist(tenant_id, wl.id)
            ind_response = self.table.query(
                KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": pk,
                    ":sk_prefix": "INDICATOR#",
                },
            )
            raw_indicators = ind_response.get("Items", [])
            
            matched_indicators = []
            filter_types = set(t.value for t in indicator_types) if indicator_types else None

            for ind in raw_indicators:
                if not ind.get("enabled", False):
                    continue
                if filter_types and ind.get("type") not in filter_types:
                    continue

                matched_indicators.append(
                    {
                        "id": ind["id"],
                        "type": ind["type"],
                        "normalizedValue": ind["normalizedValue"],
                        "matchType": ind["matchType"],
                    }
                )

            snapshot_watchlists.append(
                {
                    "id": wl.id,
                    "name": wl.name,
                    "revision": wl.revision,
                    "indicators": matched_indicators,
                }
            )

        return {"tenantId": tenant_id, "watchlists": snapshot_watchlists}