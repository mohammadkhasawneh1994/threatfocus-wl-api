import json
from typing import Any, Dict, List
import boto3
from aws_lambda_powertools import Logger, Tracer

from core.config import settings

logger = Logger(service="outbox-publisher")
tracer = Tracer(service="outbox-publisher")

dynamodb = boto3.resource("dynamodb", region_name=settings.AWS_REGION)
table = dynamodb.Table(settings.TABLE_NAME)
eventbridge = boto3.client("events", region_name=settings.AWS_REGION)


@tracer.capture_lambda_handler
@logger.inject_lambda_context
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Polls/Processes pending transaction outbox events from DynamoDB single-table
    and publishes structured events to Amazon EventBridge.
    """
    # Step 1: Query all pending events from Outbox GSI
    response = table.query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :gsi1pk",
        ExpressionAttributeValues={":gsi1pk": "OUTBOX_PENDING"},
        Limit=50,
    )

    pending_items = response.get("Items", [])
    if not pending_items:
        logger.info("No pending outbox events found.")
        return {"processed": 0}

    published_count = 0

    for item in pending_items:
        event_id = item["eventId"]
        event_type = item["eventType"]
        tenant_id = item["tenantId"]

        # Step 2: Build Envelope Schema
        event_envelope = {
            "eventId": event_id,
            "eventType": event_type,
            "eventVersion": item.get("eventVersion", 1),
            "occurredAt": item["occurredAt"],
            "tenantId": tenant_id,
            "watchlistId": item["watchlistId"],
            "watchlistRevision": item["watchlistRevision"],
            "data": item["payload"],
        }

        try:
            # Step 3: Publish Event to EventBridge Bus
            eventbridge.put_events(
                Entries=[
                    {
                        "Source": "threatfocus.watchlist",
                        "DetailType": event_type,
                        "Detail": json.dumps(event_envelope),
                        "EventBusName": settings.EVENT_BUS_NAME,
                    }
                ]
            )

            # Step 4: Mark Outbox item as PUBLISHED (or delete outbox item)
            table.update_item(
                Key={"PK": item["PK"], "SK": item["SK"]},
                UpdateExpression="SET GSI1PK = :published, #st = :status",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={
                    ":published": "OUTBOX_PUBLISHED",
                    ":status": "PUBLISHED",
                },
            )
            published_count += 1
            logger.info(f"Published outbox event {event_id} ({event_type}) for tenant {tenant_id}")

        except Exception as e:
            logger.error(f"Failed to publish outbox event {event_id}: {str(e)}")

    return {"processed": published_count}