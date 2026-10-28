"""
CloudTrail Event Fetcher Tool.

Uses boto3 directly (v1 behaviour). In MOCK_MODE returns canned events from
tests/fixtures/cloudtrail_events/ so it can run fully offline.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any

from strands import tool
from logger import get_logger
from config import settings

logger = get_logger("fetch_cloudtrail")


def _load_mock_events() -> List[Dict[str, Any]]:
    fixtures = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "cloudtrail_events"
    if not fixtures.exists():
        return []
    events: list = []
    for p in sorted(fixtures.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            if isinstance(data, list):
                events.extend(data)
            else:
                events.append(data)
        except Exception as e:
            logger.error(f"Failed to load fixture {p}: {e}")
    return events


@tool
def fetch_cloudtrail_events(lookback_seconds: int = 30) -> List[Dict[str, Any]]:
    """
    Fetch CloudTrail events from the last N seconds.

    Args:
        lookback_seconds: Number of seconds to look back (default: 30)

    Returns:
        List of CloudTrail events with a simplified structure.
    """
    if settings.mock_mode:
        events = _load_mock_events()
        logger.info(f"[mock] returning {len(events)} canned CloudTrail events")
        return events

    try:
        import boto3

        client = boto3.client("cloudtrail", region_name=settings.aws_region)

        end_time = datetime.now(timezone.utc).replace(tzinfo=None)
        start_time = end_time - timedelta(seconds=lookback_seconds)

        logger.info(f"Fetching CloudTrail events from {start_time} to {end_time}")

        response = client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=settings.cloudtrail_lookback_max_results,
        )

        events: list = []
        for event in response.get("Events", []):
            try:
                event_detail = json.loads(event.get("CloudTrailEvent", "{}"))
                processed_event = {
                    "event_id": event.get("EventId"),
                    "event_name": event.get("EventName"),
                    "event_time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
                    "username": event.get("Username"),
                    "event_source": event_detail.get("eventSource"),
                    "aws_region": event_detail.get("awsRegion"),
                    "source_ip": event_detail.get("sourceIPAddress"),
                    "user_agent": event_detail.get("userAgent"),
                    "request_parameters": event_detail.get("requestParameters"),
                    "response_elements": event_detail.get("responseElements"),
                    "resources": event.get("Resources", []),
                    "user_identity": event_detail.get("userIdentity"),
                    "error_code": event_detail.get("errorCode"),
                    "error_message": event_detail.get("errorMessage"),
                    "raw_event": event_detail,
                }
                events.append(processed_event)
            except Exception as e:
                logger.error(f"Error processing event {event.get('EventId')}: {e}")
                continue

        logger.info(f"Fetched {len(events)} CloudTrail events")
        return events

    except Exception as e:
        logger.error(f"Error fetching CloudTrail events: {e}")
        return []
