"""
DynamoDB Client for Ticket Storage.
Ported from v1. In MOCK_MODE all writes are no-ops that just log.
"""

from datetime import datetime, timezone
from decimal import Decimal

from logger import get_logger
from config import settings

logger = get_logger("dynamodb_client")


class DynamoDBTicketClient:
    """Client for managing SOC tickets in DynamoDB."""

    def __init__(self):
        self.mock = settings.mock_mode
        self.table = None
        if self.mock:
            logger.info(f"[mock] DynamoDB client stub for table: {settings.dynamodb_table}")
            return
        try:
            import boto3
            self.dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
            self.table = self.dynamodb.Table(settings.dynamodb_table)
            logger.info(f"DynamoDB client initialized for table: {settings.dynamodb_table}")
        except Exception as e:
            logger.error(f"Failed to initialize DynamoDB client: {e}")
            self.table = None

    def create_ticket(self, ticket_data: dict) -> bool:
        if self.mock:
            logger.info(f"[mock] put_item ticket: {ticket_data.get('ticket_id')}")
            return True
        if not self.table:
            logger.error("DynamoDB table not initialized")
            return False
        try:
            item = self._prepare_item(ticket_data)
            self.table.put_item(Item=item)
            logger.info(f"Ticket created in DynamoDB: {ticket_data.get('ticket_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to create ticket in DynamoDB: {e}")
            return False

    def update_ticket(self, ticket_id: str, update_data: dict) -> bool:
        if self.mock:
            logger.info(f"[mock] update_ticket: {ticket_id}")
            return True
        if not self.table:
            return False
        try:
            timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            item = {"ticket_id": ticket_id, "created_timestamp": timestamp,
                    **self._prepare_item(update_data)}
            self.table.put_item(Item=item)
            logger.info(f"Ticket updated in DynamoDB: {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update ticket in DynamoDB: {e}")
            return False

    def get_ticket_history(self, ticket_id: str) -> list:
        if self.mock or not self.table:
            return []
        try:
            import boto3
            response = self.table.query(
                KeyConditionExpression=boto3.dynamodb.conditions.Key("ticket_id").eq(ticket_id),
                ScanIndexForward=True,
            )
            return response.get("Items", [])
        except Exception as e:
            logger.error(f"Failed to get ticket history: {e}")
            return []

    def get_latest_ticket_status(self, ticket_id: str) -> dict:
        if self.mock or not self.table:
            return {}
        try:
            import boto3
            response = self.table.query(
                KeyConditionExpression=boto3.dynamodb.conditions.Key("ticket_id").eq(ticket_id),
                ScanIndexForward=False,
                Limit=1,
            )
            items = response.get("Items", [])
            return items[0] if items else {}
        except Exception as e:
            logger.error(f"Failed to get latest ticket status: {e}")
            return {}

    def _prepare_item(self, data: dict) -> dict:
        item = {}
        if "created_timestamp" not in data:
            item["created_timestamp"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
        for key, value in data.items():
            if value is None:
                continue
            elif isinstance(value, float):
                item[key] = Decimal(str(value))
            elif isinstance(value, dict):
                item[key] = self._convert_dict(value)
            elif isinstance(value, list):
                item[key] = self._convert_list(value)
            else:
                item[key] = value
        return item

    def _convert_dict(self, d: dict) -> dict:
        result = {}
        for key, value in d.items():
            if value is None:
                continue
            elif isinstance(value, float):
                result[key] = Decimal(str(value))
            elif isinstance(value, dict):
                result[key] = self._convert_dict(value)
            elif isinstance(value, list):
                result[key] = self._convert_list(value)
            else:
                result[key] = value
        return result

    def _convert_list(self, lst: list) -> list:
        result = []
        for item in lst:
            if item is None:
                continue
            elif isinstance(item, float):
                result.append(Decimal(str(item)))
            elif isinstance(item, dict):
                result.append(self._convert_dict(item))
            elif isinstance(item, list):
                result.append(self._convert_list(item))
            else:
                result.append(item)
        return result


_dynamodb_client = None


def get_dynamodb_client() -> DynamoDBTicketClient:
    global _dynamodb_client
    if _dynamodb_client is None:
        _dynamodb_client = DynamoDBTicketClient()
    return _dynamodb_client
