"""Integration tests for the SES email integration."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from integrations import email


@pytest.mark.asyncio
async def test_send_email_noop_when_unconfigured(mock_settings):
    mock_settings.email_from = ""
    mock_settings.email_to = ""
    result = await email.send_email("subj", "body")
    assert result["status"] == "skipped"


@pytest.mark.asyncio
async def test_send_email_mock_mode_no_boto3(mock_settings):
    mock_settings.email_from = "soc@example.com"
    mock_settings.email_to = "oncall@example.com"
    mock_settings.mock_mode = True
    with patch("boto3.client") as mock_client:
        result = await email.send_email("subj", "body")
        mock_client.assert_not_called()
    assert result["status"] == "mock"
    assert result["to"] == ["oncall@example.com"]


@pytest.mark.asyncio
async def test_send_email_calls_ses_when_configured(mock_settings):
    mock_settings.email_from = "soc@example.com"
    mock_settings.email_to = "a@example.com,b@example.com"
    mock_settings.mock_mode = False
    ses = MagicMock()
    ses.send_email.return_value = {"MessageId": "msg-1"}
    with patch("boto3.client", return_value=ses) as boto:
        result = await email.send_email("hi", "body", body_html="<p>body</p>")
    assert result["status"] == "sent"
    assert result["message_id"] == "msg-1"
    boto.assert_called_once()
    kwargs = ses.send_email.call_args.kwargs
    assert kwargs["Source"] == "soc@example.com"
    assert kwargs["Destination"]["ToAddresses"] == ["a@example.com", "b@example.com"]
    assert kwargs["Message"]["Subject"]["Data"] == "hi"
    assert "Html" in kwargs["Message"]["Body"]
