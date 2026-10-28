"""Unit tests for the Stage 0 deterministic filter."""
from __future__ import annotations

import pytest

from agents.filter.filter import Stage0Filter
from agents.filter.rules.benign_events import is_benign_read
from agents.filter.rules.allowlist_check import is_allowlisted


def test_describe_is_benign():
    assert is_benign_read({"eventName": "DescribeInstances"}) is True


def test_list_is_benign():
    assert is_benign_read({"eventName": "ListBuckets"}) is True


def test_get_is_benign_generic():
    assert is_benign_read({"eventName": "GetObjectAcl"}) is True


def test_get_secret_value_is_not_benign():
    assert is_benign_read({"eventName": "GetSecretValue"}) is False


def test_get_password_data_is_not_benign():
    assert is_benign_read({"eventName": "GetPasswordData"}) is False


def test_create_access_key_is_not_benign():
    assert is_benign_read({"eventName": "CreateAccessKey"}) is False


def test_allowlisted_principal():
    ev = {"userIdentity": {"arn": "arn:aws:iam::123456789012:role/CIDeployRole"}}
    assert is_allowlisted(ev) is True


def test_non_allowlisted_principal():
    ev = {"userIdentity": {"arn": "arn:aws:iam::123456789012:user/eve"}}
    assert is_allowlisted(ev) is False


@pytest.mark.asyncio
async def test_stage0_filter_mixed_batch():
    events = [
        {"eventName": "DescribeInstances",
         "userIdentity": {"arn": "arn:aws:iam::1:user/eve"}},
        {"eventName": "GetSecretValue",
         "userIdentity": {"arn": "arn:aws:iam::1:user/eve"}},
        {"eventName": "StopLogging",
         "userIdentity": {"arn": "arn:aws:iam::1:user/eve"}},
        {"eventName": "PutBucketPolicy",
         "userIdentity": {"arn": "arn:aws:iam::123456789012:role/CIDeployRole"}},
    ]
    kept, summary = await Stage0Filter().run(events)
    kept_names = [e["eventName"] for e in kept]
    assert "DescribeInstances" not in kept_names
    assert "PutBucketPolicy" not in kept_names  # allowlisted principal
    assert "GetSecretValue" in kept_names
    assert "StopLogging" in kept_names
    assert summary["in"] == 4
    assert summary["kept"] == 2
    assert summary["dropped"] == 2
