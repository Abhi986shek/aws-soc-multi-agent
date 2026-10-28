"""
AWS Mitigation Tool - real boto3 calls.

Every handler respects:
  - settings.dry_run           → returns {"status": "dry_run", ...}
  - settings.auto_mitigation_enabled → returns {"status": "disabled_by_setting"}
  - settings.mock_mode         → returns {"status": "mock", ...}
Boto3 exceptions are caught and returned as {"status": "error", ...}.
"""
from __future__ import annotations

from datetime import datetime, timezone

from strands import tool

from config import settings
from logger import get_logger

logger = get_logger("aws_mitigation")


def _guard(action: str) -> dict | None:
    if not settings.auto_mitigation_enabled:
        return {"action_type": action, "status": "disabled_by_setting"}
    if settings.mock_mode:
        return {"action_type": action, "status": "mock"}
    if settings.dry_run:
        return {"action_type": action, "status": "dry_run"}
    return None


def _boto3_client(service: str):
    import boto3
    return boto3.client(service, region_name=settings.aws_region)


@tool
def execute_aws_mitigation(
    actions: list[str],
    user_id: str,
    resources: list[str],
    source_ip: str = None,
) -> dict:
    """Executes automated AWS security mitigation actions."""
    execution_results = []
    successful_actions = []
    failed_actions = []

    for action in actions:
        result = _execute_single_action(action, user_id, resources or [], source_ip)
        execution_results.append(result)
        if result.get("success"):
            successful_actions.append(action)
        else:
            failed_actions.append({"action": action, "error": result.get("error", "not_successful")})

    return {
        "execution_timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "total_actions": len(actions),
        "successful": len(successful_actions),
        "failed": len(failed_actions),
        "execution_results": execution_results,
        "successful_actions": successful_actions,
        "failed_actions": failed_actions,
    }


def _execute_single_action(action: str, user_id: str, resources: list, source_ip: str | None) -> dict:
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    handlers = {
        "disable_user_account": lambda: _disable_user_account(user_id),
        "disable_user": lambda: _disable_user_account(user_id),
        "rotate_access_keys": lambda: _rotate_access_keys(user_id, None),
        "revoke_access_key": lambda: _rotate_access_keys(user_id, resources[0] if resources else None),
        "block_source_ip": lambda: _block_source_ip(source_ip, resources),
        "quarantine_principal": lambda: _quarantine_principal(user_id),
        "enable_cloudtrail": lambda: _enable_cloudtrail(),
        "re_enable_logging": lambda: _enable_cloudtrail(),
        "enable_s3_versioning": lambda: _enable_s3_versioning(resources),
        "isolate_account": lambda: _isolate_account(user_id),
        "detach_policy": lambda: _detach_policy(user_id),
    }
    handler = handlers.get(action)
    if not handler:
        return {"action": action, "success": False, "error": f"Unknown action: {action}", "timestamp": timestamp}
    try:
        result = handler()
        success = result.get("status") in {"ok", "dry_run", "mock", "disabled_by_setting", "manual_required", "skipped"}
        return {
            "action": action,
            "success": success,
            "details": result,
            "timestamp": timestamp,
            "error": None if success else result.get("error"),
        }
    except Exception as e:
        logger.error(f"Handler for {action} raised: {e}")
        return {"action": action, "success": False, "error": str(e), "timestamp": timestamp}


def _disable_user_account(user_id: str) -> dict:
    guard = _guard("disable_user_account")
    if guard is not None:
        return guard
    if not user_id or user_id == "unknown":
        return {"action_type": "disable_user_account", "status": "skipped", "reason": "no_user_id"}
    policy_arn = settings.deny_all_policy_arn
    if not policy_arn:
        return {"action_type": "disable_user_account", "status": "skipped",
                "reason": "deny_all_policy_arn_not_set"}
    try:
        iam = _boto3_client("iam")
        iam.attach_user_policy(UserName=user_id, PolicyArn=policy_arn)
        return {"action_type": "disable_user_account", "status": "ok", "user": user_id,
                "policy_arn": policy_arn}
    except Exception as e:
        return {"action_type": "disable_user_account", "status": "error", "error": str(e)}


def _rotate_access_keys(user_id: str, specific_key_id: str | None) -> dict:
    guard = _guard("rotate_access_keys")
    if guard is not None:
        return guard
    if not user_id or user_id == "unknown":
        return {"action_type": "rotate_access_keys", "status": "skipped", "reason": "no_user_id"}
    try:
        iam = _boto3_client("iam")
        keys = iam.list_access_keys(UserName=user_id).get("AccessKeyMetadata", [])
        deactivated = []
        for k in keys:
            kid = k.get("AccessKeyId")
            if specific_key_id and kid != specific_key_id:
                continue
            iam.update_access_key(UserName=user_id, AccessKeyId=kid, Status="Inactive")
            deactivated.append(kid)
        return {"action_type": "rotate_access_keys", "status": "ok",
                "user": user_id, "deactivated": deactivated}
    except Exception as e:
        return {"action_type": "rotate_access_keys", "status": "error", "error": str(e)}


def _block_source_ip(ip: str | None, resources: list) -> dict:
    guard = _guard("block_source_ip")
    if guard is not None:
        return guard
    if not ip:
        return {"action_type": "block_source_ip", "status": "skipped", "reason": "no_ip"}
    sg_id = next((r for r in (resources or []) if isinstance(r, str) and r.startswith("sg-")), None)
    if not sg_id:
        logger.info(f"block_source_ip: no security group in resources for ip={ip}")
        return {"action_type": "block_source_ip", "status": "skipped", "reason": "no_security_group"}
    try:
        ec2 = _boto3_client("ec2")
        cidr = ip if "/" in ip else f"{ip}/32"
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": cidr}],
            }],
        )
        return {"action_type": "block_source_ip", "status": "ok",
                "security_group": sg_id, "ip": cidr}
    except Exception as e:
        return {"action_type": "block_source_ip", "status": "error", "error": str(e)}


def _quarantine_principal(user_id: str) -> dict:
    guard = _guard("quarantine_principal")
    if guard is not None:
        return guard
    if not user_id or user_id == "unknown":
        return {"action_type": "quarantine_principal", "status": "skipped", "reason": "no_user_id"}
    try:
        iam = _boto3_client("iam")
        attached = iam.list_attached_user_policies(UserName=user_id).get("AttachedPolicies", [])
        detached = []
        for p in attached:
            arn = p.get("PolicyArn")
            iam.detach_user_policy(UserName=user_id, PolicyArn=arn)
            detached.append(arn)
        policy_arn = settings.deny_all_policy_arn
        if policy_arn:
            iam.attach_user_policy(UserName=user_id, PolicyArn=policy_arn)
        return {"action_type": "quarantine_principal", "status": "ok",
                "user": user_id, "detached": detached, "attached_deny": bool(policy_arn)}
    except Exception as e:
        return {"action_type": "quarantine_principal", "status": "error", "error": str(e)}


def _enable_cloudtrail() -> dict:
    guard = _guard("enable_cloudtrail")
    if guard is not None:
        return guard
    try:
        ct = _boto3_client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        started = []
        for t in trails:
            arn = t.get("TrailARN") or t.get("Name")
            if not arn:
                continue
            ct.start_logging(Name=arn)
            started.append(arn)
        return {"action_type": "enable_cloudtrail", "status": "ok", "trails_started": started}
    except Exception as e:
        return {"action_type": "enable_cloudtrail", "status": "error", "error": str(e)}


def _enable_s3_versioning(resources: list) -> dict:
    guard = _guard("enable_s3_versioning")
    if guard is not None:
        return guard
    buckets = [r for r in (resources or []) if isinstance(r, str) and r]
    if not buckets:
        return {"action_type": "enable_s3_versioning", "status": "skipped", "reason": "no_buckets"}
    try:
        s3 = _boto3_client("s3")
        updated = []
        for b in buckets:
            bucket_name = b.replace("arn:aws:s3:::", "").split("/")[0]
            s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={"Status": "Enabled"},
            )
            updated.append(bucket_name)
        return {"action_type": "enable_s3_versioning", "status": "ok", "buckets": updated}
    except Exception as e:
        return {"action_type": "enable_s3_versioning", "status": "error", "error": str(e)}


def _isolate_account(user_id: str) -> dict:
    guard = _guard("isolate_account")
    if guard is not None:
        return guard
    logger.warning(f"isolate_account is a manual action for user={user_id}")
    return {"action_type": "isolate_account", "status": "manual_required", "user": user_id}


def _detach_policy(user_id: str) -> dict:
    guard = _guard("detach_policy")
    if guard is not None:
        return guard
    if not user_id or user_id == "unknown":
        return {"action_type": "detach_policy", "status": "skipped", "reason": "no_user_id"}
    try:
        iam = _boto3_client("iam")
        attached = iam.list_attached_user_policies(UserName=user_id).get("AttachedPolicies", [])
        detached = []
        for p in attached:
            arn = p.get("PolicyArn")
            iam.detach_user_policy(UserName=user_id, PolicyArn=arn)
            detached.append(arn)
        return {"action_type": "detach_policy", "status": "ok",
                "user": user_id, "detached": detached}
    except Exception as e:
        return {"action_type": "detach_policy", "status": "error", "error": str(e)}
