"""Central config. Load once from env; pass the `settings` object where needed."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM (Anthropic via Strands)
    anthropic_api_key: str = Field(default="", repr=False)
    model_fast: str = Field(default="")   # stages 1-2
    model_smart: str = Field(default="")  # stages 3-4 + sidecars
    enable_prompt_cache: bool = True

    # AWS
    aws_region: str = "us-east-1"
    dynamodb_table: str = "soc_tickets"
    cloudtrail_s3_bucket: str | None = None

    # Queues
    sqs_detection_url: str | None = None
    sqs_enrichment_url: str | None = None
    sqs_triage_url: str | None = None
    sqs_response_url: str | None = None

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    correlation_window_seconds: int = 3600

    # Alerts
    slack_webhook_url: str | None = None
    slack_approval_channel: str | None = None
    slack_approval_mode: str = "deny"   # "auto_approve" | "deny" | "manual"
    slack_approval_timeout_seconds: int = 300
    email_from: str | None = None
    email_to: str | None = None

    # Mitigation
    deny_all_policy_arn: str = ""
    forensics_backup_s3_uri: str = ""
    s3_sensitive_buckets: str = ""

    # Detection tuning
    cloudtrail_lookback_max_results: int = 50
    off_hours_start_hour: int = 0
    off_hours_end_hour: int = 8

    # Safety
    dry_run: bool = False
    auto_mitigation_enabled: bool = False
    triage_confidence_threshold: float = 0.8
    max_mitigations_per_principal_per_hour: int = 5

    # Offline / testing
    mock_mode: bool = False

    # Logging
    log_level: str = "INFO"
    log_format: str = "text"  # "text" | "json"

    # MITRE ATT&CK STIX
    mitre_stix_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mitre_stix_cache_path: Path = Path.cwd() / ".cache" / "mitre-enterprise-attack.json"

    # Threat feeds
    abuseipdb_api_key: str = Field(default="", repr=False)
    greynoise_api_key: str = Field(default="", repr=False)
    threat_feed_cache_ttl_seconds: int = 3600

    # PagerDuty
    pagerduty_routing_key: str = Field(default="", repr=False)  # PagerDuty Events API v2 routing key

    # Splunk HEC
    splunk_hec_url: str = ""
    splunk_hec_token: str = Field(default="", repr=False)
    splunk_index: str = ""
    splunk_verify_tls: bool = True

    # TheHive (case management)
    thehive_url: str = ""
    thehive_api_key: str = Field(default="", repr=False)
    thehive_organisation: str = ""
    thehive_tlp: int = 2
    thehive_pap: int = 2
    thehive_verify_tls: bool = True

    # Paths
    rules_dir: Path = Path(__file__).parent / "rules"


@lru_cache
def _load() -> Settings:
    return Settings()


settings = _load()
