from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TierScope = Literal["tier1", "tier2", "tier3", "tier4", "all"]


class TierDefinition(BaseModel):
    """Defines which methods and layers are included in a tier."""

    model_config = ConfigDict(extra="forbid")

    methods: tuple[str, ...]
    layers: tuple[str, ...] = ("model", "wire", "byte")
    strategies: tuple[str, ...] = ("default", "state_breaker")


class CampaignConfig(BaseModel):
    """Full configuration for a campaign run."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    target_host: str = Field(min_length=1)
    target_port: int = Field(default=5060, ge=1, le=65535)
    transport: str = "UDP"
    mode: str = "softphone"
    scope: TierScope = "tier1"
    strategies: tuple[str, ...] = ("default", "state_breaker")
    layers: tuple[str, ...] = ("model", "wire", "byte")
    max_cases: int = Field(default=1000, ge=1)
    timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    cooldown_seconds: float = Field(default=0.2, ge=0.0, le=10.0)
    seed_start: int = Field(default=0, ge=0)
    output_path: str = Field(default="results/campaign.jsonl", min_length=1)
    process_name: str = Field(default="baresip", min_length=1)
    check_process: bool = True
    log_path: str | None = None


class CaseSpec(BaseModel):
    """Describes one test case to be executed by the campaign."""

    model_config = ConfigDict(extra="forbid")

    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str = Field(min_length=1)
    layer: str = Field(min_length=1)
    strategy: str = Field(min_length=1)


class CaseResult(BaseModel):
    """Result of executing a single test case, including oracle verdict."""

    model_config = ConfigDict(extra="forbid")

    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str
    layer: str
    strategy: str
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)
    verdict: str
    reason: str
    response_code: int | None = None
    elapsed_ms: float
    process_alive: bool | None = None
    raw_response: str | None = None
    reproduction_cmd: str
    error: str | None = None
    timestamp: float


class CampaignSummary(BaseModel):
    """Aggregate statistics for a campaign."""

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    normal: int = 0
    suspicious: int = 0
    timeout: int = 0
    crash: int = 0
    stack_failure: int = 0
    unknown: int = 0


class CampaignResult(BaseModel):
    """Top-level campaign output document."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    started_at: str
    completed_at: str | None = None
    status: Literal["running", "completed", "aborted"] = "running"
    config: CampaignConfig
    summary: CampaignSummary = Field(default_factory=CampaignSummary)
