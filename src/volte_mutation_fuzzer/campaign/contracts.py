from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from volte_mutation_fuzzer.sip.common import SIPMethod

ALL_SIP_METHODS = tuple(method.value for method in SIPMethod)
_DEFAULT_REAL_UE_SOURCE_IP = "172.22.0.21"


class CampaignConfig(BaseModel):
    """Full configuration for a campaign run."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    target_host: str | None = Field(default=None, min_length=1)
    target_port: int = Field(default=5060, ge=1, le=65535)
    transport: str = "UDP"
    mode: str = "softphone"
    methods: tuple[str, ...] = Field(default_factory=tuple)
    response_codes: tuple[int, ...] = Field(default_factory=tuple)
    with_dialog: bool = False
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
    adb_enabled: bool = False
    adb_serial: str | None = None
    adb_buffers: tuple[str, ...] = ("main", "system", "radio", "crash")
    pcap_enabled: bool = False
    pcap_dir: str = "results/pcap"
    pcap_interface: str = "any"

    # Real-UE MT INVITE template options
    target_msisdn: str | None = None
    impi: str | None = None
    mt_invite_template: str | None = None
    ipsec_mode: Literal["null", "bypass"] | None = None
    preserve_via: bool = False
    preserve_contact: bool = False
    mo_contact_host: str = "10.20.20.9"
    mo_contact_port_pc: int = Field(default=31800, ge=1, le=65535)
    mo_contact_port_ps: int = Field(default=31100, ge=1, le=65535)
    from_msisdn: str = "222222"
    mt_local_port: int = Field(default=15100, ge=1024, le=65535)

    @field_validator("methods", mode="before")
    @classmethod
    def _normalize_methods(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, str):
            value = value.split(",")
        return tuple(
            str(method).strip().upper() for method in value if str(method).strip()
        )

    @field_validator("response_codes", mode="before")
    @classmethod
    def _normalize_response_codes(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, str):
            value = value.split(",")

        codes = tuple(int(code) for code in value if str(code).strip())
        for code in codes:
            if code < 100 or code > 699:
                raise ValueError("response codes must be between 100 and 699")
        return codes

    @model_validator(mode="after")
    def _default_methods(self) -> Self:
        if not self.methods and not self.response_codes:
            object.__setattr__(self, "methods", ALL_SIP_METHODS)
        return self

    @model_validator(mode="after")
    def _validate_mt_invite_template(self) -> Self:
        # Auto-resolve target_host from target_msisdn for real-ue-direct mode
        if self.mode == "real-ue-direct":
            if self.target_host is None and self.target_msisdn is None:
                raise ValueError("real-ue-direct mode requires either target_host or target_msisdn")
            if self.target_host is None and self.target_msisdn is not None:
                from volte_mutation_fuzzer.sender.real_ue import resolve_ue_ip_from_msisdn
                try:
                    resolved_ip = resolve_ue_ip_from_msisdn(self.target_msisdn)
                    object.__setattr__(self, "target_host", resolved_ip)
                except ValueError as exc:
                    raise ValueError(
                        f"Failed to auto-resolve target_host from MSISDN {self.target_msisdn!r}: {exc}"
                    ) from exc

        if self.mt_invite_template is not None:
            if self.mode != "real-ue-direct":
                raise ValueError("mt_invite_template requires mode='real-ue-direct'")
            if self.target_msisdn is None:
                raise ValueError("mt_invite_template requires target_msisdn")
            if self.impi is None:
                raise ValueError("mt_invite_template requires impi")
            if self.ipsec_mode is None:
                object.__setattr__(self, "ipsec_mode", "null")
        return self


class CaseSpec(BaseModel):
    """Describes one test case to be executed by the campaign."""

    model_config = ConfigDict(extra="forbid")

    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str = Field(min_length=1)
    layer: str = Field(min_length=1)
    strategy: str = Field(min_length=1)
    response_code: int | None = Field(default=None, ge=100, le=699)
    related_method: str | None = None


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
    fuzz_response_code: int | None = None
    fuzz_related_method: str | None = None
    pcap_path: str | None = None


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
