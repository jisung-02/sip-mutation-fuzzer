import os
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
    max_cases: int = Field(default=1000, ge=0)
    timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    cooldown_seconds: float = Field(default=0.2, ge=0.0, le=10.0)
    seed_start: int = Field(default=0, ge=0)
    results_dir: str = Field(default="results", min_length=1)
    output_name: str | None = Field(default=None)
    crash_analysis: bool = False
    process_name: str = Field(default="baresip", min_length=1)
    check_process: bool | None = None
    log_path: str | None = None
    adb_enabled: bool | None = None
    adb_serial: str | None = None
    adb_buffers: tuple[str, ...] = ("main", "system", "radio", "crash")
    ios_enabled: bool = False
    ios_udid: str | None = None
    ios_filter_processes: tuple[str, ...] = (
        "CommCenter",
        "SpringBoard",
        "identityservicesd",
        "imagent",
        "ReportCrash",
        "launchd",
    )
    ios_run_diagnostics: bool = False
    pcap_enabled: bool | None = None
    pcap_interface: str = "any"

    # Real-UE MT INVITE template options
    target_msisdn: str | None = None
    impi: str | None = None
    mt: bool = False
    mt_invite_template: str | None = None
    ipsec_mode: Literal["null", "bypass", "native", "ipsec"] | None = None
    preserve_via: bool = False
    preserve_contact: bool = False
    mo_contact_host: str = "10.20.20.9"
    mo_contact_port_pc: int = Field(default=31800, ge=1, le=65535)
    mo_contact_port_ps: int = Field(default=31100, ge=1, le=65535)
    from_msisdn: str = "222222"
    mt_local_port: int = Field(default=15100, ge=1024, le=65535)
    resume: bool = False
    circuit_breaker_threshold: int = Field(default=10, ge=0)
    # Oracle post-response grace window (seconds) during which ADB/iOS log
    # collectors are re-polled for delayed anomalies. The field keeps the
    # legacy mode default for compatibility; the helper applies the
    # method-aware policy. ``None`` means "pick the default".
    oracle_log_grace_seconds: float | None = Field(default=None, ge=0.0, le=30.0)

    # Internal fields derived from ipsec_mode (set by model_validator)
    source_ip: str | None = None
    bind_container: str | None = None

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
    def _apply_oracle_defaults(self) -> Self:
        """오라클 기본값을 모드에 따라 자동 설정한다.

        None(미지정)인 필드만 덮어쓴다. 사용자가 명시적으로 True/False를
        지정한 경우에는 그 값을 존중한다.
        """
        if self.mode == "real-ue-direct":
            if self.check_process is None:
                object.__setattr__(self, "check_process", False)
            if self.adb_enabled is None:
                object.__setattr__(self, "adb_enabled", True)
            if self.pcap_enabled is None:
                object.__setattr__(self, "pcap_enabled", True)
            if self.pcap_interface == "any":
                object.__setattr__(self, "pcap_interface", "br-volte")
        else:
            # softphone 모드: 기존 기본값 유지
            if self.check_process is None:
                object.__setattr__(self, "check_process", True)
            if self.adb_enabled is None:
                object.__setattr__(self, "adb_enabled", False)
            if self.pcap_enabled is None:
                object.__setattr__(self, "pcap_enabled", False)
        return self

    def oracle_log_grace_seconds_for_method(self, method: str) -> float:
        if (
            "oracle_log_grace_seconds" in self.model_fields_set
            and self.oracle_log_grace_seconds is not None
        ):
            return float(self.oracle_log_grace_seconds)

        if self.mode != "real-ue-direct":
            return 0.0

        normalized_method = method.strip().upper()
        if normalized_method == "INVITE":
            return 8.0
        if normalized_method in {
            "ACK",
            "CANCEL",
            "PRACK",
            "BYE",
            "UPDATE",
            "REFER",
            "INFO",
        }:
            return 2.0
        return 1.0

    @model_validator(mode="after")
    def _validate_mt_invite_template(self) -> Self:
        # real-ue-direct: target_host는 None 허용 — RealUEDirectResolver가 동적 resolve
        if self.mode == "real-ue-direct":
            if self.target_host is None and self.target_msisdn is None:
                raise ValueError("real-ue-direct mode requires either target_host or target_msisdn")
            if self.ipsec_mode == "native" and self.target_msisdn is None:
                raise ValueError(
                    "native ipsec_mode requires target_msisdn in real-ue-direct mode"
                )

        # IMPI fallback: 환경변수 VMF_IMPI
        if self.impi is None:
            env_impi = os.environ.get("VMF_IMPI")
            if env_impi:
                object.__setattr__(self, "impi", env_impi)

        if self.ipsec_mode == "ipsec":
            object.__setattr__(self, "ipsec_mode", "native")

        # --mt flag: auto-set mt_invite_template and preserve flags
        if self.mt and self.mt_invite_template is None:
            object.__setattr__(self, "mt_invite_template", "3gpp")
        if self.mt and self.ipsec_mode != "native":
            object.__setattr__(self, "preserve_via", True)
            object.__setattr__(self, "preserve_contact", True)

        if self.mt_invite_template is not None:
            if self.mode != "real-ue-direct":
                raise ValueError("mt_invite_template requires mode='real-ue-direct'")
            if self.target_msisdn is None:
                raise ValueError("mt_invite_template requires target_msisdn")
            if self.ipsec_mode is None:
                object.__setattr__(self, "ipsec_mode", "null")

        # Convert ipsec_mode to internal fields for TargetEndpoint
        if self.ipsec_mode == "null":
            # null encryption mode: send from pcscf container netns as plaintext UDP
            object.__setattr__(self, "source_ip", None)
            object.__setattr__(self, "bind_container", "pcscf")
        elif self.ipsec_mode == "bypass":
            # xfrm bypass mode: docker exec
            object.__setattr__(self, "source_ip", None)
            object.__setattr__(self, "bind_container", "pcscf")
        elif self.ipsec_mode == "native":
            if self.mode != "real-ue-direct":
                raise ValueError("native ipsec_mode requires mode='real-ue-direct'")
            if str(self.transport).upper() != "UDP":
                raise ValueError("native ipsec_mode requires transport='UDP'")
            if self.target_msisdn is None:
                raise ValueError(
                    "native ipsec_mode requires target_msisdn in real-ue-direct mode"
                )
            object.__setattr__(self, "source_ip", None)
            object.__setattr__(self, "bind_container", "pcscf")

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
    details: dict[str, object] = Field(default_factory=dict)
    timestamp: float
    fuzz_response_code: int | None = None
    fuzz_related_method: str | None = None
    pcap_path: str | None = None
    case_wall_ms: float | None = None


class CampaignSummary(BaseModel):
    """Aggregate statistics for a campaign."""

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    normal: int = 0
    suspicious: int = 0
    timeout: int = 0
    crash: int = 0
    stack_failure: int = 0
    infra_failure: int = 0
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
