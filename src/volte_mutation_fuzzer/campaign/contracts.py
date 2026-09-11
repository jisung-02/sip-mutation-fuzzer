import os
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from volte_mutation_fuzzer.mutator.profile_catalog import (
    SUPPORTED_STRATEGIES_BY_LAYER,
    normalize_profile_name,
)
from volte_mutation_fuzzer.sip.common import SIPMethod

ALL_SIP_METHODS = tuple(method.value for method in SIPMethod)
_PACKET_FILE_DEFAULT_STRATEGIES = ("default", "state_breaker")
_CORPUS_DEFAULT_STRATEGIES = ("default", "state_breaker")
# Only these extensions are scanned when a corpus directory is loaded. Hidden
# files (e.g. macOS .DS_Store) and unrelated sidecars are skipped so a polluted
# directory cannot inject garbage seeds or break start-line method parsing.
CORPUS_FILE_SUFFIXES: frozenset[str] = frozenset({".sip", ".bin", ".bytes", ".txt"})


def _parse_packet_file_method(packet_path: Path) -> str:
    with packet_path.open("rb") as fh:
        first_line = fh.readline(4096)

    parts = first_line.strip().split(maxsplit=1)
    method = parts[0].decode("ascii", errors="ignore").upper() if parts else ""
    if method not in ALL_SIP_METHODS:
        raise ValueError(
            "packet_file start-line must be a SIP request line with a supported method"
        )
    return method


class CorpusEntry(BaseModel):
    """One raw seed packet loaded from a corpus directory."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    method: str = Field(min_length=1)
    data: bytes


def load_corpus_entries(corpus_dir: Path) -> tuple[CorpusEntry, ...]:
    """Load every recognized packet file under ``corpus_dir`` as a seed.

    Files are processed in name order so entry indices (and therefore
    seed-derived selection) are stable across runs and machines. Each file must
    start with a supported SIP request line; an empty or unparsable file is an
    error naming the offending file rather than a silent skip — a half-loaded
    corpus would silently change which seeds a given seed value selects.
    """
    entries: list[CorpusEntry] = []
    files = sorted(
        path
        for path in corpus_dir.iterdir()
        if path.is_file()
        and not path.name.startswith(".")
        and path.suffix.lower() in CORPUS_FILE_SUFFIXES
    )
    for path in files:
        data = path.read_bytes()
        if not data:
            raise ValueError(f"corpus file is empty: {path.name}")
        try:
            method = _parse_packet_file_method(path)
        except ValueError as exc:
            raise ValueError(f"corpus file rejected ({exc}): {path.name}") from exc
        entries.append(CorpusEntry(name=path.name, method=method, data=data))
    if not entries:
        raise ValueError(
            f"corpus_dir contains no packet files ({', '.join(sorted(CORPUS_FILE_SUFFIXES))}): {corpus_dir}"
        )
    return tuple(entries)


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
    profiles: tuple[str, ...] = ("legacy",)
    strategies: tuple[str, ...] = ("default", "state_breaker")
    layers: tuple[str, ...] = ("model", "wire", "byte")
    max_cases: int = Field(default=1000, ge=0)
    # Number of mutation rounds applied per case. Default 1 = single-shot
    # (legacy behaviour). >1 stacks deterministic strategies (null_byte_only,
    # boundary_only, byte_edit_only) so a single packet carries N mutations.
    mutations_per_case: int = Field(default=1, ge=1, le=100)
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
    ios_run_diagnostics: bool = False
    pcap_enabled: bool | None = None
    pcap_interface: str = "any"

    # Real-UE MT packet options
    target_msisdn: str | None = None
    impi: str | None = None
    mt: bool = False
    # Path to a file containing a complete SIP packet to send verbatim. Read as
    # raw bytes (null-byte safe). Mutually exclusive with --mt.
    # Bypasses generator + slot substitution; bytes flow straight to the sender.
    packet_file: str | None = None
    # Path to a directory of seed packets (captured or promoted from
    # interesting cases). Each case mutates one corpus entry at the byte layer
    # instead of generating a fresh packet, so campaigns can build on real
    # traffic and on previously-anomalous inputs. Mutually exclusive with
    # --mt and --packet-file.
    corpus_dir: str | None = None
    ipsec_mode: Literal["null", "bypass", "native"] | None = None
    preserve_via: bool = False
    preserve_contact: bool = False
    pixel_mode: bool = False
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
    # Extra seconds to keep ADB/iOS log collectors running after the last
    # case finishes.  Activated automatically when ``oracle_log_grace_seconds``
    # is set below the default INVITE grace (8 s) so that async crashes that
    # would have been caught by per-case polling are still visible in the full
    # logcat.  Explicitly set to 0 to disable.
    post_campaign_log_grace_seconds: float = Field(default=0.0, ge=0.0, le=60.0)
    # Max seconds to wait for UE call state to return to IDLE between INVITE
    # cases.  Set to 0 to skip idle waiting entirely (useful for high-rate
    # campaigns where back-pressure from the previous call is intentional).
    wait_idle_timeout_seconds: float = Field(default=10.0, ge=0.0, le=60.0)
    # Send a CANCEL to tear down each INVITE after a provisional response.
    # On by default so campaigns don't leave the UE ringing. Set False to let
    # the call actually alert/ring — useful for baseline "does it ring" checks.
    invite_teardown: bool = True
    # Runtime feedback: promote interesting-case payloads into
    # <campaign_dir>/corpus/ as they happen, and let corpus cases continue
    # mutating the most recent promoted seed (last-seed continuation).
    feedback_enabled: bool = True
    # Sequence mode: run a cataloged multi-message state-attack scenario
    # (retransmit, early/double teardown) instead of the per-method loop.
    sequence_scenario: str | None = None
    # Overrides the repeat count of repeated steps in the sequence scenario
    # (retransmission pressure).
    sequence_repeats: int = Field(default=2, ge=1, le=10)

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

    @field_validator("profiles", mode="before")
    @classmethod
    def _normalize_profiles(cls, value: Any) -> Any:
        if value is None:
            return ("legacy",)
        if isinstance(value, str):
            value = value.split(",")

        normalized: list[str] = []
        for item in value:
            stripped = str(item).strip()
            normalized_name = normalize_profile_name(stripped)
            if normalized_name not in normalized:
                normalized.append(normalized_name)
        return tuple(normalized or ("legacy",))

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
    def _validate_mt_packet_mode(self) -> Self:
        # real-ue-direct: target_host는 None 허용 — RealUEDirectResolver가 동적 resolve
        if self.mode == "real-ue-direct":
            if self.target_host is None and self.target_msisdn is None:
                raise ValueError(
                    "real-ue-direct mode requires either target_host or target_msisdn"
                )
            if self.ipsec_mode == "native" and self.target_msisdn is None:
                raise ValueError(
                    "native ipsec_mode requires target_msisdn in real-ue-direct mode"
                )

        # IMPI fallback: 환경변수 VMF_IMPI
        if self.impi is None:
            env_impi = os.environ.get("VMF_IMPI")
            if env_impi:
                object.__setattr__(self, "impi", env_impi)

        if self.mt and self.ipsec_mode != "native":
            object.__setattr__(self, "preserve_via", True)
            object.__setattr__(self, "preserve_contact", True)

        if self.mt:
            if self.mode != "real-ue-direct":
                raise ValueError("--mt requires mode='real-ue-direct'")
            if self.target_msisdn is None:
                raise ValueError("--mt requires target_msisdn")
            if self.ipsec_mode is None:
                object.__setattr__(self, "ipsec_mode", "null")

        if self.packet_file is not None:
            if self.mt:
                raise ValueError("packet_file is mutually exclusive with --mt")
            if self.mode != "real-ue-direct":
                raise ValueError("packet_file requires mode='real-ue-direct'")
            if self.target_msisdn is None:
                raise ValueError("packet_file requires target_msisdn")
            packet_path = Path(self.packet_file)
            if not packet_path.is_file():
                raise ValueError(
                    f"packet_file not found or not a regular file: {self.packet_file}"
                )
            packet_method = _parse_packet_file_method(packet_path)
            if self.response_codes:
                raise ValueError("packet_file does not support response_codes")
            if "layers" not in self.model_fields_set:
                object.__setattr__(self, "layers", ("byte",))
            else:
                if set(self.layers) - {"byte", "auto"}:
                    raise ValueError("packet_file supports layers: byte, auto")
                if "auto" in self.layers:
                    object.__setattr__(
                        self,
                        "layers",
                        tuple(layer for layer in self.layers if layer != "auto")
                        or ("byte",),
                    )

            if (
                "strategies" not in self.model_fields_set
                and self.strategies == _PACKET_FILE_DEFAULT_STRATEGIES
            ):
                object.__setattr__(self, "strategies", ("identity",))
            elif self.strategies != ("identity",):
                raise ValueError("packet_file supports only identity strategy")

            if not self.methods or self.methods == ALL_SIP_METHODS:
                object.__setattr__(self, "methods", (packet_method,))
            elif len(self.methods) != 1:
                raise ValueError("packet_file supports exactly one method")
            elif self.methods[0] != packet_method:
                raise ValueError(
                    "packet_file method must match file start-line "
                    f"({self.methods[0]} != {packet_method})"
                )
            if self.ipsec_mode is None:
                object.__setattr__(self, "ipsec_mode", "null")

        if self.corpus_dir is not None:
            byte_strategies = SUPPORTED_STRATEGIES_BY_LAYER["byte"]
            if self.mt:
                raise ValueError("corpus_dir is mutually exclusive with --mt")
            if self.packet_file is not None:
                raise ValueError("corpus_dir is mutually exclusive with --packet-file")
            if self.mode != "real-ue-direct":
                raise ValueError("corpus_dir requires mode='real-ue-direct'")
            if self.target_msisdn is None:
                raise ValueError("corpus_dir requires target_msisdn")
            corpus_path = Path(self.corpus_dir)
            if not corpus_path.is_dir():
                raise ValueError(
                    f"corpus_dir not found or not a directory: {self.corpus_dir}"
                )
            entries = load_corpus_entries(corpus_path)
            if self.response_codes:
                raise ValueError("corpus_dir does not support response_codes")

            # Corpus entries are raw bytes with no backing PacketModel, so only
            # the byte layer can mutate them (same constraint as --packet-file,
            # but mutation itself is allowed and is the whole point).
            if "layers" not in self.model_fields_set:
                object.__setattr__(self, "layers", ("byte",))
            else:
                if set(self.layers) - {"byte", "auto"}:
                    raise ValueError("corpus_dir supports layers: byte, auto")
                if "auto" in self.layers:
                    object.__setattr__(
                        self,
                        "layers",
                        tuple(layer for layer in self.layers if layer != "auto")
                        or ("byte",),
                    )

            if (
                "strategies" not in self.model_fields_set
                and self.strategies == _CORPUS_DEFAULT_STRATEGIES
            ):
                object.__setattr__(self, "strategies", ("default",))
            else:
                unsupported = tuple(
                    strategy
                    for strategy in self.strategies
                    if strategy not in byte_strategies
                )
                if unsupported:
                    raise ValueError(
                        "corpus_dir supports byte-layer strategies only "
                        f"({', '.join(sorted(byte_strategies))}); "
                        f"unsupported: {', '.join(unsupported)}"
                    )

            # Methods: default to the methods present in the corpus; an
            # explicit list must be a subset so every case can resolve a seed.
            corpus_methods = tuple(dict.fromkeys(entry.method for entry in entries))
            if not self.methods or self.methods == ALL_SIP_METHODS:
                object.__setattr__(self, "methods", corpus_methods)
            else:
                missing = tuple(
                    method for method in self.methods if method not in corpus_methods
                )
                if missing:
                    raise ValueError(
                        f"corpus_dir has no seed for method(s): {', '.join(missing)} "
                        f"(available: {', '.join(corpus_methods)})"
                    )

            if self.ipsec_mode is None:
                object.__setattr__(self, "ipsec_mode", "null")

        # Splice crosses two seed buffers; only corpus mode can supply the
        # second one. Reject it everywhere else so generator-path campaigns
        # fail at config time instead of emitting error cases at run time.
        if self.corpus_dir is None and "splice" in self.strategies:
            raise ValueError(
                "strategy 'splice' requires --corpus-dir (it crosses two corpus seeds)"
            )

        if self.sequence_scenario is not None:
            from volte_mutation_fuzzer.dialog.sequence_catalog import (
                build_sequence_scenario,
            )

            if self.mt or self.packet_file is not None or self.corpus_dir is not None:
                raise ValueError(
                    "sequence_scenario is mutually exclusive with --mt, --packet-file,"
                    " and --corpus-dir"
                )
            if self.response_codes:
                raise ValueError("sequence_scenario does not support response_codes")
            # Validates the name and raises with the available list on typos.
            scenario = build_sequence_scenario(
                self.sequence_scenario, repeat_override=self.sequence_repeats
            )
            del scenario
            if self.methods != ("INVITE",):
                raise ValueError(
                    "sequence_scenario campaigns run with --methods INVITE only"
                )

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
            if str(self.transport).upper() not in ("UDP", "TCP"):
                raise ValueError("native ipsec_mode requires transport='UDP' or 'TCP'")
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
    profile: str = Field(default="legacy", min_length=1)
    layer: str = Field(min_length=1)
    strategy: str = Field(min_length=1)
    response_code: int | None = Field(default=None, ge=100, le=699)
    related_method: str | None = None

    @field_validator("profile", mode="before")
    @classmethod
    def _normalize_profile(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return normalize_profile_name(value)


class CaseResult(BaseModel):
    """Result of executing a single test case, including oracle verdict."""

    model_config = ConfigDict(extra="forbid")

    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str
    profile: str = Field(default="legacy", min_length=1)
    layer: str
    strategy: str
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)
    verdict: str
    reason: str
    response_code: int | None = None
    elapsed_ms: float
    process_alive: bool | None = None
    raw_request: str | None = None
    raw_response: str | None = None
    reproduction_cmd: str
    error: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
    timestamp: float
    fuzz_response_code: int | None = None
    fuzz_related_method: str | None = None
    pcap_path: str | None = None
    case_wall_ms: float | None = None

    @field_validator("profile", mode="before")
    @classmethod
    def _normalize_profile(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return normalize_profile_name(value)


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
