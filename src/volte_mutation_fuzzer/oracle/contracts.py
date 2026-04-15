from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal[
    "normal",
    "suspicious",
    "timeout",
    "crash",
    "stack_failure",
    "setup_failed",
    "infra_failure",
    "unknown",
]


class OracleContext(BaseModel):
    """Input context provided to the oracle for verdict computation."""

    model_config = ConfigDict(extra="forbid")

    method: str = Field(min_length=1)
    timeout_threshold_ms: float = Field(default=5000.0, gt=0.0)
    # Time window after receiving a transport response during which the
    # oracle keeps polling ADB/iOS log collectors for delayed anomalies
    # (e.g. asynchronous IMS service crashes that surface seconds after
    # the 200 OK).  Zero disables the grace window.
    log_grace_seconds: float = Field(default=0.0, ge=0.0, le=30.0)
    log_grace_poll_seconds: float = Field(default=0.5, gt=0.0, le=5.0)


class ProcessCheckResult(BaseModel):
    """Result of checking whether the target process is alive."""

    model_config = ConfigDict(extra="forbid")

    process_name: str = Field(min_length=1)
    alive: bool
    pid: int | None = None
    check_time: float
    error: str | None = None


class LogCheckResult(BaseModel):
    """Result of scanning a log file for stack trace patterns."""

    model_config = ConfigDict(extra="forbid")

    log_path: str
    matched: bool
    matched_pattern: str | None = None
    matched_line: str | None = None
    lines_scanned: int = 0
    error: str | None = None


class OracleVerdict(BaseModel):
    """Final oracle judgment for a single test case."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str
    response_code: int | None = None
    elapsed_ms: float
    process_alive: bool | None = None
    details: dict[str, object] = Field(default_factory=dict)
