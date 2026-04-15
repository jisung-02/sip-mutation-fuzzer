from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AnomalySeverity = Literal["critical", "warning", "info"]
AnomalyCategory = Literal[
    "fatal_signal", "ims_anomaly", "call_anomaly", "system_anomaly"
]


class AdbDeviceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str
    state: str
    model: str | None = None
    error: str | None = None


class AdbAnomalyEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: float
    severity: AnomalySeverity
    category: AnomalyCategory
    pattern_name: str
    matched_pattern: str
    matched_line: str = Field(max_length=500)
    buffer: str = "unknown"


class AdbCollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str | None = None
    buffers: tuple[str, ...] = ("main", "system", "radio", "crash")
    log_format: str = "time"


class AdbSnapshotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meminfo_path: str | None = None
    dmesg_path: str | None = None
    bugreport_path: str | None = None
    logcat_path: str | None = None
    telephony_path: str | None = None
    ims_path: str | None = None
    netstat_path: str | None = None
    errors: tuple[str, ...] = ()
