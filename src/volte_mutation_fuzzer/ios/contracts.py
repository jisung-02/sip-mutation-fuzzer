from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.adb.contracts import AnomalyCategory, AnomalySeverity


class IosDeviceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    udid: str
    product_type: str | None = None
    product_version: str | None = None
    build_version: str | None = None
    device_name: str | None = None
    error: str | None = None


class IosCollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    udid: str | None = None


class IosSyslogLine(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_ts: float
    device_ts: str | None = None
    process: str = "unknown"
    level: str | None = None
    line: str = Field(max_length=2000)


class IosAnomalyEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: float
    severity: AnomalySeverity
    category: AnomalyCategory
    pattern_name: str
    matched_pattern: str
    matched_line: str = Field(max_length=500)
    process: str = "unknown"


class IosSnapshotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    syslog_path: str | None = None
    syslog_commcenter_path: str | None = None
    syslog_springboard_path: str | None = None
    crashes_dir: str | None = None
    new_crash_files: tuple[str, ...] = ()
    diagnostics_path: str | None = None
    anomalies_path: str | None = None
    errors: tuple[str, ...] = ()
