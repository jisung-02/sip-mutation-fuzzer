import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from volte_mutation_fuzzer.sip.common import NameAddress, SIPMethod, URIReference


class GeneratorSettings(BaseModel):
    """Environment-backed defaults consumed by the SIP generator service."""

    model_config = ConfigDict(extra="forbid")

    ENV_PREFIX: ClassVar[str] = "VMF_GENERATOR_"
    _INT_ENV_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "via_port",
            "from_port",
            "to_port",
            "request_uri_port",
            "contact_port",
        }
    )

    target_ue_name: str = Field(default="UE", min_length=1)
    via_host: str = Field(default="proxy.example.com", min_length=1)
    via_port: int | None = Field(default=5060, ge=1, le=65535)
    transport: str = Field(default="UDP", min_length=1)
    user_agent: str = Field(default="volte-mutation-fuzzer/0.1.0", min_length=1)

    from_display_name: str | None = "Remote"
    from_user: str = Field(default="remote", min_length=1)
    from_host: str = Field(default="example.com", min_length=1)
    from_port: int | None = Field(default=None, ge=1, le=65535)

    to_display_name: str | None = "UE"
    to_user: str = Field(default="ue", min_length=1)
    to_host: str = Field(default="example.com", min_length=1)
    to_port: int | None = Field(default=None, ge=1, le=65535)

    request_uri_user: str | None = "ue"
    request_uri_host: str = Field(default="example.com", min_length=1)
    request_uri_port: int | None = Field(default=None, ge=1, le=65535)

    contact_display_name: str | None = None
    contact_user: str | None = None
    contact_host: str | None = None
    contact_port: int | None = Field(default=None, ge=1, le=65535)

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        prefix: str | None = None,
    ) -> Self:
        """Load generator defaults from an env mapping or the process env."""

        source = cls._load_default_env() if env is None else env
        env_prefix = cls.ENV_PREFIX if prefix is None else prefix
        payload: dict[str, Any] = {}

        for field_name in cls.model_fields:
            env_key = f"{env_prefix}{field_name}".upper()
            raw_value = source.get(env_key)
            if raw_value is None:
                continue
            payload[field_name] = cls._parse_env_value(field_name, raw_value)

        # Pydantic BaseModel 내부 메서드이며, payload 검증과 최종 모델 인스턴스 생성을 함께 수행한다.
        return cls.model_validate(payload)

    @classmethod
    def _load_default_env(cls) -> Mapping[str, str]:
        source: dict[str, str] = {}
        source.update(cls._read_dotenv(Path(".env")))
        source.update(os.environ)
        return source

    @classmethod
    def _read_dotenv(cls, path: Path) -> dict[str, str]:
        if not path.is_file():
            return {}

        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                continue

            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue

            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values[key] = value

        return values

    @classmethod
    def _parse_env_value(cls, field_name: str, raw_value: str) -> Any:
        value = raw_value.strip()
        if value == "":
            return None
        if field_name in cls._INT_ENV_FIELDS:
            return int(value)
        return value

    @field_validator(
        "target_ue_name",
        "via_host",
        "transport",
        "user_agent",
        "from_display_name",
        "from_user",
        "from_host",
        "to_display_name",
        "to_user",
        "to_host",
        "request_uri_user",
        "request_uri_host",
        "contact_display_name",
        "contact_user",
        "contact_host",
        mode="before",
    )
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @field_validator("transport")
    @classmethod
    def _normalize_transport(cls, value: str) -> str:
        return value.upper()


class DialogContext(BaseModel):
    """State carried across related SIP messages within one dialog or flow."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    call_id: str | None = Field(default=None, min_length=1)
    local_tag: str | None = Field(default=None, min_length=1)
    remote_tag: str | None = Field(default=None, min_length=1)
    local_cseq: int = Field(default=0, ge=0, lt=2**31)
    remote_cseq: int = Field(default=0, ge=0, lt=2**31)
    route_set: tuple[NameAddress | URIReference, ...] = ()
    request_uri: URIReference | None = None
    is_registered: bool = False
    is_reinvite: bool = False

    @property
    def has_dialog(self) -> bool:
        return (
            self.call_id is not None
            and self.local_tag is not None
            and self.remote_tag is not None
        )

    def next_local_cseq(self) -> int:
        self.local_cseq += 1
        return self.local_cseq

    def next_remote_cseq(self) -> int:
        self.remote_cseq += 1
        return self.remote_cseq

    def fork_for_reinvite(self) -> Self:
        return self.model_copy(update={"is_reinvite": True})

    @field_validator("call_id", "local_tag", "remote_tag", mode="before")
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None


class RequestSpec(BaseModel):
    """Describes which SIP request the generator should produce."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    method: SIPMethod
    scenario: str | None = None
    body_kind: str | None = None
    event_package: str | None = None
    info_package: str | None = None
    sms_over_ip: bool = False
    overrides: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_overrides(self) -> bool:
        return bool(self.overrides)

    @field_validator(
        "scenario", "body_kind", "event_package", "info_package", mode="before"
    )
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @field_validator("overrides", mode="before")
    @classmethod
    def _coerce_overrides(cls, value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, Mapping):
            return dict(value)
        return value


class ResponseSpec(BaseModel):
    """Describes which SIP response the generator should produce."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    status_code: int = Field(ge=100, le=699)
    related_method: SIPMethod
    scenario: str | None = None
    event_package: str | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_overrides(self) -> bool:
        return bool(self.overrides)

    @field_validator("scenario", "event_package", mode="before")
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @field_validator("overrides", mode="before")
    @classmethod
    def _coerce_overrides(cls, value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, Mapping):
            return dict(value)
        return value
