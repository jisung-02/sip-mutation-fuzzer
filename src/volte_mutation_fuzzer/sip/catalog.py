from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.common import SIPMethod, StatusClass
from volte_mutation_fuzzer.sip.requests import (
    REQUEST_DEFINITIONS,
    REQUEST_MODELS_BY_METHOD,
    SIPRequestDefinition,
)
from volte_mutation_fuzzer.sip.responses import (
    RESPONSE_DEFINITIONS,
    RESPONSE_MODELS_BY_CODE,
    SIPResponseDefinition,
)


class SIPCatalog(BaseModel):
    """Phase 1 structured catalog built from the SIP classification document.

    Runtime packet models live in requests.py / responses.py and are exposed together
    with machine-readable packet definitions for later generator/mutator phases.
    """

    model_config = ConfigDict(extra="forbid")

    request_definitions: tuple[SIPRequestDefinition, ...] = Field(
        default=REQUEST_DEFINITIONS
    )
    response_definitions: tuple[SIPResponseDefinition, ...] = Field(
        default=RESPONSE_DEFINITIONS
    )

    @property
    def request_count(self) -> int:
        return len(self.request_definitions)

    @property
    def response_count(self) -> int:
        return len(self.response_definitions)

    def get_request(self, method: SIPMethod) -> SIPRequestDefinition:
        return next(defn for defn in self.request_definitions if defn.method == method)

    def get_response(self, status_code: int) -> SIPResponseDefinition:
        return next(
            defn
            for defn in self.response_definitions
            if defn.status_code == status_code
        )

    def grouped_response_counts(self) -> dict[StatusClass, int]:
        counts = {status_class: 0 for status_class in StatusClass}
        for definition in self.response_definitions:
            counts[definition.status_class] += 1
        return counts

    def request_json_schemas(self) -> dict[SIPMethod, dict[str, object]]:
        return {
            method: model.model_json_schema()
            for method, model in REQUEST_MODELS_BY_METHOD.items()
        }

    def response_json_schemas(self) -> dict[int, dict[str, object]]:
        return {
            code: model.model_json_schema()
            for code, model in RESPONSE_MODELS_BY_CODE.items()
        }


SIP_CATALOG = SIPCatalog()


def validate_catalog_counts() -> None:
    if len(REQUEST_MODELS_BY_METHOD) != 14 or SIP_CATALOG.request_count != 14:
        raise ValueError("SIP request catalog must contain exactly 14 methods")
    if len(RESPONSE_MODELS_BY_CODE) != 75 or SIP_CATALOG.response_count != 75:
        raise ValueError("SIP response catalog must contain exactly 75 response codes")


validate_catalog_counts()


__all__ = [
    "REQUEST_DEFINITIONS",
    "RESPONSE_DEFINITIONS",
    "SIPCatalog",
    "SIP_CATALOG",
    "validate_catalog_counts",
]
