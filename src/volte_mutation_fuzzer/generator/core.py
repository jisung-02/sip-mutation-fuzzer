from __future__ import annotations

from typing import Any

from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD, SIPRequest
from volte_mutation_fuzzer.sip.responses import SIPResponse


class SIPGenerator:
    """Orchestrates request/response model generation from generator contracts."""

    def __init__(
        self,
        settings: GeneratorSettings,
        *,
        catalog: SIPCatalog | None = None,
    ) -> None:
        self.settings = settings
        self.catalog = SIP_CATALOG if catalog is None else catalog

    def generate_request(
        self,
        spec: RequestSpec,
        context: DialogContext | None = None,
    ) -> SIPRequest:
        raise NotImplementedError("request generation is not implemented yet")

    def generate_response(
        self,
        spec: ResponseSpec,
        context: DialogContext,
    ) -> SIPResponse:
        raise NotImplementedError("response generation is not implemented yet")

    def _resolve_request_model(self, spec: RequestSpec) -> type[SIPRequest]:
        try:
            definition = self.catalog.get_request(spec.method)
        except StopIteration as exc:
            raise ValueError(
                f"request method {spec.method} is not present in the SIP catalog"
            ) from exc

        try:
            model = REQUEST_MODELS_BY_METHOD[spec.method]
        except KeyError as exc:
            raise ValueError(
                f"request method {spec.method} does not have a registered SIP model"
            ) from exc

        if model.__name__ != definition.model_name:
            raise ValueError(
                f"request model mismatch for {spec.method}: "
                f"catalog expects {definition.model_name}, "
                f"mapping provides {model.__name__}"
            )

        return model

    def _resolve_response_model(self, spec: ResponseSpec) -> type[SIPResponse]:
        raise NotImplementedError

    def _build_request_defaults(
        self,
        spec: RequestSpec,
        context: DialogContext | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def _build_response_defaults(
        self,
        spec: ResponseSpec,
        context: DialogContext,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def _apply_overrides(
        self,
        defaults: dict[str, Any],
        overrides: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError

    def _validate_preconditions(
        self,
        *,
        context: DialogContext | None,
        preconditions: tuple[str, ...],
    ) -> None:
        raise NotImplementedError
