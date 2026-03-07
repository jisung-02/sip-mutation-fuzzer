from __future__ import annotations

from volte_mutation_fuzzer.sip import SIP_CATALOG
from volte_mutation_fuzzer.sip.common import StatusClass


def main() -> None:
    response_counts = SIP_CATALOG.grouped_response_counts()
    print(
        "SIP catalog ready: "
        f"{SIP_CATALOG.request_count} requests, "
        f"{SIP_CATALOG.response_count} responses "
        f"(1xx={response_counts[StatusClass.INFORMATIONAL]}, "
        f"2xx={response_counts[StatusClass.SUCCESS]}, "
        f"3xx={response_counts[StatusClass.REDIRECTION]}, "
        f"4xx={response_counts[StatusClass.CLIENT_ERROR]}, "
        f"5xx={response_counts[StatusClass.SERVER_ERROR]}, "
        f"6xx={response_counts[StatusClass.GLOBAL_FAILURE]})"
    )
