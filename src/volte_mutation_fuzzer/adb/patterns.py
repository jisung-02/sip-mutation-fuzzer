import re

from volte_mutation_fuzzer.adb.contracts import AnomalyCategory, AnomalySeverity


class AnomalyPattern:
    def __init__(
        self,
        name: str,
        regex: str,
        severity: AnomalySeverity,
        category: AnomalyCategory,
    ) -> None:
        self.name = name
        self.regex = regex
        self.severity = severity
        self.category = category
        self.compiled = re.compile(regex, re.IGNORECASE)


ANOMALY_PATTERNS: tuple[AnomalyPattern, ...] = (
    # ---------------------------------------------------------------------
    # Native (libc/kernel-delivered) crashes -- pid terminated by signal,
    # or native runtime abort paths.  These are unambiguous "process died"
    # signals on Android.
    # ---------------------------------------------------------------------
    AnomalyPattern("SIGSEGV", r"SIGSEGV|signal 11\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGABRT", r"SIGABRT|signal 6\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGBUS", r"SIGBUS|signal 7\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGILL", r"SIGILL|signal 4\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGFPE", r"SIGFPE|signal 8\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGSYS", r"SIGSYS|signal 31\b", "critical", "fatal_signal"),
    AnomalyPattern("SIGTRAP", r"SIGTRAP|signal 5\b", "critical", "fatal_signal"),
    AnomalyPattern(
        "tombstone",
        r"tombstone.*written|Tombstone written|/data/tombstones/tombstone_",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "native_crash",
        r"Fatal signal|DEBUG\s*:.*\*\*\*|>>> .* <<<",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "libc_abort",
        r"libc\s*:\s*(?:FORTIFY|Fatal|Stack-Protector)|stack corruption detected|__stack_chk_fail",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "heap_corruption",
        r"Scudo\s+ERROR|scudo:.*corrupt|heap corruption|double free|use after free",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "assertion_failure",
        r"\bassertion failure\b|Assertion failed|CHECK failed|LOG\(FATAL\)",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "sanitizer_report",
        r"(?:Asan|ASan|HWAddressSanitizer|UBSan|MSan|LeakSanitizer|KASAN|KFENCE).*ERROR|AddressSanitizer:",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "kernel_panic",
        r"Kernel panic|panic -.*not syncing|Oops:|BUG:|WARN_ON|general protection fault",
        "critical",
        "fatal_signal",
    ),

    # ---------------------------------------------------------------------
    # Java / ART unhandled exceptions (surface as AndroidRuntime lines).
    # Samsung's ``com.sec.imsservice`` dies this way, not via SIGSEGV,
    # so the native patterns above miss it.
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "android_runtime_fatal",
        r"AndroidRuntime.*FATAL EXCEPTION|FATAL EXCEPTION:\s",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "uncaught_java_exception",
        r"java\.lang\.\w*Exception|java\.lang\.\w*Error(?!\s*=)|"
        r"java\.util\.\w*Exception|kotlin\.\w*Exception",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "art_aborting",
        r"art\s*:\s*(?:Runtime aborting|ArtMethod.*abort)|Throwing\s+[A-Z]\w+Exception",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "dropbox_crash_tag",
        r"DropBoxManagerService:.*(?:system_app_crash|system_server_crash|data_app_crash|SYSTEM_TOMBSTONE)",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "anr_not_responding",
        r"ANR in\s+\S+|Application Not Responding|anr_not_responding",
        "warning",
        "fatal_signal",
    ),

    # ---------------------------------------------------------------------
    # Modem / RIL / baseband
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "modem_crash",
        r"modem.*(?:crash|crashed|reset|reboot|ramdump)|CBD.*crash|CP\s+crash|ModemRecovery|qmimsa.*restart",
        "critical",
        "call_anomaly",
    ),
    AnomalyPattern(
        "oem_ril_crash",
        r"oem.*ril.*(?:crash|restart|died)|"
        r"(?:vendor\.)?ril-daemon.*(?:died|killed|restart)|"
        r"rild.*(?:died|killed|restart)|RILD.*crash",
        "critical",
        "call_anomaly",
    ),
    AnomalyPattern(
        # Real RIL failures expose themselves with explicit uppercase failure
        # tokens (GENERIC_FAILURE, REQUEST_NOT_SUPPORTED, NO_RESOURCES, ...)
        # or with the ``Exception``/``Error`` *class names* suffixed to
        # ``RILJ:``/``SecRIL:`` log tags. The previous regex
        # ``oem.*ril.*error|RILJ.*Error|SecRIL.*(?:error|Error)`` matched
        # case-insensitively, so any line containing ``error: 0`` (e.g. the
        # routine ``RILJ: processResponse: Unexpected response! serial: N,
        # error: 0 [PHONE0]`` modem-stale-response notice that bursts
        # background-noise-style every few minutes on A16) ended up flagged
        # as a critical RIL failure. That drowned every campaign in
        # stack_failure FPs. Tighten the alternation so only genuine RIL
        # failure tokens trip critical, and downgrade the bare
        # "Unexpected response" tracker to a separate warning pattern
        # below.
        "oem_ril_error",
        r"oem[_ -]ril[_ -]error\b"
        r"|RILJ:\s*\S*(?:_FAILURE|_FAILED|_ERROR|EXCEPTION|REQUEST_NOT_SUPPORTED|NO_RESOURCES|SECURITY_FAILURE|GENERIC_FAILURE)\b"
        r"|SecRIL.*\b(?:Exception|FAILURE|FAILED)\b"
        r"|RIL[Dd][_ -]?(?:died|killed|crash|crashed)\b"
        r"|rild[_ -]?(?:died|killed|crash|crashed)\b",
        "critical",
        "call_anomaly",
    ),
    AnomalyPattern(
        # Bare RILJ transaction-tracker-out-of-sync notice. Modem-side
        # stale responses, batch-processed every few minutes regardless of
        # what the IMS service is doing, so on its own it is **noise**.
        # Keep it visible at warning severity so deeper analysis can still
        # correlate it against suspicious cases, but never let it raise
        # the verdict to stack_failure on its own.
        "rilj_unexpected_response",
        r"RILJ\b.*processResponse:\s*Unexpected response",
        "warning",
        "call_anomaly",
    ),
    AnomalyPattern(
        "ril_request_timeout",
        r"RIL.*request.*timeout|RILJ.*TIMED_OUT",
        "warning",
        "call_anomaly",
    ),
    AnomalyPattern(
        "baseband_reset",
        r"Baseband Reset|baseband.*reset|Subsystem.*restart|SSR.*triggered|mba.*crash",
        "critical",
        "call_anomaly",
    ),
    AnomalyPattern(
        "sim_error",
        r"SIM.*(?:absent|error|removed|STATE_LOADED\s*->\s*ABSENT)",
        "warning",
        "call_anomaly",
    ),

    # ---------------------------------------------------------------------
    # IMS / VoLTE / SIP / PDN
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "ims_service_crash",
        r"(?:com\.sec\.imsservice|com\.android\.ims|imsrcs).*(?:crash|died|killed)",
        "critical",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_deregistration",
        r"IMS.*(?:deregist|DEREGIST)|imsRegistered.*false",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        # NOTE: 401 Unauthorized and 403 Forbidden are normal IMS
        # authentication-challenge responses, not failure indicators.
        # Only flag explicit registration-failure log markers.
        "ims_reg_failure",
        r"IMS.*(?:registration.*fail|reg.*fail|REGISTER_FAILURE|RegistrationFailed)"
        r"|REGISTRATION.*(?:ABORTED|TERMINATED)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_registered",
        r"IMS.*(?:registered|REGISTERED)",
        "info",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "pdn_disconnect",
        r"PDN.*(?:disconnect|lost|deactivat)|EPSBearer.*(?:release|deactivated)|APN.*teardown",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "sip_parse_error",
        r"SIP.*(?:parse error|malformed|invalid message|unexpected token)|SipMsg.*(?:invalid|corrupt)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "sip_timeout",
        r"SIP.*(?:408 Request Timeout|Transaction timeout|timer\s+[BFH]\s*fired)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        # 4xx / 5xx from the network. The negative lookbehind for "[-->] "
        # excludes Samsung SIPMSG outbound-echo lines where A16 is just
        # logging the rejection it itself sent in response to our fuzz —
        # those are NOT device-side errors, just our own 4xx/5xx
        # round-tripping back through the IMS log. We anchor on the
        # "SIP/2.0 " prefix so the lookbehind has a single, well-defined
        # position to evaluate (avoid the regex engine scanning past the
        # arrow and matching at "500 Server..." offset).
        "sip_server_error",
        r"(?<!\[-->\] )SIP/2\.0\s+[45]\d\d",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "unexpected_disconnect",
        r"(?:call|CALL).*(?:disconnect|DROP).*unexpected|CallEnded.*reason=\d+.*unknown",
        "warning",
        "call_anomaly",
    ),

    # ---------------------------------------------------------------------
    # System-level service / watchdog / resource pressure
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "system_server_restart",
        r"system_server.*(?:restart|crash|died|WATCHDOG|killed by)|Watchdog.*killing system_server",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "watchdog_hang",
        r"Watchdog.*(?:HANG|hang detected|blocked)|lockup detected on CPU",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "telephony_crash",
        r"(?:com\.android\.phone|telephony).*(?:crash|died|killed|restart)",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "bluetooth_crash",
        r"com\.android\.bluetooth.*(?:crash|died|killed)|bluetoothd.*crash",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "audio_hal_crash",
        r"audioserver.*(?:died|killed|restart)|audio HAL.*(?:error|fail|crash)",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "surfaceflinger_restart",
        r"SurfaceFlinger.*(?:died|crash|killed)",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "mediaserver_crash",
        r"mediaserver.*(?:died|killed|restart)|media\.codec.*crash",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "lmk_ims",
        r"(?:lowmemorykiller|lmk).*(?:ims|com\.android\.ims|imsservice)",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "oom_kill",
        r"Out of memory.*Killed process|oom-kill|lowmemorykiller.*killing",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "selinux_denial",
        r"avc:\s+denied\s+\{.*\}.*scontext=.*imsservice|avc:\s+denied\s+\{.*\}.*telephony",
        "warning",
        "system_anomaly",
    ),

    # ---------------------------------------------------------------------
    # Memory safety / corruption — sanitizers, allocator aborts, stack
    # smashing, OOM. fatal_signal so they bypass the IMS-tag whitelist
    # (these are system-wide signals; whatever process they fire in,
    # it's a real bug).
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "address_sanitizer",
        r"AddressSanitizer:\s+\S+",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "hw_address_sanitizer",
        r"HWAddressSanitizer:\s+\S+",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "kasan",
        r"\bKASAN:\s+\S+",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "use_after_free",
        r"use[- ]after[- ]free|UAF detected|freed memory access",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "double_free",
        r"double free or corruption|double-free detected",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "malloc_corruption",
        r"malloc(?:\(\):)?\s+(?:corrupted|invalid pointer|memory corruption)|"
        r"unsorted double linked list corrupted|"
        r"munmap_chunk\(\): invalid pointer",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "stack_smashing",
        r"\*\*\* stack smashing detected \*\*\*|stack-protector.*Aborted",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "heap_overflow",
        r"heap[- ]buffer[- ]overflow|heap corruption detected",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "out_of_memory_native",
        r"Out of memory:\s*Killed process|OOM killer.*invoked",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "out_of_memory_java",
        r"java\.lang\.OutOfMemoryError",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "unsatisfied_link_error",
        r"java\.lang\.UnsatisfiedLinkError",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "bad_alloc",
        r"std::bad_alloc|terminating with uncaught exception of type std::bad_alloc",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "mmap_failure",
        r"mmap.*failed.*\bENOMEM\b|mmap.*MAP_FAILED",
        "warning",
        "fatal_signal",
    ),

    # ---------------------------------------------------------------------
    # IMS / SIP / VoLTE functional failures (beyond what existing
    # patterns capture). ims_anomaly category — gated by tag whitelist
    # so only IMS-stack tags can trigger them.
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "ims_register_fail",
        r"(?:REGISTER|Register).*(?:failed|failure|denied|rejected).*(?:cause|reason|status)|"
        r"onRegistrationFailed",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_call_fail",
        r"(?:Call|MO|MT).*(?:setup error|terminated abnormally)|"
        r"onCallSetupError|TerminalDisconnectCause",
        "warning",
        "call_anomaly",
    ),
    AnomalyPattern(
        "ims_authentication_fail",
        r"IMS.*[Aa]uth.*(?:fail|denied|reject)|AKA challenge.*fail",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_pdn_lost",
        r"PDN.*(?:lost|disconnected unexpectedly|deactivated by network)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "volte_disabled",
        r"VoLTE.*(?:disabled|turned off|service unavailable)|IMS_DISABLED_BY_NETWORK",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "sip_response_dropped",
        r"SIP.*(?:response dropped|cannot route|unmatched transaction)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "mmtel_error",
        r"MMTEL.*[Ee]rror|mmtel.*fail",
        "warning",
        "ims_anomaly",
    ),

    # ---------------------------------------------------------------------
    # Modem / RIL firmware-level failures. fatal_signal for the truly
    # catastrophic ones (assert, subsystem restart) so they bypass tag
    # whitelist; system_anomaly for softer signals.
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "modem_assert",
        r"modem.*(?:assert|panic|fatal)|MODEM_FW_FATAL|crashscope",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "qmi_error",
        r"qmi[_:].*(?:error|fail|timeout)|QMI_ERR|qmi_fw.*serv_request.*fail",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "radio_subsystem_restart",
        r"subsys.*(?:Restart|crash)|SubsysRestartLevel|ssr_state",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "rild_died",
        r"rild.*(?:died|crashed|killed)|RIL daemon.*restart",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "ril_request_fail",
        r"RILRequest_(?:FAIL|TIMEOUT)|RIL.*request rejected",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "nv_corruption",
        r"NV(?:RAM)?.*(?:corrupt|invalid|recovery)",
        "critical",
        "fatal_signal",
    ),

    # ---------------------------------------------------------------------
    # System / process death (boost on existing patterns).
    # ---------------------------------------------------------------------
    AnomalyPattern(
        "process_died",
        r"Process\s+\S+\s+\(pid\s+\d+\) has died",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "binder_died",
        r"Binder.*died|BinderProxy.*died|onServiceDisconnected.*ims",
        "warning",
        "system_anomaly",
    ),
    AnomalyPattern(
        "watchdog_kill",
        r"Watchdog killing|killing system_server|watchdog.*detected.*hang",
        "critical",
        "system_anomaly",
    ),
    AnomalyPattern(
        "selinux_denial_ims",
        r"avc:\s+denied.*scontext=.*ims",
        "warning",
        "system_anomaly",
    ),
)
