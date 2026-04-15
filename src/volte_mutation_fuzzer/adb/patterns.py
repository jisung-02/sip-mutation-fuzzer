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
        r"oem.*ril.*(?:crash|restart|died)|rild.*(?:died|killed|restart)|RILD.*crash",
        "critical",
        "call_anomaly",
    ),
    AnomalyPattern(
        "oem_ril_error",
        r"oem.*ril.*error|RILJ.*Error|SecRIL.*(?:error|Error)",
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
        "ims_reg_failure",
        r"IMS.*(?:registration.*fail|reg.*fail|REGISTER_FAILURE)|SIP.*403|401 Unauthorized",
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
        "sip_server_error",
        r"SIP/2\.0\s+5\d\d|5\d\d\s+Server Internal Error",
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
)
