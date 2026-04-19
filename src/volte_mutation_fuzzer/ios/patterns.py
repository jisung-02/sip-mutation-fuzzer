from volte_mutation_fuzzer.adb.patterns import AnomalyPattern

IOS_ANOMALY_PATTERNS: tuple[AnomalyPattern, ...] = (
    AnomalyPattern(
        "EXC_BAD_ACCESS",
        r"EXC_BAD_ACCESS|Exception Type:\s*EXC_BAD_ACCESS",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "launchd_terminated_crash",
        r"(?:com\.apple\.)?(?:CommCenter|identityservicesd|imagent).*"
        r"terminated due to (?:crash|signal)",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "EXC_CRASH_SIGABRT",
        r"Abort trap: 6|SIGABRT|signal 6",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "EXC_CRASH_SIGSEGV",
        r"SIGSEGV|signal 11",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "report_crash_saved",
        r"ReportCrash.*(?:Saved crash report|writing .*\.ips|Saved .*\.ips)",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "jetsam_kill",
        r"(?:CommCenter|identityservicesd|imagent).*jetsam|"
        r"jetsam.*(?:CommCenter|identityservicesd|imagent)",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "kernel_panic",
        r"AppleAVE2?.*panic|watchdog.*panic|kernel panic",
        "critical",
        "fatal_signal",
    ),
    AnomalyPattern(
        "ims_registration_failed",
        r"\[IMS\].*registration.*(?:fail|error)",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_deregistration",
        r"\[IMS\].*deregist",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "sip_transaction_timeout",
        r"SIP transaction timeout|SIP.*timer.*expired",
        "warning",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "ims_registered",
        r"\[IMS\].*registered",
        "info",
        "ims_anomaly",
    ),
    AnomalyPattern(
        "callkit_call_failed",
        r"CallKit.*(?:fail|error)",
        "warning",
        "call_anomaly",
    ),
    AnomalyPattern(
        "incoming_call_ui",
        r"incoming call UI presented|CallKit.*incoming call",
        "info",
        "call_anomaly",
    ),
    AnomalyPattern(
        "assertion_failed",
        r"Assertion failed|NSInternalInconsistencyException",
        "info",
        "system_anomaly",
    ),
    AnomalyPattern(
        "commcenter_error_burst",
        r"CommCenter.*<(?:Error|Fault)>",
        "warning",
        "system_anomaly",
    ),
)
