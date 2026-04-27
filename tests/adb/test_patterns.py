import unittest

from volte_mutation_fuzzer.adb.patterns import ANOMALY_PATTERNS, AnomalyPattern


def _match_pattern(line: str) -> AnomalyPattern | None:
    for pattern in ANOMALY_PATTERNS:
        if pattern.compiled.search(line):
            return pattern
    return None


class AnomalyPatternsTests(unittest.TestCase):
    def test_sigsegv_matches(self) -> None:
        pattern = _match_pattern("Fatal signal SIGSEGV in vendor process")
        assert pattern is not None
        self.assertEqual(pattern.name, "SIGSEGV")
        self.assertEqual(pattern.severity, "critical")
        self.assertEqual(pattern.category, "fatal_signal")

    def test_sigabrt_matches(self) -> None:
        pattern = _match_pattern("signal 6 raised by media service")
        assert pattern is not None
        self.assertEqual(pattern.name, "SIGABRT")

    def test_tombstone_matches(self) -> None:
        pattern = _match_pattern("Tombstone written to: /data/tombstones/tombstone_01")
        assert pattern is not None
        self.assertEqual(pattern.name, "tombstone")

    def test_heap_corruption_matches(self) -> None:
        pattern = _match_pattern("Scudo ERROR: corrupted chunk header at 0x1234")
        assert pattern is not None
        self.assertEqual(pattern.name, "heap_corruption")
        self.assertEqual(pattern.severity, "critical")

    def test_ims_deregistration_matches(self) -> None:
        pattern = _match_pattern("IMS stack DEREGIST reason=radio_lost")
        assert pattern is not None
        self.assertEqual(pattern.name, "ims_deregistration")
        self.assertEqual(pattern.severity, "warning")

    def test_ims_registered_is_info(self) -> None:
        pattern = _match_pattern("IMS REGISTERED on LTE")
        assert pattern is not None
        self.assertEqual(pattern.name, "ims_registered")
        self.assertEqual(pattern.severity, "info")

    def test_normal_lines_do_not_match(self) -> None:
        self.assertIsNone(_match_pattern("Audio route changed successfully"))

    def test_telephony_crash_matches(self) -> None:
        # Real AMS process-kill signal — the kind of line that should
        # promote a verdict.
        pattern = _match_pattern(
            "I/ActivityManager( 1234): am_kill: 5678:com.android.phone (adj 0): killed"
        )
        assert pattern is not None
        self.assertEqual(pattern.name, "telephony_crash")

    def test_telephony_crash_matches_proc_died(self) -> None:
        # AMS am_proc_died trace — also a real death signal.
        pattern = _match_pattern(
            "I/ActivityManager( 1234): am_proc_died: 5678 com.android.phone proc died"
        )
        assert pattern is not None
        self.assertEqual(pattern.name, "telephony_crash")

    def test_telephony_crash_does_not_match_binder_unbind_fp(self) -> None:
        # Regression: case 10 of the 2026-04-27 SDP byte_edit Pixel
        # campaign matched the loose old regex on a normal Telecom
        # binder unbind line — the bound TelephonyConnectionService had
        # disconnected after a missed-call cleanup, but the process
        # ``com.android.phone`` never died (logged again 200ms later).
        line = (
            "04-27 14:12:06.900 I/Telecom ( 1702): CallsManager: "
            "handleConnectionServiceDeath: service [ConnectionServiceWrapper "
            "componentName=ComponentInfo{com.android.phone/com.android."
            "services.telephony.TelephonyConnectionService}] died: ..."
        )
        self.assertIsNone(_match_pattern(line))

    # ---- sip_server_error: echo regex tightening ----

    def test_sip_server_error_inbound_5xx_matches(self) -> None:
        pattern = _match_pattern("[<--] SIP/2.0 500 Server Internal Error")
        assert pattern is not None
        self.assertEqual(pattern.name, "sip_server_error")

    def test_sip_server_error_no_arrow_5xx_matches(self) -> None:
        pattern = _match_pattern("response: SIP/2.0 503 Service Unavailable")
        assert pattern is not None
        self.assertEqual(pattern.name, "sip_server_error")

    def test_sip_server_error_4xx_matches(self) -> None:
        pattern = _match_pattern("[<--] SIP/2.0 401 Unauthorized")
        assert pattern is not None
        self.assertEqual(pattern.name, "sip_server_error")

    def test_sip_server_error_regex_skips_outbound_echo(self) -> None:
        # The sip_server_error regex itself uses a negative lookbehind to
        # exclude "[-->] SIP/2.0 5xx" echoes.  Other ims_anomaly patterns
        # (e.g. sip_timeout for 408) might still match the echo line in
        # isolation — those are filtered out at the feed_line level by
        # the SIPMSG outbound-echo pre-check, see tests/adb/test_core.py.
        from volte_mutation_fuzzer.adb.patterns import ANOMALY_PATTERNS
        sip_server_err = next(p for p in ANOMALY_PATTERNS if p.name == "sip_server_error")
        line = "I/SIPMSG[0,2]( 2815): [-->] SIP/2.0 500 Server Internal Error"
        self.assertIsNone(sip_server_err.compiled.search(line))

    # ---- new patterns: memory safety / sanitizers ----

    def test_address_sanitizer_matches(self) -> None:
        pattern = _match_pattern("AddressSanitizer: heap-buffer-overflow on address 0xdead")
        assert pattern is not None
        # several overlapping patterns can win first depending on order;
        # what matters is severity and category.
        self.assertIn(
            pattern.name,
            ("address_sanitizer", "heap_overflow", "sanitizer_report"),
        )
        self.assertEqual(pattern.severity, "critical")
        self.assertEqual(pattern.category, "fatal_signal")

    def test_hw_address_sanitizer_matches(self) -> None:
        pattern = _match_pattern("HWAddressSanitizer: tag-mismatch on address 0xdead")
        assert pattern is not None
        self.assertIn(
            pattern.name,
            ("hw_address_sanitizer", "sanitizer_report"),
        )
        self.assertEqual(pattern.category, "fatal_signal")

    def test_double_free_matches(self) -> None:
        pattern = _match_pattern("double free or corruption (out)")
        assert pattern is not None
        # heap_corruption pattern is broader and may win first
        self.assertIn(pattern.name, ("double_free", "heap_corruption"))
        self.assertEqual(pattern.severity, "critical")

    def test_malloc_corruption_matches(self) -> None:
        pattern = _match_pattern("malloc(): unsorted double linked list corrupted")
        assert pattern is not None
        self.assertEqual(pattern.name, "malloc_corruption")

    def test_stack_smashing_matches(self) -> None:
        pattern = _match_pattern("*** stack smashing detected ***: terminated")
        assert pattern is not None
        self.assertEqual(pattern.name, "stack_smashing")

    def test_use_after_free_matches(self) -> None:
        pattern = _match_pattern("use-after-free detected in IMS audio buffer")
        assert pattern is not None
        self.assertEqual(pattern.name, "use_after_free")

    def test_oom_native_matches(self) -> None:
        pattern = _match_pattern("Out of memory: Killed process 9999 (com.sec.imsservice)")
        assert pattern is not None
        # could match either out_of_memory_native or oom_kill — both correct
        self.assertIn(pattern.name, ("out_of_memory_native", "oom_kill"))

    def test_oom_java_matches(self) -> None:
        pattern = _match_pattern("java.lang.OutOfMemoryError: Failed to allocate")
        assert pattern is not None
        # uncaught_java_exception is broader and may win first; either is fine
        self.assertIn(pattern.name, ("out_of_memory_java", "uncaught_java_exception"))

    def test_unsatisfied_link_error_matches(self) -> None:
        pattern = _match_pattern("java.lang.UnsatisfiedLinkError: libims_native.so")
        assert pattern is not None
        self.assertIn(pattern.name, ("unsatisfied_link_error", "uncaught_java_exception"))

    def test_bad_alloc_matches(self) -> None:
        pattern = _match_pattern("terminating with uncaught exception of type std::bad_alloc")
        assert pattern is not None
        self.assertEqual(pattern.name, "bad_alloc")

    # ---- new patterns: modem / RIL ----

    def test_modem_assert_matches(self) -> None:
        pattern = _match_pattern("modem assert: MODEM_FW_FATAL at firmware_main.c:42")
        assert pattern is not None
        self.assertEqual(pattern.name, "modem_assert")
        self.assertEqual(pattern.category, "fatal_signal")

    def test_radio_subsystem_restart_matches(self) -> None:
        pattern = _match_pattern("subsys-modem: Restart triggered for crashscope")
        assert pattern is not None
        # could match modem_crash or radio_subsystem_restart depending on order
        self.assertIn(pattern.name, ("modem_crash", "radio_subsystem_restart"))

    def test_radio_subsystem_restart_matches_underscore_form(self) -> None:
        pattern = _match_pattern(
            "I/Kernel ( 1234): subsystem_restart: peripheral=modem reason=panic"
        )
        assert pattern is not None
        # ``baseband_reset`` regex (``Subsystem.*restart``) often catches
        # this first; ``radio_subsystem_restart`` is a fallback. Either
        # critical signal is acceptable.
        self.assertIn(
            pattern.name,
            ("modem_crash", "radio_subsystem_restart", "baseband_reset"),
        )

    def test_radio_subsystem_restart_matches_samsung_level(self) -> None:
        pattern = _match_pattern(
            "I/Shannon ( 5678): SubsysRestartLevel changed: 1 -> 0"
        )
        assert pattern is not None
        self.assertEqual(pattern.name, "radio_subsystem_restart")

    def test_radio_subsystem_restart_does_not_match_audio_stats_fp(self) -> None:
        # Regression: ConnectivityMonitorStateMachine periodic call-state
        # reporter contains both ``SubSystem`` and ``Crash`` substrings 30+
        # chars apart. Earlier ``subsys.*(?:Restart|crash)`` matched it
        # under IGNORECASE on every fuzzed INVITE on Pixel — see
        # 2026-04-27 SDP byte_edit campaign (8/13 stack_failure FPs).
        line = (
            "I/ConnectivityMonitorStateMachine( 3061): [OnCallLteOrNr] "
            "{subId=11} updateAudioSubSystemInfo =MicStatus: -1, "
            "CrashCounter: -1, SpeakerImpedenceLeft: 0.0"
        )
        self.assertIsNone(_match_pattern(line))

    def test_rild_died_matches(self) -> None:
        pattern = _match_pattern("rild: died with signal 9")
        assert pattern is not None
        self.assertIn(pattern.name, ("rild_died", "oem_ril_crash"))

    def test_qmi_error_matches(self) -> None:
        pattern = _match_pattern("qmi_fw: serv_request: fail (timeout)")
        assert pattern is not None
        self.assertEqual(pattern.name, "qmi_error")

    def test_nv_corruption_matches(self) -> None:
        pattern = _match_pattern("NV-RAM corruption detected, recovery initiated")
        assert pattern is not None
        self.assertEqual(pattern.name, "nv_corruption")

    # ---- new patterns: process death / system ----

    def test_process_died_matches(self) -> None:
        pattern = _match_pattern("Process com.sec.imsservice (pid 9999) has died")
        assert pattern is not None
        # ims_service_crash pattern matches "imsservice" + "died" first;
        # process_died is a fallback. Either is correct.
        self.assertIn(pattern.name, ("process_died", "ims_service_crash"))
        self.assertEqual(pattern.severity, "critical")

    def test_process_died_unrelated_proc_matches(self) -> None:
        # When the dead process isn't IMS, ims_service_crash won't match,
        # so the new process_died pattern is responsible.
        pattern = _match_pattern("Process com.example.unrelated (pid 1234) has died")
        assert pattern is not None
        self.assertEqual(pattern.name, "process_died")

    def test_binder_died_matches(self) -> None:
        pattern = _match_pattern("BinderProxy died: onServiceDisconnected for ims")
        assert pattern is not None
        self.assertEqual(pattern.name, "binder_died")

    def test_watchdog_kill_matches(self) -> None:
        pattern = _match_pattern("Watchdog killing system_server after 60s hang")
        assert pattern is not None
        # could match watchdog_kill or system_server_restart
        self.assertIn(pattern.name, ("watchdog_kill", "system_server_restart"))

    # ---- new patterns: IMS functional failures ----

    def test_ims_register_fail_matches(self) -> None:
        pattern = _match_pattern("REGISTER failed: cause=403, reason=auth")
        assert pattern is not None
        # ims_reg_failure is older + stricter; new ims_register_fail is broader
        self.assertIn(pattern.name, ("ims_register_fail", "ims_reg_failure"))

    def test_ims_authentication_fail_matches(self) -> None:
        pattern = _match_pattern("IMS Auth failed: AKA challenge failure")
        assert pattern is not None
        self.assertIn(pattern.name, ("ims_authentication_fail", "ims_reg_failure"))

    def test_volte_disabled_matches(self) -> None:
        pattern = _match_pattern("VoLTE service unavailable: IMS_DISABLED_BY_NETWORK")
        assert pattern is not None
        self.assertEqual(pattern.name, "volte_disabled")
