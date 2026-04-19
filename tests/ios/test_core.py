import json
import unittest
from pathlib import Path
from unittest.mock import patch

from volte_mutation_fuzzer.ios.contracts import (
    IosCollectorConfig,
    IosSyslogLine,
)
from volte_mutation_fuzzer.ios.core import (
    IosAnomalyDetector,
    IosConnector,
    IosSyslogCollector,
    _parse_syslog_line,
)


class _DummyCompletedProcess:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class _DummyPopen:
    def __init__(self, lines: list[str] | None = None) -> None:
        self.stdout = iter(lines or [])
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: int | None = None) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True


class SyslogLineParserTests(unittest.TestCase):
    def test_parse_standard_line(self) -> None:
        raw = "Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: [IMS] Reg started"
        parsed = _parse_syslog_line(raw, host_ts=100.0)
        self.assertEqual(parsed.device_ts, "Apr 15 10:32:17")
        self.assertEqual(parsed.process, "CommCenter")
        self.assertEqual(parsed.level, "Notice")
        self.assertIn("Reg started", parsed.line)

    def test_parse_malformed_preserves_line(self) -> None:
        raw = "garbage text with no timestamp"
        parsed = _parse_syslog_line(raw, host_ts=200.0)
        self.assertEqual(parsed.host_ts, 200.0)
        self.assertEqual(parsed.line, raw)


class IosConnectorTests(unittest.TestCase):
    def test_cmd_without_udid(self) -> None:
        connector = IosConnector()
        self.assertEqual(
            connector._cmd("idevicesyslog"), ["idevicesyslog"]
        )

    def test_cmd_with_udid(self) -> None:
        connector = IosConnector(udid="ABC-123")
        self.assertEqual(
            connector._cmd("ideviceinfo", "-k", "ProductType"),
            ["ideviceinfo", "-u", "ABC-123", "-k", "ProductType"],
        )

    def test_check_device_connected(self) -> None:
        def fake_run(cmd, **kwargs):
            if cmd == ["idevice_id", "-l"]:
                return _DummyCompletedProcess(stdout="ABC-123\n")
            if cmd[:2] == ["ideviceinfo", "-u"] and cmd[-2:] == ["-k", "ProductType"]:
                return _DummyCompletedProcess(stdout="iPhone13,2\n")
            if cmd[-2:] == ["-k", "ProductVersion"]:
                return _DummyCompletedProcess(stdout="17.5.1\n")
            if cmd[-2:] == ["-k", "BuildVersion"]:
                return _DummyCompletedProcess(stdout="21F90\n")
            if cmd[-2:] == ["-k", "DeviceName"]:
                return _DummyCompletedProcess(stdout="iPhone 12\n")
            return _DummyCompletedProcess(stdout="")

        with patch("subprocess.run", side_effect=fake_run):
            info = IosConnector(udid="ABC-123").check_device()
        self.assertEqual(info.udid, "ABC-123")
        self.assertEqual(info.product_type, "iPhone13,2")
        self.assertEqual(info.product_version, "17.5.1")
        self.assertEqual(info.device_name, "iPhone 12")
        self.assertIsNone(info.error)

    def test_check_device_not_connected(self) -> None:
        with patch("subprocess.run", return_value=_DummyCompletedProcess(stdout="")):
            info = IosConnector().check_device()
        self.assertEqual(info.error, "no device connected")

    def test_check_device_requested_udid_missing(self) -> None:
        with patch(
            "subprocess.run", return_value=_DummyCompletedProcess(stdout="OTHER-999\n")
        ):
            info = IosConnector(udid="ABC-123").check_device()
        self.assertEqual(info.error, "requested udid not connected")

    def test_check_device_libimobiledevice_missing(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            info = IosConnector().check_device()
        self.assertEqual(info.error, "libimobiledevice not found")

    def test_check_device_reports_ideviceinfo_failure(self) -> None:
        def fake_run(cmd, **kwargs):
            if cmd == ["idevice_id", "-l"]:
                return _DummyCompletedProcess(stdout="ABC-123\n")
            return _DummyCompletedProcess(
                stdout="",
                stderr="ERROR: Could not connect to lockdownd",
                returncode=255,
            )

        with patch("subprocess.run", side_effect=fake_run):
            info = IosConnector(udid="ABC-123").check_device()

        self.assertEqual(info.udid, "ABC-123")
        self.assertIsNone(info.product_type)
        assert info.error is not None
        self.assertIn("lockdownd", info.error)


def test_run_diagnostics_returns_error_on_missing_binary(tmp_path: Path) -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        path, error = IosConnector().run_diagnostics(str(tmp_path / "diag.json"))
    assert path is None
    assert error == "idevicediagnostics not found"


def test_run_diagnostics_returns_error_on_nonzero(tmp_path: Path) -> None:
    with patch(
        "subprocess.run",
        return_value=_DummyCompletedProcess(
            stdout="", stderr="lockdown error", returncode=1
        ),
    ):
        path, error = IosConnector().run_diagnostics(str(tmp_path / "diag.json"))
    assert path is None
    assert error is not None
    assert "lockdown error" in error


def test_take_snapshot_records_diagnostics_failure(tmp_path: Path) -> None:
    collector = IosSyslogCollector()

    def fake_run(cmd, **kwargs):
        if cmd[0] == "idevicecrashreport":
            return _DummyCompletedProcess(stdout="ok")
        if cmd[0] == "idevicediagnostics":
            return _DummyCompletedProcess(
                stdout="", stderr="lockdown busy", returncode=1
            )
        return _DummyCompletedProcess(stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        snapshot = IosConnector().take_snapshot(
            str(tmp_path / "ios"),
            collector=collector,
            syslog_since=0.0,
            syslog_until=1.0,
            run_diagnostics=True,
        )

    assert snapshot.diagnostics_path is None
    assert any("lockdown busy" in err for err in snapshot.errors)


def test_pull_crashes_detects_new_files(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        out_index = cmd.index("-e") + 1
        Path(cmd[out_index]).joinpath("CommCenter-2026-04-15.ips").write_text("{}")
        return _DummyCompletedProcess(stdout="Saved 1 report")

    with patch("subprocess.run", side_effect=fake_run):
        new_files, errors = IosConnector().pull_crashes(str(tmp_path))

    assert "CommCenter-2026-04-15.ips" in new_files
    assert errors == []


def test_pull_crashes_records_errors(tmp_path: Path) -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        new_files, errors = IosConnector().pull_crashes(str(tmp_path))

    assert new_files == ()
    assert errors == ["idevicecrashreport not found"]


def test_take_snapshot_writes_syslog_and_pulls_crashes(tmp_path: Path) -> None:
    collector = IosSyslogCollector()
    collector.push_for_test(
        IosSyslogLine(
            host_ts=100.0,
            device_ts="Apr 15 10:32:17",
            process="CommCenter",
            level="Notice",
            line="Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: SIP response code: 180",
        )
    )
    collector.push_for_test(
        IosSyslogLine(
            host_ts=101.0,
            device_ts="Apr 15 10:32:18",
            process="SpringBoard",
            level="Notice",
            line="Apr 15 10:32:18 iPhone SpringBoard[89] <Notice>: incoming call UI presented",
        )
    )
    collector.push_for_test(
        IosSyslogLine(
            host_ts=200.0,
            line="out-of-window line",
        )
    )

    detector = IosAnomalyDetector()

    def fake_run(cmd, **kwargs):
        if cmd[0] == "idevicecrashreport":
            return _DummyCompletedProcess(stdout="ok")
        return _DummyCompletedProcess(stdout="")

    out_dir = tmp_path / "ios"
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = IosConnector().take_snapshot(
            str(out_dir),
            collector=collector,
            syslog_since=99.0,
            syslog_until=150.0,
            detector=detector,
        )

    assert snapshot.syslog_path is not None
    body = Path(snapshot.syslog_path).read_text(encoding="utf-8")
    assert "SIP response code: 180" in body
    assert "incoming call UI" in body
    assert "out-of-window line" not in body

    assert snapshot.syslog_commcenter_path is not None
    cc_body = Path(snapshot.syslog_commcenter_path).read_text(encoding="utf-8")
    assert "CommCenter" in cc_body
    assert "SpringBoard" not in cc_body

    assert snapshot.anomalies_path is not None
    events = json.loads(Path(snapshot.anomalies_path).read_text(encoding="utf-8"))
    assert any(e["pattern_name"] == "incoming_call_ui" for e in events)


class IosSyslogCollectorHealthTests(unittest.TestCase):
    def test_slice_filters_by_host_ts(self) -> None:
        collector = IosSyslogCollector()
        collector.push_for_test(IosSyslogLine(host_ts=10.0, line="a"))
        collector.push_for_test(IosSyslogLine(host_ts=20.0, line="b"))
        collector.push_for_test(IosSyslogLine(host_ts=30.0, line="c"))

        out = collector.slice(since_ts=15.0, until_ts=25.0)
        self.assertEqual([x.line for x in out], ["b"])

    def test_healthy_when_running(self) -> None:
        collector = IosSyslogCollector()
        collector._running.set()
        self.assertTrue(collector.is_healthy)

    def test_unhealthy_when_dead(self) -> None:
        collector = IosSyslogCollector()
        collector._running.set()
        collector._dead = True
        self.assertFalse(collector.is_healthy)

    def test_start_invokes_idevicesyslog_with_process_filters(self) -> None:
        collector = IosSyslogCollector(
            IosCollectorConfig(
                udid="ABC-123", filter_processes=("CommCenter", "SpringBoard")
            )
        )
        instance = _DummyPopen(lines=[])
        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            return_value=instance,
        ) as popen_mock:
            collector.start()
            collector.stop()
        first_call = popen_mock.call_args_list[0]
        self.assertEqual(
            first_call.args[0],
            [
                "idevicesyslog",
                "-u",
                "ABC-123",
                "-p",
                "CommCenter",
                "-p",
                "SpringBoard",
            ],
        )

    def test_start_omits_process_filters_when_empty(self) -> None:
        collector = IosSyslogCollector(
            IosCollectorConfig(udid="ABC-123", filter_processes=())
        )
        instance = _DummyPopen(lines=[])
        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            return_value=instance,
        ) as popen_mock:
            collector.start()
            collector.stop()
        self.assertEqual(
            popen_mock.call_args_list[0].args[0],
            ["idevicesyslog", "-u", "ABC-123"],
        )

    def test_reader_loop_drops_unfiltered_processes(self) -> None:
        collector = IosSyslogCollector(
            IosCollectorConfig(filter_processes=("CommCenter",)),
            max_reconnect_attempts=1,
            reconnect_delay=0.05,
        )
        collector._running.set()
        first_proc = _DummyPopen(
            lines=[
                "Apr 15 10:00:00 iPhone MobileMail[1] <Error>: SIGABRT\n",
                "Apr 15 10:00:01 iPhone CommCenter[127] <Error>: EXC_BAD_ACCESS\n",
            ]
        )

        def fake_popen(*args, **kwargs):
            collector._running.clear()
            return _DummyPopen(lines=[])

        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            side_effect=fake_popen,
        ):
            collector._reader_loop(first_proc)

        stored = collector.slice(since_ts=0.0, until_ts=time_future())
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].process, "CommCenter")

    def test_reader_loop_parses_and_stores(self) -> None:
        first_proc = _DummyPopen(
            lines=["Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: hello\n"]
        )
        collector = IosSyslogCollector(
            max_reconnect_attempts=1,
            reconnect_delay=0.05,
        )
        collector._running.set()

        def fake_popen(*args, **kwargs):
            # First reconnect attempt -> stop the loop immediately
            collector._running.clear()
            return _DummyPopen(lines=[])

        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            side_effect=fake_popen,
        ):
            collector._reader_loop(first_proc)

        lines = collector.slice(since_ts=0.0, until_ts=time_future())
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].process, "CommCenter")

    def test_start_marks_dead_when_popen_fails(self) -> None:
        collector = IosSyslogCollector()
        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            side_effect=FileNotFoundError("idevicesyslog"),
        ):
            with self.assertRaises(FileNotFoundError):
                collector.start()
        self.assertFalse(collector.is_running)
        self.assertFalse(collector.is_healthy)

    def test_reader_loop_marks_dead_after_max_retries(self) -> None:
        collector = IosSyslogCollector(
            max_reconnect_attempts=1,
            reconnect_delay=0.05,
        )
        collector._running.set()

        with patch(
            "volte_mutation_fuzzer.ios.core.subprocess.Popen",
            side_effect=OSError("idevicesyslog missing"),
        ):
            collector._reader_loop(_DummyPopen(lines=[]))

        self.assertFalse(collector.is_healthy)


def time_future() -> float:
    import time as _t

    return _t.time() + 10_000


class IosAnomalyDetectorTests(unittest.TestCase):
    def _line(self, text: str, ts: float = 1.0, process: str = "CommCenter") -> IosSyslogLine:
        return IosSyslogLine(host_ts=ts, process=process, line=text)

    def test_detects_exc_bad_access(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(
            self._line("CommCenter[127] <Error>: EXC_BAD_ACCESS at 0x00")
        )
        assert event is not None
        self.assertEqual(event.severity, "critical")
        self.assertEqual(event.category, "fatal_signal")
        self.assertEqual(event.pattern_name, "EXC_BAD_ACCESS")

    def test_detects_abort_trap(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(self._line("something Abort trap: 6 happened"))
        assert event is not None
        self.assertEqual(event.pattern_name, "EXC_CRASH_SIGABRT")

    def test_detects_reportcrash_writing_ips(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(
            self._line(
                "ReportCrash writing /var/mobile/Library/Logs/CrashReporter/CommCenter-2026-04-19-123456.ips"
            )
        )
        assert event is not None
        self.assertEqual(event.pattern_name, "report_crash_saved")
        self.assertEqual(event.severity, "critical")

    def test_detects_identityservicesd_termination(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(
            self._line(
                "identityservicesd terminated due to signal 6",
                process="identityservicesd",
            )
        )
        assert event is not None
        self.assertEqual(event.pattern_name, "launchd_terminated_crash")
        self.assertEqual(event.severity, "critical")

    def test_detects_ims_deregistration(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(self._line("[IMS] deregistration triggered"))
        assert event is not None
        self.assertEqual(event.category, "ims_anomaly")
        self.assertEqual(event.severity, "warning")

    def test_promotes_commcenter_assertion_to_warning(self) -> None:
        detector = IosAnomalyDetector()
        event = detector.feed_line(
            self._line(
                "Assertion failed: radio state invariant",
                process="CommCenter",
            )
        )
        assert event is not None
        self.assertEqual(event.pattern_name, "assertion_failed")
        self.assertEqual(event.severity, "warning")

    def test_no_match_returns_none(self) -> None:
        detector = IosAnomalyDetector()
        self.assertIsNone(detector.feed_line(self._line("boring log")))

    def test_drain_clears_buffer(self) -> None:
        detector = IosAnomalyDetector()
        detector.feed_line(self._line("EXC_BAD_ACCESS here"))
        self.assertEqual(len(detector.peek_events()), 1)
        drained = detector.drain_events()
        self.assertEqual(len(drained), 1)
        self.assertEqual(detector.peek_events(), [])

    def test_feed_lines_batches_matches(self) -> None:
        detector = IosAnomalyDetector()
        events = detector.feed_lines([
            self._line("normal"),
            self._line("EXC_BAD_ACCESS"),
            self._line("[IMS] deregistration"),
        ])
        self.assertEqual(len(events), 2)

    def test_max_events_enforced(self) -> None:
        detector = IosAnomalyDetector(max_events=2)
        detector.feed_line(self._line("EXC_BAD_ACCESS a"))
        detector.feed_line(self._line("Abort trap: 6"))
        detector.feed_line(self._line("[IMS] deregistration"))
        self.assertEqual(len(detector.peek_events()), 2)

    def test_total_lines_scanned(self) -> None:
        detector = IosAnomalyDetector()
        detector.feed_line(self._line("one"))
        detector.feed_lines([self._line("two"), self._line("three")])
        self.assertEqual(detector.total_lines_scanned, 3)
