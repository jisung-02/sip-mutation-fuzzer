import unittest
from pathlib import Path
from unittest.mock import patch

from volte_mutation_fuzzer.adb.contracts import AdbCollectorConfig
from volte_mutation_fuzzer.adb.core import (
    AdbAnomalyDetector,
    AdbConnector,
    AdbLogCollector,
)


class _DummyCompletedProcess:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


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


class AdbConnectorTests(unittest.TestCase):
    def test_adb_cmd_without_serial(self) -> None:
        connector = AdbConnector()
        self.assertEqual(connector._adb_cmd("devices"), ["adb", "devices"])

    def test_adb_cmd_with_serial(self) -> None:
        connector = AdbConnector(serial="SER123")
        self.assertEqual(
            connector._adb_cmd("shell", "getprop"),
            ["adb", "-s", "SER123", "shell", "getprop"],
        )

    def test_check_device_connected(self) -> None:
        output = (
            "List of devices attached\n"
            "SER123\tdevice product:pixel model:Pixel_8 device:husky\n"
        )
        with patch(
            "subprocess.run", return_value=_DummyCompletedProcess(stdout=output)
        ):
            info = AdbConnector().check_device()
        self.assertEqual(info.serial, "SER123")
        self.assertEqual(info.state, "device")
        self.assertEqual(info.model, "Pixel_8")

    def test_check_device_not_found(self) -> None:
        output = "List of devices attached\n\n"
        with patch(
            "subprocess.run", return_value=_DummyCompletedProcess(stdout=output)
        ):
            info = AdbConnector(serial="SER123").check_device()
        self.assertEqual(info.serial, "SER123")
        self.assertEqual(info.state, "not_found")

    def test_check_device_unauthorized(self) -> None:
        output = "List of devices attached\nSER123\tunauthorized\n"
        with patch(
            "subprocess.run", return_value=_DummyCompletedProcess(stdout=output)
        ):
            info = AdbConnector(serial="SER123").check_device()
        self.assertEqual(info.state, "unauthorized")

    def test_check_device_adb_not_found(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("adb missing")):
            info = AdbConnector().check_device()
        self.assertEqual(info.serial, "unknown")
        self.assertEqual(info.state, "not_found")
        self.assertEqual(info.error, "adb not found")


def test_take_snapshot_full_profile_writes_meminfo_and_dmesg(tmp_path: Path) -> None:
    outputs: dict[tuple[str, ...], str] = {
        ("adb", "-s", "SER123", "shell", "dumpsys", "telephony.registry"): (
            "telephony output\n"
        ),
        ("adb", "-s", "SER123", "shell", "dumpsys", "ims"): "ims output\n",
        ("adb", "-s", "SER123", "shell", "netstat", "-tlnup"): "netstat output\n",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "main"): "main logcat\n",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "system"): "system logcat\n",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "radio"): "radio logcat\n",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "crash"): "crash logcat\n",
        (
            "adb",
            "-s",
            "SER123",
            "logcat",
            "-d",
            "-b",
            "main,system,radio,crash",
        ): "combined logcat\n",
        ("adb", "-s", "SER123", "shell", "dumpsys", "meminfo"): "meminfo output\n",
        ("adb", "-s", "SER123", "shell", "dmesg"): "dmesg output\n",
    }

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        return _DummyCompletedProcess(stdout=outputs[tuple(cmd)])

    connector = AdbConnector(serial="SER123")
    output_dir = tmp_path / "nested" / "snapshots"
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(output_dir), profile="full")

    assert output_dir.exists()
    assert snapshot.errors == ()
    assert snapshot.meminfo_path is not None
    assert snapshot.dmesg_path is not None
    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is not None
    assert snapshot.netstat_path is not None
    assert snapshot.logcat_path is not None
    assert Path(snapshot.meminfo_path).read_text(encoding="utf-8") == "meminfo output\n"
    assert Path(snapshot.dmesg_path).read_text(encoding="utf-8") == "dmesg output\n"
    assert (
        Path(snapshot.telephony_path).read_text(encoding="utf-8")
        == "telephony output\n"
    )
    assert Path(snapshot.ims_path).read_text(encoding="utf-8") == "ims output\n"
    assert Path(snapshot.netstat_path).read_text(encoding="utf-8") == "netstat output\n"
    assert Path(snapshot.logcat_path).read_text(encoding="utf-8") == "combined logcat\n"


def test_take_snapshot_light_profile_keeps_telephony_and_logcat(
    tmp_path: Path,
) -> None:
    collector = AdbLogCollector()
    collector.push_for_test("main", "before-window", timestamp=10.0)
    collector.push_for_test("radio", "radio-window", timestamp=20.0)
    collector.push_for_test("main", "main-window", timestamp=25.0)
    collector.push_for_test("main", "after-window", timestamp=40.0)

    called_cmds: list[tuple[str, ...]] = []

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        called_cmds.append(tuple(cmd))
        if tuple(cmd) == ("adb", "-s", "SER123", "shell", "dumpsys", "telephony.registry"):
            return _DummyCompletedProcess(stdout="telephony output\n")
        raise AssertionError(f"unexpected shell command: {cmd}")

    connector = AdbConnector(serial="SER123")
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(
            str(tmp_path / "snapshots"),
            profile="light",
            collector=collector,
            log_since=10.0,
            log_until=30.0,
        )

    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is None
    assert snapshot.netstat_path is None
    assert snapshot.meminfo_path is None
    assert snapshot.dmesg_path is None
    assert snapshot.logcat_path is not None
    assert Path(snapshot.telephony_path).read_text(encoding="utf-8") == (
        "telephony output\n"
    )
    assert Path(tmp_path / "snapshots" / "logcat_main.txt").read_text(
        encoding="utf-8"
    ) == "main-window\n"
    assert Path(tmp_path / "snapshots" / "logcat_radio.txt").read_text(
        encoding="utf-8"
    ) == "radio-window\n"
    assert Path(snapshot.logcat_path).read_text(encoding="utf-8") == (
        "radio-window\nmain-window\n"
    )
    assert called_cmds == [
        ("adb", "-s", "SER123", "shell", "dumpsys", "telephony.registry"),
    ]


def test_take_snapshot_records_shell_failures(tmp_path: Path) -> None:
    outputs: dict[tuple[str, ...], str] = {
        ("adb", "-s", "SER123", "shell", "dumpsys", "telephony.registry"): (
            "telephony output\n"
        ),
        ("adb", "-s", "SER123", "shell", "dumpsys", "ims"): "ims output\n",
        ("adb", "-s", "SER123", "shell", "netstat", "-tlnup"): "netstat output\n",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "main"): "",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "system"): "",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "radio"): "",
        ("adb", "-s", "SER123", "logcat", "-d", "-b", "crash"): "",
        (
            "adb",
            "-s",
            "SER123",
            "logcat",
            "-d",
            "-b",
            "main,system,radio,crash",
        ): "",
    }

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        if tuple(cmd) == ("adb", "-s", "SER123", "shell", "dumpsys", "meminfo"):
            raise RuntimeError("meminfo boom")
        if tuple(cmd) == ("adb", "-s", "SER123", "shell", "dmesg"):
            return _DummyCompletedProcess(stdout="permission denied", returncode=1)
        return _DummyCompletedProcess(stdout=outputs.get(tuple(cmd), ""))

    connector = AdbConnector(serial="SER123")
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(tmp_path / "snapshots"))

    assert snapshot.meminfo_path is None
    assert snapshot.dmesg_path is None
    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is not None
    assert snapshot.netstat_path is not None
    assert snapshot.errors == (
        "dumpsys meminfo failed: meminfo boom",
        "dmesg failed: permission denied",
    )


def test_take_snapshot_creates_output_dir_for_bugreport(tmp_path: Path) -> None:
    outputs: dict[tuple[str, ...], str] = {
        ("adb", "shell", "dumpsys", "meminfo"): "meminfo output\n",
        ("adb", "shell", "dmesg"): "dmesg output\n",
        ("adb", "shell", "dumpsys", "telephony.registry"): "telephony output\n",
        ("adb", "shell", "dumpsys", "ims"): "ims output\n",
        ("adb", "shell", "netstat", "-tlnup"): "netstat output\n",
        ("adb", "logcat", "-d", "-b", "main"): "",
        ("adb", "logcat", "-d", "-b", "system"): "",
        ("adb", "logcat", "-d", "-b", "radio"): "",
        ("adb", "logcat", "-d", "-b", "crash"): "",
        ("adb", "logcat", "-d", "-b", "main,system,radio,crash"): "",
        ("adb", "bugreport"): "bugreport output\n",
    }

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        return _DummyCompletedProcess(stdout=outputs.get(tuple(cmd), ""))

    connector = AdbConnector()
    output_dir = tmp_path / "new" / "adb"
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(output_dir), bugreport=True)

    assert output_dir.exists()
    assert snapshot.bugreport_path is not None
    assert (
        Path(snapshot.bugreport_path).read_text(encoding="utf-8")
        == "bugreport output\n"
    )


def test_take_snapshot_uses_collector_window_for_logcat(tmp_path: Path) -> None:
    collector = AdbLogCollector()
    collector.push_for_test("main", "before-window", timestamp=10.0)
    collector.push_for_test("radio", "radio-first", timestamp=20.0)
    collector.push_for_test("main", "main-second", timestamp=25.0)
    collector.push_for_test("crash", "boundary-window", timestamp=30.0)
    connector = AdbConnector(serial="SER123")
    calls: list[tuple[str, ...]] = []

    outputs: dict[tuple[str, ...], str] = {
        ("adb", "-s", "SER123", "shell", "dumpsys", "telephony.registry"): (
            "telephony output\n"
        ),
        ("adb", "-s", "SER123", "shell", "dumpsys", "ims"): "ims output\n",
        ("adb", "-s", "SER123", "shell", "netstat", "-tlnup"): "netstat output\n",
        ("adb", "-s", "SER123", "shell", "dumpsys", "meminfo"): "meminfo output\n",
        ("adb", "-s", "SER123", "shell", "dmesg"): "dmesg output\n",
    }

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        calls.append(tuple(cmd))
        return _DummyCompletedProcess(stdout=outputs[tuple(cmd)])

    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(
            str(tmp_path / "snapshots"),
            collector=collector,
            log_since=10.0,
            log_until=30.0,
        )

    assert snapshot.logcat_path is not None
    body = Path(snapshot.logcat_path).read_text(encoding="utf-8")
    assert "before-window" not in body
    assert "radio-first" in body
    assert "main-second" in body
    assert "boundary-window" in body
    assert body.index("radio-first") < body.index("main-second") < body.index(
        "boundary-window"
    )
    assert not any("logcat" in cmd for cmd in calls)


class AdbLogCollectorTests(unittest.TestCase):
    def test_start_spawns_process_per_buffer_and_clears_logcat(self) -> None:
        config = AdbCollectorConfig(serial="SER123", buffers=("main", "radio"))
        collector = AdbLogCollector(config)
        popen_instances = [_DummyPopen(), _DummyPopen()]

        with (
            patch("subprocess.run") as run_mock,
            patch("subprocess.Popen", side_effect=popen_instances) as popen_mock,
        ):
            collector.start(clear=True)
            collector.stop()

        run_mock.assert_called_once_with(
            ["adb", "-s", "SER123", "logcat", "-c"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(popen_mock.call_count, 2)
        self.assertEqual(
            popen_mock.call_args_list[0].args[0][:5],
            ["adb", "-s", "SER123", "logcat", "-b"],
        )
        self.assertEqual(
            popen_mock.call_args_list[0].args[0][-2:],
            ["-v", "time"],
        )

    def test_get_lines_drains_queue(self) -> None:
        collector = AdbLogCollector()
        collector._queue.put(("main", "one"))
        collector._queue.put(("radio", "two"))

        lines = collector.get_lines()

        self.assertEqual(lines, [("main", "one"), ("radio", "two")])
        self.assertEqual(collector.get_lines(), [])

    def test_slice_uses_non_overlapping_time_windows(self) -> None:
        collector = AdbLogCollector()
        collector.push_for_test("main", "first", timestamp=10.0)
        collector.push_for_test("main", "boundary", timestamp=20.0)
        collector.push_for_test("radio", "later", timestamp=30.0)

        first = collector.slice(since_ts=0.0, until_ts=20.0)
        second = collector.slice(since_ts=20.0, until_ts=40.0)

        self.assertEqual(first, [("main", "first"), ("main", "boundary")])
        self.assertEqual(second, [("radio", "later")])


class AdbLogCollectorHealthTests(unittest.TestCase):
    def test_healthy_when_running(self) -> None:
        collector = AdbLogCollector()
        collector._running.set()
        self.assertTrue(collector.is_healthy)
        self.assertEqual(collector.dead_buffers, frozenset())
        self.assertEqual(collector.reconnect_count, 0)

    def test_unhealthy_when_buffer_dead(self) -> None:
        collector = AdbLogCollector()
        collector._running.set()
        collector._dead_buffers.add("main")
        self.assertFalse(collector.is_healthy)
        self.assertEqual(collector.dead_buffers, frozenset({"main"}))

    def test_unhealthy_when_stopped(self) -> None:
        collector = AdbLogCollector()
        # _running is not set
        self.assertFalse(collector.is_healthy)

    def test_reader_loop_reconnects_on_eof(self) -> None:
        """When adb logcat subprocess dies (EOF), _reader_loop retries."""
        # First proc: yields 1 line then EOF
        first_proc = _DummyPopen(lines=["line1\n"])
        # Second proc: yields 1 line then EOF → triggers another reconnect → stop
        second_proc = _DummyPopen(lines=["line2\n"])

        collector = AdbLogCollector(
            AdbCollectorConfig(buffers=("main",)),
            max_reconnect_attempts=5,
            reconnect_delay=0.1,  # Fast for test
        )
        collector._running.set()

        popen_calls = [second_proc]

        def fake_popen(*args, **kwargs):
            if popen_calls:
                return popen_calls.pop(0)
            # No more procs — stop the collector to end the loop
            collector._running.clear()
            return _DummyPopen(lines=[])

        with patch(
            "volte_mutation_fuzzer.adb.core.subprocess.Popen",
            side_effect=fake_popen,
        ):
            collector._reader_loop("main", first_proc)

        # Should have read lines from both processes
        lines = []
        while not collector._queue.empty():
            lines.append(collector._queue.get_nowait())
        self.assertIn(("main", "line1"), lines)
        self.assertIn(("main", "line2"), lines)
        self.assertGreaterEqual(collector.reconnect_count, 1)

    def test_reader_loop_marks_dead_after_max_retries(self) -> None:
        """After max_reconnect_attempts, buffer is marked dead."""
        collector = AdbLogCollector(
            AdbCollectorConfig(buffers=("radio",)),
            max_reconnect_attempts=2,
            reconnect_delay=0.1,
        )
        collector._running.set()

        # All Popen calls fail
        with patch(
            "volte_mutation_fuzzer.adb.core.subprocess.Popen",
            side_effect=OSError("adb not found"),
        ):
            # First proc: immediate EOF
            collector._reader_loop("radio", _DummyPopen(lines=[]))

        self.assertIn("radio", collector.dead_buffers)
        self.assertFalse(collector.is_healthy)

    def test_stop_clears_dead_buffers(self) -> None:
        collector = AdbLogCollector()
        collector._running.set()
        collector._dead_buffers.add("main")
        collector.stop()
        self.assertEqual(collector.dead_buffers, frozenset())


class AdbAnomalyDetectorTests(unittest.TestCase):
    def test_detects_sigsegv(self) -> None:
        detector = AdbAnomalyDetector()
        event = detector.feed_line("crash", "Fatal signal SIGSEGV in system_server")
        assert event is not None
        self.assertEqual(event.severity, "critical")
        self.assertEqual(event.category, "fatal_signal")

    def test_detects_vendor_ril_daemon_death(self) -> None:
        detector = AdbAnomalyDetector()
        event = detector.feed_line(
            "radio", "vendor.ril-daemon died unexpectedly after restart request"
        )
        assert event is not None
        self.assertEqual(event.pattern_name, "oem_ril_crash")
        self.assertEqual(event.severity, "critical")

    def test_detects_ims_deregistration(self) -> None:
        detector = AdbAnomalyDetector()
        event = detector.feed_line("radio", "IMS deregist triggered by network change")
        assert event is not None
        self.assertEqual(event.severity, "warning")
        self.assertEqual(event.category, "ims_anomaly")

    def test_no_match_returns_none(self) -> None:
        detector = AdbAnomalyDetector()
        self.assertIsNone(detector.feed_line("main", "regular info log"))

    def test_drain_events_clears_buffer(self) -> None:
        detector = AdbAnomalyDetector()
        detector.feed_line("crash", "signal 11")
        self.assertEqual(len(detector.peek_events()), 1)
        drained = detector.drain_events()
        self.assertEqual(len(drained), 1)
        self.assertEqual(detector.peek_events(), [])

    def test_feed_lines_batches_matches(self) -> None:
        detector = AdbAnomalyDetector()
        events = detector.feed_lines(
            [
                ("main", "normal log"),
                ("crash", "signal 11"),
                ("radio", "IMS deregist reason=unknown"),
            ]
        )
        self.assertEqual(len(events), 2)

    def test_max_events_is_enforced(self) -> None:
        detector = AdbAnomalyDetector(max_events=2)
        detector.feed_line("crash", "signal 11")
        detector.feed_line("crash", "signal 6")
        detector.feed_line("radio", "IMS deregist reason=unknown")
        events = detector.peek_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].pattern_name, "SIGABRT")
        self.assertEqual(events[1].pattern_name, "ims_deregistration")

    def test_total_lines_scanned_tracks_all_inputs(self) -> None:
        detector = AdbAnomalyDetector()
        detector.feed_line("main", "one")
        detector.feed_lines([("main", "two"), ("main", "three")])
        self.assertEqual(detector.total_lines_scanned, 3)
