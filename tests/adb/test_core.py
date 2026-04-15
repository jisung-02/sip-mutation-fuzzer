import time
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


def test_take_snapshot_writes_meminfo_and_dmesg(tmp_path: Path) -> None:
    outputs = {
        ("dumpsys", "meminfo"): "meminfo output\n",
        ("dmesg",): "dmesg output\n",
    }

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        # All snapshot calls go through `adb -s SER123 shell <args...>`
        # except `adb logcat ...`.  Return per-command stdout; default
        # to empty success for anything else so unrelated dumps don't
        # spuriously appear in `errors`.
        shell_args = tuple(cmd[cmd.index("shell") + 1:]) if "shell" in cmd else ()
        return _DummyCompletedProcess(stdout=outputs.get(shell_args, ""))

    connector = AdbConnector(serial="SER123")
    output_dir = tmp_path / "nested" / "snapshots"
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(output_dir))

    assert output_dir.exists()
    assert snapshot.errors == ()
    assert snapshot.meminfo_path is not None
    assert snapshot.dmesg_path is not None
    assert Path(snapshot.meminfo_path).read_text(encoding="utf-8") == "meminfo output\n"
    assert Path(snapshot.dmesg_path).read_text(encoding="utf-8") == "dmesg output\n"


def test_take_snapshot_records_shell_failures(tmp_path: Path) -> None:
    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        if cmd[-2:] == ["dumpsys", "meminfo"]:
            raise RuntimeError("meminfo boom")
        return _DummyCompletedProcess(stdout="permission denied", returncode=1)

    connector = AdbConnector(serial="SER123")
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(tmp_path / "snapshots"))

    assert snapshot.meminfo_path is None
    assert snapshot.dmesg_path is None
    # `take_snapshot` runs its dumps concurrently, so `errors` order is
    # not guaranteed.  Verify the two failure modes we care about — the
    # raised exception and a non-zero-return shell error — are both
    # reported, independent of ordering.
    assert "dumpsys meminfo failed: meminfo boom" in snapshot.errors
    assert "dmesg failed: permission denied" in snapshot.errors


def test_take_snapshot_creates_output_dir_for_bugreport(tmp_path: Path) -> None:
    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        outputs = {
            ("adb", "shell", "dumpsys", "meminfo"): "meminfo output\n",
            ("adb", "shell", "dmesg"): "dmesg output\n",
            ("adb", "bugreport"): "bugreport output\n",
        }
        return _DummyCompletedProcess(stdout=outputs[tuple(cmd)])

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


def test_take_snapshot_runs_dumps_concurrently(tmp_path: Path) -> None:
    # Every dump call blocks for `delay` seconds; if the ten dumps were
    # serial the wall clock would be ~10 * delay.  Parallel execution
    # with ``max_workers=8`` should finish in well under half that.
    import threading as _threading

    delay = 0.1
    call_count = 0
    counter_lock = _threading.Lock()
    max_concurrent = 0
    active = 0

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        nonlocal call_count, active, max_concurrent
        with counter_lock:
            call_count += 1
            active += 1
            if active > max_concurrent:
                max_concurrent = active
        time.sleep(delay)
        with counter_lock:
            active -= 1
        return _DummyCompletedProcess(stdout="ok\n")

    connector = AdbConnector()
    with patch("subprocess.run", side_effect=fake_run):
        t0 = time.perf_counter()
        connector.take_snapshot(str(tmp_path / "snapshots"))
        elapsed = time.perf_counter() - t0

    # The anchor `get_device_time()` plus ten dumps gives 11 subprocess
    # calls.  Serial execution would take ~11 * delay = 1.1s; parallel
    # pool should stay under ~0.6s comfortably.
    assert call_count >= 11
    assert max_concurrent >= 2, "dump calls did not overlap in time"
    assert elapsed < delay * 11 * 0.75, (
        f"wall clock {elapsed:.3f}s looks serial for delay={delay}s"
    )


def test_take_snapshot_captures_device_time_before_logcat(tmp_path: Path) -> None:
    # The `logcat_next_since` anchor must be captured before any `logcat`
    # dump starts so logs arriving during the dump window are covered by
    # the next snapshot (overlap rather than gap).  Telephony / IMS /
    # netstat dumps may run either side of the anchor — the contract is
    # specifically about logcat.
    import threading as _threading

    order: list[str] = []
    order_lock = _threading.Lock()

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        with order_lock:
            if "shell" in cmd and cmd[cmd.index("shell") + 1] == "date":
                order.append("anchor")
            elif "logcat" in cmd:
                order.append("logcat")
            else:
                order.append("other")
        return _DummyCompletedProcess(stdout="ok\n")

    connector = AdbConnector()
    with patch("subprocess.run", side_effect=fake_run):
        connector.take_snapshot(str(tmp_path / "snapshots"))

    assert "anchor" in order, "device time anchor was never captured"
    assert "logcat" in order, "logcat dumps were never invoked"
    anchor_idx = order.index("anchor")
    first_logcat_idx = order.index("logcat")
    assert anchor_idx < first_logcat_idx, (
        f"anchor must precede first logcat dump, got order={order[:8]}"
    )


def test_take_snapshot_partial_failure_does_not_block_others(tmp_path: Path) -> None:
    # If one dump raises, the remaining dumps must still run to
    # completion and produce their files.  Parallel execution should not
    # abort the pool on a single failure.
    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> _DummyCompletedProcess:
        if cmd[-2:] == ["dumpsys", "meminfo"]:
            raise RuntimeError("meminfo boom")
        return _DummyCompletedProcess(stdout="ok\n")

    connector = AdbConnector()
    with patch("subprocess.run", side_effect=fake_run):
        snapshot = connector.take_snapshot(str(tmp_path / "snapshots"))

    # The failing task shows up in errors…
    assert any("meminfo" in err for err in snapshot.errors)
    assert snapshot.meminfo_path is None
    # …but independent tasks still produced their outputs.
    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is not None
    assert snapshot.netstat_path is not None
    assert snapshot.dmesg_path is not None
    assert snapshot.logcat_path is not None


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
