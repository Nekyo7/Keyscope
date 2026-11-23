#!/usr/bin/env python3
"""Tests for process_logger.py (standard library unittest, real /proc data).

Run:  python3 -m unittest -v test_process_logger
"""

import contextlib
import io
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import process_logger as pl  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "process_logger.py")
SPECIAL_NAME = 'a)b (c,d|"e'  # 11 characters; Linux allows at most 15 in a process name


class RunningProgram:
    """Runs the real program (stdin and stdout are pipes) and collects its output."""

    def __init__(self, log_path, *extra):
        self.process = subprocess.Popen(
            [sys.executable, SCRIPT, "--log-file", log_path, "--interval", "0.2", *extra],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self._chunks = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        fd = self.process.stdout.fileno()
        while True:
            data = os.read(fd, 4096)
            if not data:
                return
            with self._lock:
                self._chunks.append(data)

    @property
    def output(self):
        with self._lock:
            return b"".join(self._chunks).decode("utf-8", "replace")

    def wait_for(self, text, timeout=8.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if text in self.output:
                return True
            time.sleep(0.05)
        return False

    def send(self, text):
        self.process.stdin.write(text.encode())
        self.process.stdin.flush()

    def finish(self, text="5\n", timeout=15):
        """Send the Exit choice and wait for the program to end; returns its exit code."""
        try:
            self.send(text)
            self.process.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        code = self.process.wait(timeout=timeout)
        self._close()
        return code

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        self._close()

    def _close(self):
        self._reader.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "log.csv")
        self.log = pl.EventLog(self.log_path)
        self.monitor = pl.Monitor(self.log, interval=0.1)
        self.children = []
        self.programs = []
        self.monitor.scan_once()  # baseline

    def tearDown(self):
        self.monitor.stop()
        for program in self.programs:
            program.kill()
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait()
        self.tmp.cleanup()

    def spawn(self, *command):
        child = subprocess.Popen(command or ("sleep", "60"))
        self.children.append(child)
        return child

    def kill(self, child):
        child.kill()
        child.wait()  # reap it, otherwise it stays a zombie and keeps its PID

    def cycle(self):
        """Run one scan and return the events it produced."""
        self.monitor.scan_once()
        return self.monitor.drain()[0]

    @staticmethod
    def find(events, pid, kind):
        return [e for e in events if e.pid == str(pid) and e.event == kind]


class DetectionTests(BaseCase):
    def test_process_creation_detected(self):
        child = self.spawn("sleep", "60")
        started = self.find(self.cycle(), child.pid, pl.EVENT_STARTED)
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0].name, "sleep")
        self.assertEqual(started[0].ppid, str(os.getpid()))
        self.assertTrue(started[0].state)

    def test_process_termination_detected(self):
        child = self.spawn("sleep", "60")
        self.cycle()
        self.kill(child)
        terminated = self.find(self.cycle(), child.pid, pl.EVENT_TERMINATED)
        self.assertEqual(len(terminated), 1)
        self.assertEqual(terminated[0].name, "sleep")
        self.assertIn("Last observed state", pl.format_event(terminated[0]))

    def test_multiple_simultaneous_processes(self):
        children = [self.spawn("sleep", "60") for _ in range(5)]
        events = self.cycle()
        for child in children:
            self.assertEqual(len(self.find(events, child.pid, pl.EVENT_STARTED)), 1)
        for child in children:
            self.kill(child)
        events = self.cycle()
        for child in children:
            self.assertEqual(len(self.find(events, child.pid, pl.EVENT_TERMINATED)), 1)

    def test_baseline_processes_are_not_reported(self):
        child = self.spawn("sleep", "60")           # exists BEFORE monitoring starts
        monitor = pl.Monitor(self.log, interval=0.1)
        monitor.scan_once()                          # baseline
        monitor.scan_once()
        self.assertEqual(self.find(monitor.drain()[0], child.pid, pl.EVENT_STARTED), [])

    def test_real_pid_reuse(self):
        """Forces the kernel to hand the same PID to a new process (needs root)."""
        ns_last_pid = "/proc/sys/kernel/ns_last_pid"
        for _ in range(30):
            first = self.spawn("sleep", "60")
            self.cycle()                             # monitor now knows `first`
            self.kill(first)                         # exits, but we do NOT scan yet
            try:
                with open(ns_last_pid, "w") as f:
                    f.write(str(first.pid - 1))      # next fork() will get first.pid
            except OSError as exc:
                self.skipTest(f"cannot set {ns_last_pid} (run as root): {exc}")
            # Start times have 10 ms resolution (100 ticks per second), so a
            # process that reuses the PID within the same tick cannot be told
            # apart. Real PID reuse takes far longer than that.
            time.sleep(0.05)
            second = self.spawn("sleep", "61")
            if second.pid == first.pid:
                break
            self.kill(second)
            self.cycle()
        else:
            self.skipTest("could not obtain the same PID twice")
        events = self.cycle()
        terminated = self.find(events, first.pid, pl.EVENT_TERMINATED)
        started = self.find(events, first.pid, pl.EVENT_STARTED)
        self.assertEqual(len(terminated), 1, "old process must be reported as terminated")
        self.assertEqual(len(started), 1, "new process must be reported as started")
        self.assertNotEqual(terminated[0].start_ticks, started[0].start_ticks)

    def test_pid_reuse_logic_with_different_start_time(self):
        """Pure-logic check of detect_changes() for the same PID, different start time."""
        old = pl.ProcessInfo(4000, 1, "worker", "Sleeping", 1000)
        new = pl.ProcessInfo(4000, 1, "worker", "Running", 2000)
        started, terminated, snapshot = pl.detect_changes(
            {old.key: old}, pl.ScanResult({new.key: new}, set()))
        self.assertEqual(started, [new])
        self.assertEqual(terminated, [old])
        self.assertEqual(list(snapshot), [new.key])


class NameAndTimestampTests(BaseCase):
    def start_named_process(self):
        code = (f"open('/proc/self/comm','w').write({SPECIAL_NAME!r});"
                "import time; time.sleep(60)")
        child = self.spawn(sys.executable, "-c", code)
        deadline = time.time() + 5
        while time.time() < deadline:                # wait until the name has changed
            try:
                with open(f"/proc/{child.pid}/comm") as f:
                    if f.read().strip() == SPECIAL_NAME:
                        return child
            except OSError:
                pass
            time.sleep(0.05)
        self.fail("child did not rename itself")

    def test_special_characters_in_process_name(self):
        child = self.start_named_process()
        started = self.find(self.cycle(), child.pid, pl.EVENT_STARTED)
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0].name, SPECIAL_NAME)
        # ... and the name survives the CSV round trip
        events, skipped = self.log.read_all()
        self.assertEqual(skipped, 0)
        self.assertEqual([e for e in events if e.pid == str(child.pid)][0].name, SPECIAL_NAME)

    def test_csv_round_trip_of_awkward_names(self):
        names = ['a,b', 'say "hi"', 'pipe|name', 'two\nlines', 'tab\there', 'ünï-çødé', ' padded ']
        for i, name in enumerate(names):
            self.log.append(pl.ProcessEvent("2026-01-01 00:00:00+00:00", pl.EVENT_STARTED,
                                            str(100 + i), "1", name, "Sleeping", "5", ""))
        events, skipped = self.log.read_all()
        self.assertEqual(skipped, 0)
        self.assertEqual([e.name for e in events], names)

    def test_control_characters_are_escaped_on_screen(self):
        self.assertEqual(pl.printable("a\nb\x1b[31m"), "a\\nb\\x1b[31m")

    def test_timestamps_are_timezone_aware_and_consistent(self):
        before = datetime.now().astimezone()
        child = self.spawn("sleep", "60")
        event = self.find(self.cycle(), child.pid, pl.EVENT_STARTED)[0]
        after = datetime.now().astimezone()
        stamp = datetime.fromisoformat(event.timestamp)
        self.assertIsNotNone(stamp.tzinfo, "timestamp must carry a UTC offset")
        self.assertLessEqual(abs((stamp - before).total_seconds()), (after - before).total_seconds() + 1)
        # Exactly the same text is shown on screen and stored in the file.
        self.assertIn(event.timestamp, pl.format_event(event))
        logged, _ = self.log.read_all()
        self.assertEqual([e.timestamp for e in logged if e.pid == str(child.pid)], [event.timestamp])

    def test_all_events_of_one_scan_share_one_timestamp(self):
        children = [self.spawn("sleep", "60") for _ in range(4)]
        events = [e for e in self.cycle() if e.pid in {str(c.pid) for c in children}]
        self.assertEqual(len({e.timestamp for e in events}), 1)

    def test_process_start_time_is_close_to_real_start(self):
        before = datetime.now().astimezone()
        child = self.spawn("sleep", "60")
        event = self.find(self.cycle(), child.pid, pl.EVENT_STARTED)[0]
        if not event.process_start:
            self.skipTest("boot time not available")
        started = datetime.fromisoformat(event.process_start)
        self.assertLess(abs((started - before).total_seconds()), 5)


class LogTests(BaseCase):
    def sample_event(self, pid="1"):
        return pl.ProcessEvent("2026-01-01 00:00:00+00:00", pl.EVENT_TERMINATED,
                               pid, "1", "demo", "Sleeping", "5", "")

    def test_log_persists_after_restart(self):
        child = self.spawn("sleep", "60")
        self.cycle()
        self.kill(child)
        self.cycle()
        reopened = pl.EventLog(self.log_path)        # new object = new program run
        events, _ = reopened.read_all()
        kinds = [e.event for e in events if e.pid == str(child.pid)]
        self.assertEqual(kinds, [pl.EVENT_STARTED, pl.EVENT_TERMINATED])

    def test_missing_and_empty_log(self):
        self.assertEqual(self.log.read_all(), ([], 0))
        with open(self.log_path, "w", newline="") as f:
            f.write(",".join(pl.LOG_HEADER) + "\n")  # header only
        self.assertEqual(self.log.read_all(), ([], 0))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pl.view_log(self.log)
        self.assertIn("No events recorded yet.", out.getvalue())

    def test_damaged_rows_are_skipped_not_fatal(self):
        self.log.append(self.sample_event("7"))
        with open(self.log_path, "a") as f:
            f.write("garbage line\n")
            f.write("a,b,c,d,e,f,g,h,i,j\n")
        events, skipped = self.log.read_all()
        self.assertEqual([e.pid for e in events], ["7"])
        self.assertEqual(skipped, 2)

    def test_clear_keeps_a_backup(self):
        self.log.append(self.sample_event("7"))
        backup = self.log.clear()
        self.assertTrue(os.path.exists(backup))
        self.assertEqual(self.log.read_all(), ([], 0))
        self.assertEqual(pl.EventLog(backup).read_all()[0][0].pid, "7")
        self.log.append(self.sample_event("8"))      # a fresh file with a header is created
        self.assertEqual([e.pid for e in self.log.read_all()[0]], ["8"])

    def test_unrecognised_file_is_backed_up_not_overwritten(self):
        with open(self.log_path, "w") as f:
            f.write("something else entirely\n")
        self.log.append(self.sample_event("9"))
        backups = [n for n in os.listdir(self.tmp.name) if n.endswith(".bak")]
        self.assertEqual(len(backups), 1)
        with open(os.path.join(self.tmp.name, backups[0])) as f:
            self.assertEqual(f.read(), "something else entirely\n")
        self.assertEqual([e.pid for e in self.log.read_all()[0]], ["9"])

    def test_old_pipe_format_is_migrated_with_backup(self):
        legacy = os.path.join(self.tmp.name, "log.log")
        original = ("2026-11-04 10:30:01|STARTED|2456|sleep|Sleeping\n"
                    "2026-11-04 10:30:15|TERMINATED|2456|sleep|Sleeping\n"
                    "2026-11-04 10:31:00|STARTED|3000|we|ird|Running\n"
                    "not a valid line\n")
        with open(legacy, "w") as f:
            f.write(original)
        converted, skipped, backup = self.log.migrate_legacy(legacy)
        self.assertEqual((converted, skipped), (3, 1))
        self.assertFalse(os.path.exists(legacy))
        with open(backup) as f:
            self.assertEqual(f.read(), original)     # nothing lost
        events, _ = self.log.read_all()
        self.assertEqual([e.name for e in events], ["sleep", "sleep", "we|ird"])
        self.assertIsNotNone(datetime.fromisoformat(events[0].timestamp).tzinfo)
        self.assertIsNone(self.log.migrate_legacy(legacy))  # nothing left to migrate

    def test_log_write_error_does_not_stop_monitoring(self):
        broken = pl.EventLog(self.tmp.name)          # a directory cannot be written as a file
        monitor = pl.Monitor(broken, interval=0.1)
        monitor.scan_once()
        child = self.spawn("sleep", "60")
        monitor.scan_once()
        events, notices, _ = monitor.drain()
        self.assertEqual(len(self.find(events, child.pid, pl.EVENT_STARTED)), 1)
        self.assertTrue(any("WARNING (writing the log)" in n for n in notices))

    def test_log_read_error_is_reported(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pl.view_log(pl.EventLog(self.tmp.name))
        self.assertIn("Cannot read the log", out.getvalue())


class ScanErrorTests(BaseCase):
    def test_failed_scan_does_not_report_mass_termination(self):
        self.spawn("sleep", "60")
        self.cycle()
        known = self.monitor.baseline_size
        with mock.patch.object(pl, "PROC_DIR", "/nonexistent-proc"):
            self.monitor.scan_once()
        events, notices, _ = self.monitor.drain()
        self.assertEqual(events, [])
        self.assertTrue(any("WARNING (scanning /proc)" in n for n in notices))
        self.assertEqual(self.monitor.baseline_size, known)   # snapshot kept
        self.monitor.scan_once()                              # /proc is back
        events, notices, _ = self.monitor.drain()
        self.assertEqual(events, [])
        self.assertTrue(any("Recovered" in n for n in notices))

    def test_scan_where_nothing_is_readable_is_rejected(self):
        with mock.patch.object(pl, "read_process", return_value=(pl.READ_UNREADABLE, None)):
            with self.assertRaises(pl.ScanError):
                pl.scan_processes()

    def test_unreadable_process_is_not_called_terminated(self):
        child = self.spawn("sleep", "60")
        self.cycle()
        real = pl.read_process

        def deny(pid):
            return (pl.READ_UNREADABLE, None) if pid == str(child.pid) else real(pid)

        with mock.patch.object(pl, "read_process", side_effect=deny):
            events = self.cycle()
        self.assertEqual(self.find(events, child.pid, pl.EVENT_TERMINATED), [])
        self.assertEqual(self.cycle(), [])                    # readable again: still no events

    def test_vanished_process_is_reported_as_gone(self):
        self.assertEqual(pl.read_process("999999999"), (pl.READ_GONE, None))

    def test_unexpected_error_in_loop_is_survived(self):
        with mock.patch.object(pl, "scan_processes", side_effect=RuntimeError("boom")):
            self.monitor.scan_once()
        self.assertTrue(any("boom" in n for n in self.monitor.drain()[1]))


class ThreadAndInterfaceTests(BaseCase):
    def test_interval_validation(self):
        self.assertEqual(pl.parse_args(["-i", "0.5"]).interval, 0.5)
        for bad in ("0.01", "abc", "-1", "nan", "999999"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                pl.parse_args(["--interval", bad])

    def test_background_thread_starts_detects_and_stops_cleanly(self):
        monitor = pl.Monitor(self.log, interval=0.1)
        self.assertTrue(monitor.start())
        self.assertFalse(monitor.start())            # second start is refused
        child = self.spawn("sleep", "60")
        deadline = time.time() + 5
        events = []
        while time.time() < deadline and not self.find(events, child.pid, pl.EVENT_STARTED):
            time.sleep(0.1)
            events += monitor.drain()[0]
        self.assertTrue(self.find(events, child.pid, pl.EVENT_STARTED))
        self.assertTrue(monitor.stop())
        self.assertFalse(monitor.running)
        self.assertFalse(monitor.stop())
        self.assertNotIn("process-monitor", [t.name for t in threading.enumerate()])

    def run_program(self, text, *extra):
        return subprocess.run(
            [sys.executable, SCRIPT, "--log-file", self.log_path, *extra],
            input=text, capture_output=True, text=True, timeout=30)

    def test_invalid_menu_input(self):
        # "6" no longer exists (the menu has options 1-5), so it is invalid too
        result = self.run_program("9\nabc\n0\n7.5\n6\n5\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("Invalid option"), 5)
        self.assertNotIn("Traceback", result.stderr)

    def test_empty_log_through_the_menu(self):
        result = self.run_program("2\n4\n5\n")
        self.assertIn("No events recorded yet.", result.stdout)
        self.assertIn("The log is already empty.", result.stdout)
        self.assertEqual(result.returncode, 0)

    def test_menu_options_and_exit_on_end_of_input(self):
        result = self.run_program("3\n1\n")        # input ends without choosing Exit
        self.assertEqual(result.returncode, 0)
        self.assertIn("Total running processes:", result.stdout)
        self.assertIn("Monitoring stopped", result.stdout)
        self.assertIn("Goodbye.", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


class AutomaticMonitoringTests(BaseCase):
    """Monitoring starts by itself and events appear without any keyboard input."""

    def launch(self, *extra):
        program = RunningProgram(self.log_path, *extra)
        self.programs.append(program)
        return program

    def test_monitoring_starts_automatically_on_launch(self):
        program = self.launch()                      # nothing is typed at all
        self.assertTrue(program.wait_for("Monitoring started automatically"))
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        self.assertIn("baseline", program.output)
        self.assertEqual(program.finish(), 0)

    def test_menu_has_no_start_option(self):
        program = self.launch()
        self.assertTrue(program.wait_for("5. Exit"))
        menu = program.output
        self.assertNotIn("Start monitoring", menu)
        for line in ("1. Stop monitoring", "2. View activity log",
                     "3. Show current processes", "4. Clear log", "5. Exit"):
            self.assertIn(line, menu)
        self.assertEqual(program.finish(), 0)

    def test_new_process_is_detected_displayed_and_saved_automatically(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        child = self.spawn("sleep", "60")            # no key is pressed after this
        self.assertTrue(program.wait_for(f"PID: {child.pid} (parent PID: {os.getpid()})"),
                        program.output)
        self.assertIn("PROCESS STARTED", program.output)
        events, _ = pl.EventLog(self.log_path).read_all()   # already persisted in the CSV
        started = self.find(events, child.pid, pl.EVENT_STARTED)
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0].name, "sleep")
        self.assertIn(started[0].timestamp, program.output)  # same text on screen and in file
        self.assertEqual(program.finish(), 0)

    def test_terminated_process_is_detected_displayed_and_saved_automatically(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        child = self.spawn("sleep", "60")
        self.assertTrue(program.wait_for(f"PID: {child.pid} (parent PID"))
        self.kill(child)                             # no key is pressed after this either
        self.assertTrue(program.wait_for("PROCESS TERMINATED"), program.output)
        self.assertTrue(program.wait_for("Last observed state:"))
        events, _ = pl.EventLog(self.log_path).read_all()
        self.assertEqual(len(self.find(events, child.pid, pl.EVENT_TERMINATED)), 1)
        self.assertEqual(program.finish(), 0)

    def test_processes_running_at_launch_are_not_reported(self):
        child = self.spawn("sleep", "60")            # exists BEFORE the program starts
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        time.sleep(1.0)                              # several scans
        self.assertNotIn(f"PID: {child.pid} ", program.output)
        self.assertEqual(program.finish(), 0)
        events, _ = pl.EventLog(self.log_path).read_all()
        self.assertEqual(self.find(events, child.pid, pl.EVENT_STARTED), [])

    def test_all_menu_operations_still_work(self):
        pl.EventLog(self.log_path).append(
            pl.ProcessEvent("2026-01-01 00:00:00+00:00", pl.EVENT_STARTED,
                            "42", "1", "earlier", "Sleeping", "5", ""))
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        program.send("2\n")                          # view activity log
        self.assertTrue(program.wait_for("Total events recorded:"))
        self.assertIn("Name: earlier", program.output)
        program.send("3\n")                          # show current processes
        self.assertTrue(program.wait_for("Total running processes:"))
        program.send("1\n")                          # stop monitoring
        self.assertTrue(program.wait_for("Monitoring stopped."))
        program.send("1\n")                          # stopping twice is harmless
        self.assertTrue(program.wait_for("already stopped"))
        program.send("4\n")                          # clear log ...
        self.assertTrue(program.wait_for("Delete all"))
        program.send("n\n")                          # ... but decline
        self.assertTrue(program.wait_for("Cancelled."))
        events, _ = pl.EventLog(self.log_path).read_all()
        self.assertTrue(events, "declining must keep the log")
        program.send("4\ny\n")                      # clear log and confirm with y
        self.assertTrue(program.wait_for("Log cleared."))
        program.send("2\n")
        self.assertTrue(program.wait_for("No events recorded yet."))
        self.assertEqual(program.finish(), 0)
        self.assertTrue([n for n in os.listdir(self.tmp.name) if n.endswith(".bak")],
                        "clearing keeps a backup")

    def test_stopped_monitoring_detects_nothing(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        program.send("1\n")
        self.assertTrue(program.wait_for("Monitoring stopped."))
        child = self.spawn("sleep", "60")
        time.sleep(1.0)
        self.assertNotIn(f"PID: {child.pid} ", program.output)
        self.assertEqual(program.finish(), 0)
        events, _ = pl.EventLog(self.log_path).read_all()
        self.assertEqual(self.find(events, child.pid, pl.EVENT_STARTED), [])

    def test_exit_choice_ends_the_program_cleanly(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        started = time.time()
        self.assertEqual(program.finish(), 0)
        self.assertLess(time.time() - started, 5)
        self.assertIn("Goodbye.", program.output)
        self.assertNotIn("Traceback", program.output)

    def test_end_of_input_ends_the_program_cleanly(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        program.process.stdin.close()                # Ctrl+D
        self.assertEqual(program.process.wait(timeout=10), 0)
        self.assertNotIn("Traceback", program.output)

    def test_ctrl_c_ends_the_program_cleanly(self):
        program = self.launch()
        self.assertTrue(program.wait_for("Monitoring     : RUNNING"))
        program.process.send_signal(signal.SIGINT)
        self.assertEqual(program.process.wait(timeout=10), 0)
        self.assertIn("Goodbye.", program.output)
        self.assertNotIn("Traceback", program.output)

    def test_shutdown_stops_both_background_threads(self):
        monitor = pl.Monitor(self.log, interval=0.1)
        display = pl.LiveDisplay(monitor, pl.Terminal())
        self.assertTrue(monitor.start())
        self.assertTrue(display.start())
        names = [t.name for t in threading.enumerate()]
        self.assertIn("process-monitor", names)
        self.assertIn("event-display", names)
        with contextlib.redirect_stdout(io.StringIO()):
            monitor.stop()
            display.stop()
        names = [t.name for t in threading.enumerate()]
        self.assertNotIn("process-monitor", names)
        self.assertNotIn("event-display", names)
        self.assertFalse(monitor.running)
        self.assertFalse(display.running)

    def test_live_display_prints_events_without_any_input(self):
        display = pl.LiveDisplay(self.monitor, pl.Terminal())
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            display.start()
            child = self.spawn("sleep", "60")
            self.monitor.scan_once()
            deadline = time.time() + 5
            while time.time() < deadline and f"PID: {child.pid} " not in captured.getvalue():
                time.sleep(0.05)
            display.stop()
        self.assertIn("PROCESS STARTED", captured.getvalue())
        self.assertIn(f"PID: {child.pid} ", captured.getvalue())

    def test_events_wait_while_a_menu_command_prints(self):
        terminal = pl.Terminal()
        display = pl.LiveDisplay(self.monitor, terminal)
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            display.start()
            with terminal.output_block():            # a menu command is printing
                child = self.spawn("sleep", "60")
                self.monitor.scan_once()
                time.sleep(0.6)                      # several display polls
                self.assertEqual(captured.getvalue(), "", "events must wait for the command")
            deadline = time.time() + 5
            while time.time() < deadline and f"PID: {child.pid} " not in captured.getvalue():
                time.sleep(0.05)
            display.stop()
        self.assertIn(f"PID: {child.pid} ", captured.getvalue())

    def test_typed_input_is_kept_when_an_event_appears(self):
        """On a real terminal (pty) the prompt and half-typed text are redrawn after an event."""
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, SCRIPT, "--log-file", self.log_path, "--interval", "0.2"],
            stdin=slave, stdout=slave, stderr=slave, env=dict(os.environ, TERM="xterm"))
        os.close(slave)
        collected = []

        def pump(seconds):
            end = time.time() + seconds
            while time.time() < end:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        collected.append(os.read(master, 4096))
                    except OSError:
                        return

        try:
            pump(1.0)
            os.write(master, b"3")                   # typed, but Enter NOT pressed
            pump(0.3)
            child = self.spawn("sleep", "60")
            pump(1.5)
            text = b"".join(collected).decode("utf-8", "replace")
            self.assertIn("PROCESS STARTED", text)
            self.assertIn(f"PID: {child.pid} ", text)
            after_event = text[text.index("PROCESS STARTED"):]
            self.assertIn("Choose an option (1-5): 3", after_event,
                          "prompt and the typed '3' must be redrawn below the event")
            os.write(master, b"\x7f5\n")             # erase the 3, choose 5 = Exit
            pump(1.0)
            self.assertEqual(process.wait(timeout=10), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)


class QueueTests(BaseCase):
    def test_concurrent_draining_delivers_every_event_exactly_once(self):
        monitor = pl.Monitor(self.log, interval=0.05)
        monitor.start()
        children = [self.spawn("sleep", "60") for _ in range(20)]
        wanted = {str(c.pid) for c in children}
        seen = []
        deadline = time.time() + 8
        while time.time() < deadline and not wanted <= {e.pid for e in seen}:
            seen += monitor.drain()[0]               # the main thread reads while the monitor writes
            time.sleep(0.02)
        monitor.stop()
        seen += monitor.drain()[0]
        started = [e.pid for e in seen if e.event == pl.EVENT_STARTED and e.pid in wanted]
        self.assertEqual(sorted(started), sorted(wanted))   # all 20, no duplicates

    def test_full_queue_never_blocks_and_nothing_is_lost_from_the_log(self):
        with mock.patch.object(pl, "MAX_PENDING", 2):
            monitor = pl.Monitor(self.log, interval=0.1)
        monitor.scan_once()                          # baseline
        children = [self.spawn("sleep", "60") for _ in range(5)]
        monitor.scan_once()
        events, _, omitted = monitor.drain()
        self.assertEqual(len(events) + omitted, 5)
        self.assertEqual(omitted, 3)
        logged, _ = self.log.read_all()
        for child in children:
            self.assertEqual(len(self.find(logged, child.pid, pl.EVENT_STARTED)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)