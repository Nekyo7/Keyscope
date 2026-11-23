#!/usr/bin/env python3
"""Linux Process Activity Logger

Periodically scans the Linux /proc filesystem, detects processes that were
created or terminated, and records every event with a timezone-aware
timestamp in a CSV log file. Monitoring starts automatically when the program
is launched, and every new event is shown on the screen as soon as it is
detected. A terminal menu lets you view the history, list the running
processes, stop monitoring, clear the history and exit.

Python 3 standard library only. No database, no external packages.

Known limitation (by design of periodic polling):
    The program compares one scan with the next. A process that starts AND
    exits between two scans is never seen, so detection of every process is
    NOT guaranteed. A shorter --interval reduces, but cannot remove, this gap.
    The timestamp of an event is the time the scan DETECTED it, which can be
    up to one interval later than the real start or exit.

Usage:
    python3 process_logger.py [--interval SECONDS] [--log-file PATH]
"""

import argparse
import contextlib
import csv
import functools
import os
import queue
import sys
import threading
from collections import Counter
from dataclasses import astuple, dataclass
from datetime import datetime

try:
    import readline  # standard library; lets the live display redraw what the user is typing
except ImportError:
    readline = None

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
PROC_DIR = "/proc"
DEFAULT_INTERVAL = 1.0   # seconds between scans (change with --interval)
MIN_INTERVAL = 0.1
MAX_INTERVAL = 3600.0
DEFAULT_LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "process_activity.csv"
)
LOG_HEADER = [
    "timestamp", "event", "pid", "ppid", "name", "state",
    "start_ticks", "process_start",
]
EVENT_STARTED = "STARTED"
EVENT_TERMINATED = "TERMINATED"
EVENT_NAMES = (EVENT_STARTED, EVENT_TERMINATED)
VIEW_LIMIT = 30      # events shown by default when viewing a long log
MAX_PENDING = 500    # events/notices that may wait in the queues for the display thread
DISPLAY_POLL = 0.2   # seconds the display thread waits for new events before re-checking

# Process state letters used in /proc/<pid>/stat (see "man 5 proc").
STATE_NAMES = {
    "R": "Running",
    "S": "Sleeping",
    "D": "Disk Sleep",
    "Z": "Zombie",
    "T": "Stopped",
    "t": "Tracing Stop",
    "X": "Dead",
    "I": "Idle",
}

# Result codes for reading a single process.
READ_OK = "ok"
READ_GONE = "gone"              # process exited while we were scanning (normal)
READ_UNREADABLE = "unreadable"  # exists, but we could not read/parse it


class ScanError(Exception):
    """The /proc scan failed as a whole, so its result must not be trusted."""


class LogError(Exception):
    """The log file could not be read, written or backed up."""


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ProcessInfo:
    """One process as seen in /proc/<pid>/stat."""
    pid: int
    ppid: int
    name: str
    state: str
    start_ticks: int  # field 22 of /proc/<pid>/stat: start time in clock ticks since boot

    @property
    def key(self):
        # PID alone is not unique over time: Linux reuses PIDs. The pair
        # (PID, start time) identifies one specific process instance.
        return (self.pid, self.start_ticks)


@dataclass
class ScanResult:
    processes: dict        # key (pid, start_ticks) -> ProcessInfo
    unreadable_pids: set   # PIDs that exist but could not be read this scan


@dataclass(frozen=True)
class ProcessEvent:
    """One log record. All fields are text, in the same order as LOG_HEADER."""
    timestamp: str
    event: str
    pid: str
    ppid: str
    name: str
    state: str
    start_ticks: str
    process_start: str


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------
def current_timestamp():
    """Local time WITH UTC offset, e.g. '2026-11-20 12:21:31+05:30'.

    This exact string is used both on screen and in the log file.
    """
    return datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")


@functools.lru_cache(maxsize=1)
def read_boot_time():
    """Boot time (seconds since the epoch) from the 'btime' line of /proc/stat."""
    try:
        with open(f"{PROC_DIR}/stat", "r") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def process_start_time(start_ticks):
    """Approximate wall-clock start time of a process, or '' if unknown.

    /proc stores start times as clock ticks since boot, so:
        start = boot time + ticks / ticks-per-second
    The result is approximate (e.g. if the VM clock was adjusted after boot).
    """
    boot = read_boot_time()
    try:
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        if boot is None or ticks_per_second <= 0:
            return ""
        started = datetime.fromtimestamp(boot + int(start_ticks) / ticks_per_second)
        return started.astimezone().isoformat(sep=" ", timespec="seconds")
    except (ValueError, OSError, OverflowError):
        return ""


# --------------------------------------------------------------------------
# /proc reading
# --------------------------------------------------------------------------
def parse_stat(data):
    """Turn the text of /proc/<pid>/stat into a ProcessInfo (None if malformed).

    Layout: "<pid> (<comm>) <state> <ppid> ... <starttime> ..."
    The command name (comm) may itself contain spaces or ')', so it is cut
    out between the FIRST '(' and the LAST ')'.
    """
    left = data.find("(")
    right = data.rfind(")")
    if left == -1 or right <= left:
        return None
    try:
        fields = data[right + 1:].split()  # fields[0] is field 3 (state)
        return ProcessInfo(
            pid=int(data[:left]),
            ppid=int(fields[1]),                              # field 4
            name=data[left + 1:right],
            state=STATE_NAMES.get(fields[0], fields[0]),      # field 3
            start_ticks=int(fields[19]),                      # field 22
        )
    except (ValueError, IndexError):
        return None


def read_process(pid):
    """Read one process. Returns (READ_OK, ProcessInfo) or (status, None).

    READ_GONE        - the process exited between listing /proc and reading it.
    READ_UNREADABLE  - it exists but cannot be read (e.g. permission denied when
                       /proc is mounted with hidepid) or its data is malformed.
                       We must NOT treat this as a termination.
    """
    try:
        with open(f"{PROC_DIR}/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except (FileNotFoundError, ProcessLookupError):
        return READ_GONE, None
    except OSError:  # PermissionError and any other unexpected I/O error
        return READ_UNREADABLE, None

    info = parse_stat(data)
    if info is None:
        return READ_UNREADABLE, None
    return READ_OK, info


def scan_processes():
    """Scan /proc once. Raises ScanError if the scan as a whole is unusable."""
    try:
        entries = os.listdir(PROC_DIR)  # one numeric directory per process
    except OSError as exc:
        raise ScanError(f"cannot list {PROC_DIR}: {exc}") from exc

    processes = {}
    unreadable = set()
    for entry in entries:
        if not entry.isdigit():  # skip non-process entries such as 'cpuinfo'
            continue
        status, info = read_process(entry)
        if status == READ_OK:
            processes[info.key] = info
        elif status == READ_UNREADABLE:
            unreadable.add(int(entry))
        # READ_GONE: the process just exited, simply leave it out.

    if not processes:
        # A real Linux system always has running processes, so an empty result
        # means the scan failed. Using it would report everything as terminated.
        raise ScanError("no process could be read from /proc (incomplete scan)")
    return ScanResult(processes, unreadable)


def detect_changes(previous, scan):
    """Compare the previous snapshot with a new scan.

    Returns (started, terminated, new_snapshot).
    A previous process is reported as terminated only when its (PID, start time)
    is gone AND its PID was readable in this scan. If the PID is merely
    unreadable we cannot prove it exited, so it is carried over unchanged.
    A reused PID has a different start time, so it shows up as one
    TERMINATED process plus one STARTED process.
    """
    current = scan.processes
    started = [current[key] for key in current.keys() - previous.keys()]

    terminated = []
    carried_over = {}
    for key in previous.keys() - current.keys():
        if key[0] in scan.unreadable_pids:
            carried_over[key] = previous[key]
        else:
            terminated.append(previous[key])

    new_snapshot = dict(current)
    new_snapshot.update(carried_over)
    started.sort(key=lambda p: p.pid)
    terminated.sort(key=lambda p: p.pid)
    return started, terminated, new_snapshot


def make_event(timestamp, event, info):
    return ProcessEvent(
        timestamp=timestamp,
        event=event,
        pid=str(info.pid),
        ppid=str(info.ppid),
        name=info.name,
        state=info.state,
        start_ticks=str(info.start_ticks),
        process_start=process_start_time(info.start_ticks),
    )


# --------------------------------------------------------------------------
# Log file (CSV)
# --------------------------------------------------------------------------
def make_backup_path(path, label):
    """Return an unused file name like '<path>.<label>-20261120-122131.bak'."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{path}.{label}-{stamp}"
    candidate, counter = f"{base}.bak", 1
    while os.path.exists(candidate):
        candidate = f"{base}-{counter}.bak"
        counter += 1
    return candidate


def parse_legacy_line(line):
    """Convert one line of the old pipe-separated log into a ProcessEvent.

    Old format: TIMESTAMP|EVENT|PID|NAME|STATE. The name is rebuilt from the
    middle fields, so names that contain '|' are recovered correctly.
    """
    parts = line.rstrip("\r\n").split("|")
    if len(parts) < 5 or parts[1] not in EVENT_NAMES or not parts[2].isdigit():
        return None
    try:
        # Old timestamps had no time zone; assume the local zone.
        timestamp = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S").astimezone()
        timestamp = timestamp.isoformat(sep=" ", timespec="seconds")
    except ValueError:
        timestamp = parts[0]
    return ProcessEvent(timestamp, parts[1], parts[2], "", "|".join(parts[3:-1]),
                        parts[-1], "", "")


class EventLog:
    """CSV event log. All file access is serialised by one lock, so the
    monitoring thread and the menu thread can never corrupt each other."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._header_checked = False

    # -- writing ----------------------------------------------------------
    def append(self, event):
        """Add one event. Raises LogError if the file cannot be written."""
        try:
            with self._lock:
                self._prepare_file()
                # newline="" is required by the csv module; it quotes commas,
                # quotes and line breaks inside fields (e.g. odd process names).
                with open(self.path, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f, lineterminator="\n").writerow(astuple(event))
        except OSError as exc:
            raise LogError(f"cannot write {self.path}: {exc}") from exc

    def _prepare_file(self):
        """Make sure the file exists and starts with the expected CSV header.
        A file with a different header is moved to a backup, never overwritten."""
        has_data = os.path.exists(self.path) and os.path.getsize(self.path) > 0
        if has_data and not self._header_checked:
            with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
                first_row = next(csv.reader(f), None)
            if first_row != LOG_HEADER:
                os.replace(self.path, make_backup_path(self.path, "unrecognised"))
                has_data = False
        if not has_data:
            with open(self.path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f, lineterminator="\n").writerow(LOG_HEADER)
        self._header_checked = True

    # -- reading ----------------------------------------------------------
    def read_all(self):
        """Return (events, skipped_rows). A missing file is simply an empty log."""
        with self._lock:
            if not os.path.exists(self.path):
                return [], 0
            events, skipped = [], 0
            try:
                with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
                    for row in csv.DictReader(f):
                        event = self._row_to_event(row)
                        if event is None:
                            skipped += 1
                        else:
                            events.append(event)
            except (OSError, csv.Error) as exc:
                raise LogError(f"cannot read {self.path}: {exc}") from exc
            return events, skipped

    @staticmethod
    def _row_to_event(row):
        if None in row or row.get("event") not in EVENT_NAMES or not row.get("pid"):
            return None  # extra columns, unknown event or missing PID: damaged row
        values = {column: row.get(column) or "" for column in LOG_HEADER}
        return ProcessEvent(**values)

    # -- maintenance ------------------------------------------------------
    def clear(self):
        """Move the current log to a backup file. Returns the backup path."""
        with self._lock:
            if not os.path.exists(self.path):
                return None
            backup = make_backup_path(self.path, "cleared")
            try:
                os.replace(self.path, backup)
            except OSError as exc:
                raise LogError(f"cannot back up {self.path}: {exc}") from exc
            return backup

    def migrate_legacy(self, legacy_path):
        """Convert the old pipe-separated log to CSV, keeping the old file as .bak.

        Returns (converted, skipped, backup_path), or None if nothing to do.
        Nothing is migrated if a non-empty CSV log already exists.
        """
        if os.path.abspath(legacy_path) == os.path.abspath(self.path):
            return None
        if not os.path.isfile(legacy_path):
            return None
        with self._lock:
            if os.path.exists(self.path) and os.path.getsize(self.path) > 0:
                return None
            try:
                events, skipped = [], 0
                with open(legacy_path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        event = parse_legacy_line(line)
                        if event is None:
                            skipped += 1
                        else:
                            events.append(event)
                # Write the new file completely first, then retire the old one,
                # so the old records are never lost if something fails midway.
                with open(self.path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f, lineterminator="\n")
                    writer.writerow(LOG_HEADER)
                    writer.writerows(astuple(e) for e in events)
                backup = make_backup_path(legacy_path, "old-format")
                os.replace(legacy_path, backup)
            except OSError as exc:
                raise LogError(f"cannot migrate {legacy_path}: {exc}") from exc
            self._header_checked = True
            return len(events), skipped, backup


# --------------------------------------------------------------------------
# Monitor (background thread: never prints, never reads input)
# --------------------------------------------------------------------------
class Monitor:
    """Scans /proc every `interval` seconds in a background thread.

    The thread only writes to the log file and puts events and notices into
    thread-safe queues (queue.Queue). It never prints and never calls input();
    the LiveDisplay thread takes the items out of the queues with drain().
    """

    def __init__(self, log, interval=DEFAULT_INTERVAL):
        self.log = log
        self.interval = interval
        self.session_events = 0
        self._stop = threading.Event()
        self._thread = None
        self._previous = None       # snapshot of the previous scan (None = no baseline yet)
        self._lock = threading.Lock()
        self._events = queue.Queue(maxsize=MAX_PENDING)
        self._notices = queue.Queue(maxsize=MAX_PENDING)
        self._dropped = 0           # events that did not fit in the queue (they are in the log)
        self._output_ready = threading.Event()
        self._problems = {}         # topic -> current problem text

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    @property
    def baseline_size(self):
        return len(self._previous) if self._previous else 0

    def start(self):
        """Take the baseline scan, then start the background thread."""
        if self.running:
            return False
        self._stop.clear()
        self.session_events = 0
        self._previous = None
        self.scan_once()  # baseline: processes already running are not logged
        self._thread = threading.Thread(target=self._run, name="process-monitor", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """Stop the thread and wait for it to finish."""
        if not self.running:
            return False
        self._stop.set()
        self._thread.join()
        return True

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self.scan_once()
            except Exception as exc:  # keep monitoring whatever goes wrong
                self._report("monitoring loop", f"unexpected error: {exc!r}")

    def scan_once(self):
        """One scan-and-compare cycle (also called directly by the tests)."""
        try:
            scan = scan_processes()
        except ScanError as exc:
            # Keep the previous snapshot; do NOT report mass terminations.
            self._report("scanning /proc", f"scan skipped, no events were generated: {exc}")
            return
        except Exception as exc:
            self._report("scanning /proc", f"unexpected scan error, scan skipped: {exc!r}")
            return
        self._report("scanning /proc", None)

        timestamp = current_timestamp()  # one timestamp for everything found in this scan
        if self._previous is None:
            self._previous = scan.processes  # baseline
            return

        started, terminated, self._previous = detect_changes(self._previous, scan)
        for info in terminated:
            self._record(make_event(timestamp, EVENT_TERMINATED, info))
        for info in started:
            self._record(make_event(timestamp, EVENT_STARTED, info))

    def _record(self, event):
        try:
            self.log.append(event)
            self._report("writing the log", None)
        except LogError as exc:
            self._report("writing the log", f"event not saved to the log file: {exc}")
        with self._lock:
            self.session_events += 1
        self._enqueue(self._events, event)

    def _report(self, topic, problem):
        """Queue a notice when a topic starts failing, changes, or recovers."""
        with self._lock:
            before = self._problems.get(topic)
            if problem == before:
                return
            if problem is None:
                del self._problems[topic]
                self._enqueue(self._notices, f"Recovered: {topic} works again.")
            else:
                self._problems[topic] = problem
                self._enqueue(self._notices, f"WARNING ({topic}): {problem}")

    def _enqueue(self, target, item):
        """Put an item in a queue without ever blocking the scanning thread."""
        try:
            target.put_nowait(item)
        except queue.Full:
            if target is self._events:
                with self._lock:
                    self._dropped += 1
        self._output_ready.set()

    def drain(self):
        """Take everything queued so far: (events, notices, omitted_count)."""
        events, notices = [], []
        for source, items in ((self._events, events), (self._notices, notices)):
            while True:
                try:
                    items.append(source.get_nowait())
                except queue.Empty:
                    break
        with self._lock:
            omitted, self._dropped = self._dropped, 0
        return events, notices, omitted

    def wait_for_output(self, timeout):
        """Block until something is queued or `timeout` passes (used by LiveDisplay)."""
        if self._output_ready.wait(timeout):
            self._output_ready.clear()
            return True
        return False


# --------------------------------------------------------------------------
# Terminal display
# --------------------------------------------------------------------------
def printable(text):
    """Escape control characters so unusual process names cannot garble the terminal."""
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in str(text)
    )


def format_event(event):
    parent = f" (parent PID: {printable(event.ppid)})" if event.ppid else ""
    # A terminated process can no longer be read, so its state is the last one
    # seen in the previous scan, not necessarily the state at the moment of exit.
    state_label = "State" if event.event == EVENT_STARTED else "Last observed state"
    lines = [
        f"[{printable(event.timestamp)}] PROCESS {printable(event.event)}",
        f"PID: {printable(event.pid)}{parent}",
        f"Name: {printable(event.name)}",
        f"{state_label}: {printable(event.state)}",
    ]
    if event.process_start:
        lines.append(f"Process start time: {printable(event.process_start)} (approx.)")
    return "\n".join(lines)


def pending_text(monitor):
    """Return the text for everything queued by the monitor ('' if nothing is waiting)."""
    events, notices, omitted = monitor.drain()
    lines = list(notices)
    if omitted:
        lines.append(f"({omitted} event(s) could not be displayed; they are saved in the log.)")
    for event in events:
        lines.append("\n" + format_event(event))
    return "\n".join(lines)


class Terminal:
    """Stops the live display and the menu from clashing on the terminal.

    * emit()         (display thread) prints a new event even while the user is
                     typing. On a real terminal it clears the prompt line, prints
                     the event and redraws the prompt with what was typed so far.
    * output_block() (main thread) holds the terminal while a menu command prints,
                     so new events wait until that command's output is complete.
    * read_line()    (main thread only) is the only place that calls input().
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._block_open = False   # True while the main thread holds the lock in output_block()
        self._prompt = None        # prompt text while input() is waiting, else None
        self._next_prompt = None

    @property
    def interactive(self):
        try:
            return sys.stdin.isatty() and sys.stdout.isatty()
        except (AttributeError, ValueError):
            return False

    @contextlib.contextmanager
    def output_block(self):
        with self._lock:
            self._block_open = True
            try:
                yield
            finally:
                self._block_open = False

    def _prompt_displayed(self):
        """readline calls this after the prompt is on screen and before the user types."""
        with self._lock:
            self._prompt = self._next_prompt

    def read_line(self, prompt):
        """Read one line from the user. Returns None on Ctrl+D / Ctrl+C."""
        held = self._block_open
        if held:                      # let events appear while we wait for the user
            self._block_open = False
            self._lock.release()
        use_hook = readline is not None and self.interactive and hasattr(readline, "set_pre_input_hook")
        try:
            self._next_prompt = prompt
            if use_hook:
                readline.set_pre_input_hook(self._prompt_displayed)
            else:
                self._prompt = prompt
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        finally:
            if use_hook:
                readline.set_pre_input_hook(None)
            self._lock.acquire()
            self._prompt = None
            if held:
                self._block_open = True   # the caller's output_block() continues
            else:
                self._lock.release()

    def emit(self, text):
        """Print text from the display thread without damaging the input line."""
        with self._lock:
            out = sys.stdout
            if self._prompt is not None and self.interactive:
                typed = readline.get_line_buffer() if readline is not None else ""
                out.write("\r\x1b[K" + text + "\n" + self._prompt + typed)
            else:
                out.write(text + "\n")
            out.flush()


terminal = Terminal()


class LiveDisplay:
    """Display thread: shows each event as soon as the monitor queues it.

    It only reads from the monitor's queues and prints through Terminal.emit();
    it never calls input() and never touches the log file.
    """

    def __init__(self, monitor, term=None):
        self.monitor = monitor
        self.terminal = term or terminal
        self._stop = threading.Event()
        self._thread = None

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="event-display", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """Stop the thread, then show anything that is still queued."""
        if self._thread is not None:
            self._stop.set()
            self._thread.join()
            self._thread = None
        self.flush()

    def flush(self):
        text = pending_text(self.monitor)
        if text:
            self.terminal.emit(text)

    def _run(self):
        while not self._stop.is_set():
            if self.monitor.wait_for_output(DISPLAY_POLL) and not self._stop.is_set():
                try:
                    self.flush()
                except (OSError, ValueError):  # the terminal is gone (closed pipe)
                    return


def show_current_processes():
    try:
        scan = scan_processes()
    except ScanError as exc:
        print(f"\nCannot read the process list: {exc}")
        return
    processes = sorted(scan.processes.values(), key=lambda p: p.pid)
    print(f"\n{'PID':<8}{'PPID':<8}{'STATE':<14}{'STARTED (approx.)':<21}NAME")
    print("-" * 70)
    for p in processes:
        started = process_start_time(p.start_ticks)[:19] or "-"
        print(f"{p.pid:<8}{p.ppid:<8}{p.state:<14}{started:<21}{printable(p.name)[:30]}")
    counts = Counter(p.state for p in processes)
    summary = ", ".join(f"{state}: {n}" for state, n in counts.most_common())
    print(f"\nTotal running processes: {len(processes)}")
    print(f"By state: {summary}")
    if scan.unreadable_pids:
        print(f"Note: {len(scan.unreadable_pids)} process(es) could not be read and are not listed.")


def view_log(log):
    try:
        events, skipped = log.read_all()
    except LogError as exc:
        print(f"\nCannot read the log: {exc}")
        return
    if not events:
        print("\nNo events recorded yet.")
    else:
        shown = events
        if len(events) > VIEW_LIMIT:
            answer = read_line(
                f"\nThe log has {len(events)} events. "
                f"Press Enter for the latest {VIEW_LIMIT}, or type 'a' for all: "
            )
            if (answer or "").strip().lower() != "a":
                shown = events[-VIEW_LIMIT:]
        print("\n===== PROCESS ACTIVITY HISTORY =====")
        for event in shown:
            print()
            print(format_event(event))
        counts = Counter(e.event for e in events)
        print(f"\nShowing {len(shown)} of {len(events)} events.")
        print(f"Total events recorded: {len(events)} "
              f"({counts[EVENT_STARTED]} started, {counts[EVENT_TERMINATED]} terminated)")
    if skipped:
        print(f"Note: {skipped} damaged log row(s) were skipped.")


def clear_log(log):
    try:
        events, _ = log.read_all()
    except LogError as exc:
        print(f"\nCannot read the log: {exc}")
        return
    if not events:
        print("\nThe log is already empty.")
        return
    answer = read_line(f"Delete all {len(events)} events? A backup copy is kept. (y/n): ")
    if (answer or "").strip().lower() != "y":
        print("Cancelled. The log was not changed.")
        return
    try:
        backup = log.clear()
    except LogError as exc:
        print(f"Cannot clear the log: {exc}")
        return
    print(f"Log cleared. The previous log was saved as: {backup}")


def start_monitoring(monitor):
    """Called automatically when the program launches (there is no menu option for it)."""
    if not monitor.start():
        print("Monitoring is already running.")
        return
    if monitor.baseline_size:
        print(f"Monitoring started automatically. The {monitor.baseline_size} processes running "
              "now are the baseline and will not be logged as new.")
    else:
        print("Monitoring started automatically, waiting for the first successful scan.")
    print("New events are displayed here as soon as they are detected.")


def stop_monitoring(monitor):
    if monitor.stop():
        print(f"Monitoring stopped. Events this session: {monitor.session_events}")
        print("Restart the program to monitor again.")
    else:
        print("Monitoring is already stopped. Restart the program to monitor again.")


def print_menu(monitor):
    status = "RUNNING" if monitor.running else "STOPPED"
    print("\n" + "=" * 40)
    print("   LINUX PROCESS ACTIVITY LOGGER")
    print("=" * 40)
    print(f"   Monitoring     : {status} (scan every {monitor.interval:g} s)")
    print(f"   Session events : {monitor.session_events}")
    print("-" * 40)
    print("1. Stop monitoring")
    print("2. View activity log")
    print("3. Show current processes")
    print("4. Clear log")
    print("5. Exit")
    print("(New events appear automatically; press Enter to show this menu again)")


def read_line(prompt):
    """input() wrapper. Only the main thread may call it.
    Returns None on Ctrl+D / Ctrl+C."""
    return terminal.read_line(prompt)


def run_menu(monitor, log):
    """Menu loop. Returns when the user chooses Exit (or presses Ctrl+D / Ctrl+C)."""
    with terminal.output_block():
        print_menu(monitor)
    while True:
        answer = read_line("Choose an option (1-5): ")
        choice = "5" if answer is None else answer.strip()
        if choice == "5":
            return
        # While a command prints, new events wait so they cannot split its output.
        with terminal.output_block():
            if choice == "":
                pass
            elif choice == "1":
                stop_monitoring(monitor)
            elif choice == "2":
                view_log(log)
            elif choice == "3":
                show_current_processes()
            elif choice == "4":
                clear_log(log)
            else:
                print("Invalid option. Enter a number from 1 to 5.")
            print_menu(monitor)
            sys.stdout.flush()


# --------------------------------------------------------------------------
# Start-up
# --------------------------------------------------------------------------
def interval_argument(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a number")
    if not MIN_INTERVAL <= value <= MAX_INTERVAL:
        raise argparse.ArgumentTypeError(
            f"must be between {MIN_INTERVAL:g} and {MAX_INTERVAL:g} seconds")
    return value


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Linux Process Activity Logger")
    parser.add_argument("-i", "--interval", type=interval_argument, default=DEFAULT_INTERVAL,
                        help=f"seconds between scans (default {DEFAULT_INTERVAL:g})")
    parser.add_argument("-l", "--log-file", default=DEFAULT_LOG_FILE,
                        help="CSV log file (default: process_activity.csv next to the script)")
    return parser.parse_args(argv)


def migrate_old_log(log):
    """If an old 'process_activity.log' exists, convert it and keep it as a backup."""
    legacy_path = os.path.splitext(log.path)[0] + ".log"
    try:
        result = log.migrate_legacy(legacy_path)
    except LogError as exc:
        print(f"Warning: old log not migrated: {exc}")
        return
    if result:
        converted, skipped, backup = result
        print(f"Old log converted to CSV: {converted} event(s), {skipped} unreadable line(s).")
        print(f"The original file was kept as: {backup}")


def main(argv=None):
    args = parse_args(argv)
    if not os.path.isdir(PROC_DIR):
        print("This program needs a Linux system with a /proc filesystem.")
        return 1

    log = EventLog(args.log_file)
    migrate_old_log(log)
    monitor = Monitor(log, args.interval)
    display = LiveDisplay(monitor)
    try:
        start_monitoring(monitor)   # monitoring starts automatically at launch
        display.start()
        run_menu(monitor, log)
    except KeyboardInterrupt:
        print()
    finally:
        monitor.stop()              # always end both background threads, even after an error
        display.stop()              # ...and show the last events that were still queued
    print("Goodbye.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())