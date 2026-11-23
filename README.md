# Linux Process Activity Logger (improved version)

Monitors Linux processes by periodically scanning `/proc`, detects processes that were created or terminated, and keeps a timestamped CSV activity log. **Monitoring starts automatically when the program launches**, new events are shown on screen the moment they are detected, and a terminal menu lets you view the history, list running processes, stop monitoring, clear the history and exit. Python 3 standard library only; no database, no external packages, no GUI.

## 1. File structure

```
process_logger/
├── process_logger.py        # the program (improved version of your file)
├── test_process_logger.py   # 46 automated tests (unittest, real /proc data)
├── README.md                # this file
└── process_activity.csv     # created on the first event (the log)
```

If you ran the old version earlier, an old `process_activity.log` may exist in the same folder. It is converted automatically on the next start and kept as `process_activity.log.old-format-<date>.bak` (see section 3, item 8).

## 2. Commands to run in Kali Linux

```bash
# 1. Go to the project folder
cd ~/process_logger

# 2. Check Python 3 (preinstalled on Kali)
python3 --version

# 3. Run the program (monitoring starts immediately; default: scan every 1 second)
python3 process_logger.py

# 4. Other options
python3 process_logger.py --interval 0.5            # scan every 0.5 s (allowed: 0.1 to 3600)
python3 process_logger.py --log-file /tmp/demo.csv  # use another log file
python3 process_logger.py --help

# 5. Run all automated tests
python3 -m unittest -v test_process_logger
# The real PID-reuse test needs root; without root it is reported as skipped
sudo python3 -m unittest -v test_process_logger

# 6. Look at the log outside the program
column -s, -t process_activity.csv | less -S
```

No `sudo` is needed to run the logger itself.

## 3. Every significant modification

| # | Area | Before | Now | Why |
|---|------|--------|-----|-----|
| 1 | Reading `/proc` | `read_process()` returned `None` for every failure | Returns a status: **ok**, **gone** (exited during the scan) or **unreadable** (permission denied or malformed data). The `/proc/[PID]/stat` parsing and the `(PID, start_time)` key are unchanged | A process that cannot be read is not the same as a process that has exited |
| 2 | Failed scans | A failed scan would have made every process look terminated | `scan_processes()` raises `ScanError` if `/proc` cannot be listed or if no process at all can be read. The monitor skips that scan, keeps the previous snapshot, generates no events and shows a warning (and a "Recovered" notice later) | Prevents false mass-termination events |
| 3 | Unreadable processes | Silently dropped | `detect_changes()` carries an unreadable PID over to the next snapshot instead of calling it terminated | Same reason, at single-process level |
| 4 | Event detection | Inside the thread loop | Separate function `detect_changes()`. Terminated events are listed before started ones, so a reused PID reads naturally. Baseline is unchanged (existing processes are not logged) but is now taken in `start()` before the thread begins, so a process launched right after the program starts is not missed | Modular and testable |
| 5 | Interval | Constant in the code | `--interval SECONDS` (0.1 to 3600, validated). Shown in the menu | Configurable interval |
| 6 | Timestamps | `datetime.now()` called separately for screen and file, no time zone | One `current_timestamp()` per scan, with UTC offset (e.g. `2026-11-20 12:21:31+05:30`). The same string is printed and stored | One consistent, timezone-aware time |
| 7 | Log format | `TIME\|EVENT\|PID\|NAME\|STATE`. A name containing `\|` broke the file | CSV through Python's `csv` module (`process_activity.csv`) with columns `timestamp, event, pid, ppid, name, state, start_ticks, process_start`. Commas, quotes, `\|`, line breaks and Unicode in names are quoted correctly | Delimiter-safe storage |
| 8 | Old logs | Not considered | **Migration:** an old `process_activity.log` is converted to CSV (names containing `\|` are recovered, naive timestamps get the local offset) and the original is kept as a `.bak`. **Clear log** now moves the log to a `.bak` instead of deleting it. A file with an unexpected header is moved to a `.bak`, never overwritten | No stored record is lost |
| 9 | Log errors | An I/O error would crash the thread | `EventLog` raises `LogError`. The monitor shows a warning once, keeps monitoring and still displays the event. Viewing or clearing a log that cannot be read prints a message. Damaged rows are skipped and counted | Graceful handling |
| 10 | Terminated state | Not shown | Shown as **Last observed state** (from the previous scan), because the exact state at the moment of exit cannot be read | Honest labelling |
| 11 | Extra process info | PID, name, state | Also parent PID, and the approximate process start time (boot time + start ticks / ticks per second) | "Process start information" |
| 12 | Background output | Thread called `print()` while the user typed | The monitoring thread never prints and never reads input. It puts events and notices into thread-safe `queue.Queue` objects. A separate **display thread** (`LiveDisplay`) takes them out and prints them (see row 19). Names are escaped so control characters cannot garble the terminal | Menu input is never corrupted |
| 13 | Menu | 6 options, start was manual | **5 options** (see row 18). Header shows monitoring status, interval and **session event count**. Empty input shows the menu again. Invalid input prints a message. Ctrl+C / Ctrl+D exit cleanly | Faculty feedback |
| 14 | Log viewer | Printed everything | Same format plus a total with started/terminated counts. Long logs show the latest 30 unless you type `a` | Readable in a demo |
| 15 | Current processes | PID, name, state | PID, PPID, state, approximate start time, name, plus a count by state and a note if some processes were unreadable | More informative |
| 16 | Exit | Thread stopped by `stop()` | `main()` always calls `monitor.stop()` in a `finally` block, and the last queued events are shown first | Clean shutdown |
| 17 | Code | One thread-unsafe global lock, plain dicts | Small classes (`ProcessInfo`, `ProcessEvent`, `EventLog`, `Monitor`), docstrings, comments on Linux-specific parts (`/proc/PID/stat` fields, `btime`, `SC_CLK_TCK`, `hidepid`) | Quality |
| 18 | Automatic start | Monitoring began only after choosing menu option 1 | `main()` starts monitoring at launch (the baseline scan is taken first, so processes already running are still not reported as new). The "Start monitoring" option is removed. Menu: **1** Stop monitoring, **2** View activity log, **3** Show current processes, **4** Clear log (with confirmation), **5** Exit | Faculty feedback |
| 19 | Live display | Events were shown only when the user pressed Enter or chose an option | `LiveDisplay` thread prints each event as soon as it is queued. `Terminal` keeps it from clashing with input: on a real terminal it clears the prompt line, prints the event and redraws the prompt **with the text typed so far**; while a menu command is printing (`output_block()`), new events wait until that output is complete. `input()` is called only by the main thread | Events without pressing Enter, no conflicts with typing |
| 20 | Shutdown | `monitor.stop()` only | Exit, Ctrl+C, Ctrl+D or an error stop the monitoring thread, then the display thread, which first shows any events still queued. A full queue never blocks scanning; events that do not fit are counted and are still saved in the log | Clean shutdown |

## 4. Test cases and expected results

Run: `python3 -m unittest -v test_process_logger`. Every test uses real processes (`sleep`, a child renaming itself) and the real `/proc`; only the error tests replace `/proc` access to force a failure.

| Requirement | Test | Expected |
|---|---|---|
| Creation | `test_process_creation_detected` | One STARTED event with the right PID, name `sleep`, parent PID = test process |
| Termination | `test_process_termination_detected` | One TERMINATED event; screen text says "Last observed state" |
| Several processes | `test_multiple_simultaneous_processes` | 5 STARTED events, then 5 TERMINATED events |
| Baseline | `test_baseline_processes_are_not_reported` | A process started before monitoring produces no event |
| PID reuse (real) | `test_real_pid_reuse` | The kernel gives the same PID to a new process; one TERMINATED and one STARTED event with different start ticks (needs root, otherwise skipped) |
| PID reuse (logic) | `test_pid_reuse_logic_with_different_start_time` | Same PID, different start time: one started, one terminated |
| Special characters | `test_special_characters_in_process_name` | A real process named `a)b (c,d\|"e` is detected and survives the CSV round trip |
| Special characters | `test_csv_round_trip_of_awkward_names` | Commas, quotes, pipes, line breaks, tabs, Unicode all read back unchanged |
| Special characters | `test_control_characters_are_escaped_on_screen` | Newlines and escape codes are shown as text |
| Timestamps | `test_timestamps_are_timezone_aware_and_consistent` | Has a UTC offset, matches the clock, identical on screen and in the file |
| Timestamps | `test_all_events_of_one_scan_share_one_timestamp` | One value per scan |
| Process start | `test_process_start_time_is_close_to_real_start` | Within 5 s of the real start |
| Persistence | `test_log_persists_after_restart` | A new `EventLog` object (new program run) reads the earlier events |
| Empty log | `test_missing_and_empty_log`, `test_empty_log_through_the_menu` | "No events recorded yet." / "The log is already empty." |
| Invalid menu input | `test_invalid_menu_input` | `9`, `abc`, `0`, `7.5` and `6` (no longer an option) each print "Invalid option"; exit code 0; no traceback |
| Logging errors | `test_log_write_error_does_not_stop_monitoring`, `test_log_read_error_is_reported`, `test_damaged_rows_are_skipped_not_fatal` | Warning shown once, event still displayed, program keeps running |
| Scanning errors | `test_failed_scan_does_not_report_mass_termination`, `test_scan_where_nothing_is_readable_is_rejected`, `test_unreadable_process_is_not_called_terminated`, `test_vanished_process_is_reported_as_gone`, `test_unexpected_error_in_loop_is_survived` | No false TERMINATED events; warning, then "Recovered" |
| Backup/migration | `test_clear_keeps_a_backup`, `test_unrecognised_file_is_backed_up_not_overwritten`, `test_old_pipe_format_is_migrated_with_backup` | Backups exist and contain the original data |
| Threading | `test_background_thread_starts_detects_and_stops_cleanly`, `test_menu_options_and_exit_on_end_of_input`, `test_concurrent_draining_delivers_every_event_exactly_once`, `test_full_queue_never_blocks_and_nothing_is_lost_from_the_log` | Thread starts, a second start is refused, stop ends the thread; 20 simultaneous events reach the reader exactly once; a full queue never blocks and nothing is lost from the log |
| Automatic start | `test_monitoring_starts_automatically_on_launch`, `test_menu_has_no_start_option` | With nothing typed, the program reports "Monitoring started automatically" and RUNNING; the menu has no Start option |
| Automatic detection and display | `test_new_process_is_detected_displayed_and_saved_automatically`, `test_terminated_process_is_detected_displayed_and_saved_automatically` | A new and then a terminated `sleep` appear on screen **without any key press**, with the same timestamp as in the CSV |
| Baseline | `test_processes_running_at_launch_are_not_reported` | A process running before launch produces no event |
| Menu operations | `test_all_menu_operations_still_work`, `test_stopped_monitoring_detects_nothing` | View, show processes, stop (twice), clear (declined, then confirmed, with a `.bak`), view empty log; after Stop nothing is detected |
| Display and typing | `test_live_display_prints_events_without_any_input`, `test_events_wait_while_a_menu_command_prints`, `test_typed_input_is_kept_when_an_event_appears` | Events print by themselves; they wait while a command is printing; on a real (pty) terminal the prompt and the half-typed `3` are redrawn below the event |
| Clean shutdown | `test_exit_choice_ends_the_program_cleanly`, `test_end_of_input_ends_the_program_cleanly`, `test_ctrl_c_ends_the_program_cleanly`, `test_shutdown_stops_both_background_threads` | Exit code 0, "Goodbye.", no traceback, no monitoring or display thread left |
| Interval | `test_interval_validation` | `0.5` accepted; `0.01`, `abc`, `-1`, `nan`, `999999` rejected |

Expected summary line: `Ran 46 tests ... OK` (the real PID-reuse test counts as skipped if you are not root).

## 5. Demonstration procedure (about 10 minutes)

You need two terminals in Kali: **A** (the logger) and **B** (to create activity).

1. **Terminal A:** `cd ~/process_logger && python3 process_logger.py --interval 0.5`
   Monitoring starts by itself. The message shows the baseline: processes already running are not logged as new.
2. **Menu option 3** (current processes). Point out PID, parent PID, state and the count by state. This is process management information read from `/proc`.
3. **Creation. Terminal B:** `sleep 60 &` (note the PID printed). **Do not touch Terminal A**: within about a second a PROCESS STARTED event appears with that PID, state and parent (the shell).
4. **Several at once. B:** `for i in 1 2 3; do sleep 60 & done`. Three STARTED events appear with one shared timestamp.
5. **Termination. B:** `pkill sleep`. PROCESS TERMINATED events appear, labelled "Last observed state".
6. **Typing is not disturbed.** In A type `2` but do **not** press Enter. In B run `sleep 5 &`. The event appears above and your `2` is still on the prompt line. Press Enter to open the log viewer.
7. **Special characters. B:**
   `python3 -c "open('/proc/self/comm','w').write('a)b (c,d|\"e'); import time; time.sleep(30)" &`
   The odd name is shown correctly. Then in B: `column -s, -t ~/process_logger/process_activity.csv | tail -3` shows it quoted safely in the file.
8. **Log viewer. Menu option 2**: the full history, with the total.
9. **Stop monitoring. Menu option 1**, then in B run `sleep 5 &`: nothing appears. Monitoring does not restart by itself; to monitor again restart the program.
10. **Persistence. Menu option 5** (exit), start the program again, choose **2**: the earlier events are still there.
11. **PID reuse (optional, needs sudo).** Restart with a long interval: `python3 process_logger.py --interval 10` (monitoring starts at once).
    In B run `sudo -v`, then `sleep 300 & echo $!` and wait about 12 seconds until the STARTED event appears in A. Then, in B, in one line (replace `4242` with that PID):
    `kill 4242; wait 4242 2>/dev/null; echo $((4242-1)) | sudo tee /proc/sys/kernel/ns_last_pid >/dev/null; sleep 301 & echo $!`
    The new `sleep` gets the same PID. After the next scan, A shows one TERMINATED and one STARTED event for the same PID, with different process start times. This shows why the program identifies a process by PID plus start time.
12. **Limitation (honest result). B:** `echo hello` (finishes instantly). Nothing is logged, because it starts and exits between two scans. This is expected with periodic polling.
13. **Tests.** `python3 -m unittest -v test_process_logger` (use `sudo` to include the real PID-reuse test).

## 6. Limitations

- **Polling can miss short-lived processes.** A process that starts and exits between two scans is never seen. A shorter interval reduces the gap but cannot remove it. Detection of every process is not guaranteed.
- **Event time is detection time**, up to one interval after the real start or exit. The "process start time" column is the approximate real start (from the kernel).
- **State of a terminated process** is the last state seen in the previous scan.
- **Start time has 10 ms resolution.** A PID reused within the same 10 ms tick as the previous owner could not be told apart. In practice PID reuse takes far longer than that.
- **Approximate start time** depends on the boot time reported by the kernel; it may be off by a second or more if the VM clock was adjusted after boot.
- **Not shown:** processes hidden from your user by a `hidepid` mount option.
- **Stop is final for the session.** There is no menu option to resume, so to monitor again restart the program.
- **Live redraw needs a real terminal.** On a terminal (Kali, SSH) the prompt and half-typed text are redrawn after each event. If the output is redirected to a file or pipe, events are simply printed as lines. Moving the cursor into the middle of a half-typed line and then receiving an event puts the cursor back at the end of that line.
- Events are saved to the log immediately, before they are displayed.

## 7. Check against the original requirements

| Requirement | Where |
|---|---|
| Periodic scan of running processes | `scan_processes()`, `Monitor` |
| Show PID, name, state | Menu option 3, event blocks |
| Detect creation / termination | `detect_changes()` |
| Timestamped log with start and termination information | `EventLog`, CSV columns |
| View recorded events | Menu option 2 |
| Start / stop controls | Automatic start at launch; menu option 1 stops monitoring |
| Uses `/proc`, Python 3 standard library only, no database | Imports: `argparse, contextlib, csv, functools, os, queue, sys, threading, collections, dataclasses, datetime` (and `readline`, also standard library) |
| Demonstrates OS concepts | Processes, PIDs and PID reuse, process states, `/proc`, file handling, threads |