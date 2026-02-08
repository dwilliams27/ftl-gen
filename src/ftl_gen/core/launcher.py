"""Monitored FTL launcher with log capture and hang/crash detection."""

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ftl_gen.config import Settings


# Patterns in FTL.log that indicate errors
ERROR_PATTERNS = [
    re.compile(r"error", re.IGNORECASE),
    re.compile(r"exception", re.IGNORECASE),
    re.compile(r"fatal", re.IGNORECASE),
    re.compile(r"failed to", re.IGNORECASE),
    re.compile(r"could not", re.IGNORECASE),
    re.compile(r"segfault", re.IGNORECASE),
]

# Loading milestone that indicates blueprints are parsed
BLUEPRINTS_LOADED = "Blueprints Loaded!"

# How long after "Blueprints Loaded!" with no activity = hang
HANG_TIMEOUT_SECONDS = 15

# How long to monitor before assuming success
MONITOR_DURATION_SECONDS = 30


@dataclass
class LaunchResult:
    """Result of a monitored FTL launch."""

    success: bool
    message: str
    hang_detected: bool = False
    exit_code: int | None = None
    log_tail: list[str] = field(default_factory=list)
    errors_in_log: list[str] = field(default_factory=list)


@dataclass
class CrashReport:
    """Snapshot of FTL state for debugging."""

    process_alive: bool
    exit_code: int | None = None
    log_lines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    macos_crash_report: str | None = None
    mod_name: str | None = None


class FTLLauncher:
    """Launches FTL with monitoring, log capture, and crash detection."""

    def __init__(self, settings: Settings, mod_name: str | None = None):
        self.settings = settings
        self.mod_name = mod_name
        self._proc: subprocess.Popen | None = None
        self._log_lines: list[str] = []
        self._log_lock = threading.Lock()
        self._log_thread: threading.Thread | None = None
        self._stop_tailing = threading.Event()
        self._log_bookmark: int = 0

    def start(self) -> LaunchResult:
        """Start FTL and begin tailing the log. Returns immediately (non-blocking).

        Use get_crash_report() to poll for log lines and process status.
        """
        ftl_exe = self.settings.find_ftl_executable()
        if not ftl_exe:
            return LaunchResult(success=False, message="FTL executable not found")

        log_path = self.settings.ftl_log_path

        # FTL truncates its log on each launch, but rewrites it so fast
        # (~510 bytes in microseconds) that polling-based truncation
        # detection misses it.  Truncate the file ourselves before launch
        # so we can simply read from position 0.
        try:
            log_path.write_text("")
        except OSError:
            pass
        self._log_bookmark = 0

        # Launch FTL
        try:
            self._proc = subprocess.Popen(
                [str(ftl_exe)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as e:
            return LaunchResult(success=False, message=f"Failed to launch FTL: {e}")

        # Start log tailing thread
        self._stop_tailing.clear()
        self._log_thread = threading.Thread(
            target=self._tail_log, args=(log_path,), daemon=True
        )
        self._log_thread.start()

        return LaunchResult(success=True, message="FTL launched")

    def launch(self) -> LaunchResult:
        """Launch FTL and monitor for hangs/crashes (blocking, up to 30s).

        1. Record current FTL.log size
        2. Launch FTL via Popen
        3. Tail FTL.log in background thread
        4. Watchdog: detect early exit, hang, or success
        """
        result = self.start()
        if not result.success:
            return result

        # Watchdog loop
        blueprints_loaded = False
        last_line_count = 0
        stale_since: float | None = None
        start = time.monotonic()

        while time.monotonic() - start < MONITOR_DURATION_SECONDS:
            time.sleep(1.0)

            # Check if process exited
            if self._proc.poll() is not None:
                # Give log thread a moment to catch up
                time.sleep(0.5)
                exit_code = self._proc.returncode
                errors = self._extract_errors()
                tail = self._get_tail(50)
                return LaunchResult(
                    success=False,
                    message=f"FTL exited early with code {exit_code}",
                    exit_code=exit_code,
                    log_tail=tail,
                    errors_in_log=errors,
                )

            with self._log_lock:
                current_count = len(self._log_lines)
                lines = list(self._log_lines)

            # Check for "Blueprints Loaded!" milestone
            if not blueprints_loaded:
                for line in lines:
                    if BLUEPRINTS_LOADED in line:
                        blueprints_loaded = True
                        break

            # Hang detection: blueprints loaded but no new log activity
            if blueprints_loaded:
                if current_count == last_line_count:
                    if stale_since is None:
                        stale_since = time.monotonic()
                    elif time.monotonic() - stale_since >= HANG_TIMEOUT_SECONDS:
                        errors = self._extract_errors()
                        tail = self._get_tail(50)
                        return LaunchResult(
                            success=False,
                            message=f"FTL appears hung after '{BLUEPRINTS_LOADED}' "
                            f"(no log activity for {HANG_TIMEOUT_SECONDS}s)",
                            hang_detected=True,
                            log_tail=tail,
                            errors_in_log=errors,
                        )
                else:
                    stale_since = None

            last_line_count = current_count

        # Made it through monitoring without crash/hang
        return LaunchResult(
            success=True,
            message="FTL launched and appears to be running normally",
            log_tail=self._get_tail(20),
            errors_in_log=self._extract_errors(),
        )

    def get_crash_report(self) -> CrashReport:
        """Get a snapshot of FTL state for debugging.

        Can be called any time after launch().
        """
        process_alive = self._proc is not None and self._proc.poll() is None
        exit_code = None
        if self._proc is not None and not process_alive:
            exit_code = self._proc.returncode

        with self._log_lock:
            log_lines = list(self._log_lines)

        errors = self._extract_errors()
        crash_report_path = self._find_macos_crash_report()

        return CrashReport(
            process_alive=process_alive,
            exit_code=exit_code,
            log_lines=log_lines,
            errors=errors,
            macos_crash_report=crash_report_path,
            mod_name=self.mod_name,
        )

    def stop(self) -> None:
        """Stop monitoring and kill FTL if running."""
        self._stop_tailing.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def _tail_log(self, log_path: Path) -> None:
        """Background thread: tail FTL.log from bookmark."""
        pos = self._log_bookmark

        while not self._stop_tailing.is_set():
            if not log_path.exists():
                time.sleep(0.5)
                continue

            try:
                size = log_path.stat().st_size
                if size < pos:
                    # File was truncated (FTL rewrites log on each launch)
                    pos = 0
                    with self._log_lock:
                        self._log_lines.clear()
                if size > pos:
                    with open(log_path, "r", errors="replace") as f:
                        f.seek(pos)
                        new_data = f.read()
                        pos = f.tell()

                    new_lines = new_data.splitlines()
                    with self._log_lock:
                        self._log_lines.extend(new_lines)
            except OSError:
                pass

            time.sleep(0.5)

    def _get_tail(self, n: int) -> list[str]:
        """Get the last N log lines."""
        with self._log_lock:
            return self._log_lines[-n:]

    def _extract_errors(self) -> list[str]:
        """Extract lines matching error patterns."""
        with self._log_lock:
            lines = list(self._log_lines)

        errors = []
        for line in lines:
            if any(p.search(line) for p in ERROR_PATTERNS):
                errors.append(line)
        return errors

    def _find_macos_crash_report(self) -> str | None:
        """Look for recent FTL crash reports in DiagnosticReports."""
        reports_dir = Path.home() / "Library" / "Logs" / "DiagnosticReports"
        if not reports_dir.exists():
            return None

        # Look for .ips files related to FTL, sorted newest first
        ftl_reports = sorted(
            (f for f in reports_dir.iterdir()
             if f.suffix == ".ips" and "FTL" in f.name),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if ftl_reports:
            # Only return if it's recent (within last 5 minutes)
            newest = ftl_reports[0]
            age = time.time() - newest.stat().st_mtime
            if age < 300:
                return str(newest)

        return None
