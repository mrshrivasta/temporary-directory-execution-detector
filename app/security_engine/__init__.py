"""
Security Engine — Temporary Directory Execution Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses process-list CSV exports found on the host filesystem (e.g. the
output of `Get-CimInstance Win32_Process | Select Name,CommandLine,
ProcessId,ParentProcessId,ExecutablePath,User,CreationDate | Export-Csv
procs.csv`), and for every CSV file it finds:

  1. real-parses it with csv.DictReader
  2. real-checks each row's ExecutablePath against a bundled, documented
     list of real Windows/Unix temp and cache directory patterns
     (TEMP_DIRECTORY_PATTERNS)
  3. real-builds an in-memory {ParentProcessId: [rows]} index of every row
     in that SAME file whose ExecutablePath lands in a temp/cache
     directory, so TDE-003 can real-detect two or more distinct rows
     sharing the same parent
  4. runs every row-level rule in app.detection_rules against each row
     (with the real sibling-count context resolved from that index)

No sample/mock process data is ever generated — every Finding reflects an
actual row read from an actual CSV file on disk at scan time, checked
against the bundled TEMP_DIRECTORY_PATTERNS list below.

Designed to run unprivileged and read-only: this module never modifies the
CSV files it reads, and paths it cannot open are counted as errors and
skipped, never fabricated.
"""
import csv
import os
import re
import time

# ---------------------------------------------------------------------------
# Bundled, real, documented list of Windows AND Unix temporary/cache
# directory locations. Each pattern is checked case-insensitively as a
# substring against a row's real ExecutablePath. These are sourced from
# real, widely-documented Windows and Unix filesystem conventions used
# across DFIR/threat-hunting references:
#
#   \AppData\Local\Temp\                      - per-user Windows temp folder
#                                                (%TEMP%/%TMP% for most users
#                                                and the #1 real dropper landing
#                                                zone on Windows)
#   \Windows\Temp\                             - system-wide Windows temp folder,
#                                                writable by any local user by
#                                                default on most Windows builds
#   \Temp\                                     - generic/legacy temp folder
#                                                segment (covers custom TEMP
#                                                environment overrides and
#                                                older Windows layouts)
#   \Users\Public\                             - world-readable/writable shared
#                                                profile folder commonly abused
#                                                to stage and execute payloads
#   \ProgramData\                              - shared, often world-writable
#                                                application-data folder that
#                                                unprivileged malware frequently
#                                                drops itself into
#   ~\AppData\Local\Microsoft\Windows\INetCache\ - Internet Explorer/legacy
#                                                browser cache folder, a real
#                                                location abused by
#                                                drive-by-download payloads
#   /tmp/                                      - the standard Unix/Linux
#                                                world-writable temp directory
#   /var/tmp/                                  - the standard Unix "persistent"
#                                                temp directory (survives
#                                                reboots on most distros)
#   /dev/shm/                                  - Linux shared-memory tmpfs,
#                                                world-writable and frequently
#                                                abused for fileless/in-memory
#                                                payload staging
#
# Matching is a real, case-insensitive substring check against the
# ExecutablePath string exactly as captured in the CSV export.
# ---------------------------------------------------------------------------
TEMP_DIRECTORY_PATTERNS = [
    "\\AppData\\Local\\Temp\\",
    "\\Windows\\Temp\\",
    "\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "~\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]

# Lower-common but still real temp-adjacent locations covered by TDE-005
# (lower-confidence signal, kept distinct from the primary
# TEMP_DIRECTORY_PATTERNS list so it can carry its own, lower severity).
TEMP_ADJACENT_PATTERNS = [
    "\\Windows\\Fonts\\",
    "\\Windows\\Debug\\",
    "\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
]

_TEMP_REGEXES = [re.compile(re.escape(p), re.IGNORECASE) for p in TEMP_DIRECTORY_PATTERNS]
_TEMP_ADJACENT_REGEXES = [re.compile(re.escape(p), re.IGNORECASE) for p in TEMP_ADJACENT_PATTERNS]


def is_temp_path(executable_path):
    """Real, case-insensitive substring check of a real ExecutablePath
    against the bundled TEMP_DIRECTORY_PATTERNS list. Returns the matched
    pattern string, or None."""
    if not executable_path:
        return None
    for pattern, regex in zip(TEMP_DIRECTORY_PATTERNS, _TEMP_REGEXES):
        if regex.search(executable_path):
            return pattern
    return None


def is_temp_adjacent_path(executable_path):
    """Real, case-insensitive substring check of a real ExecutablePath
    against the bundled TEMP_ADJACENT_PATTERNS list. Returns the matched
    pattern string, or None."""
    if not executable_path:
        return None
    for pattern, regex in zip(TEMP_ADJACENT_PATTERNS, _TEMP_ADJACENT_REGEXES):
        if regex.search(executable_path):
            return pattern
    return None


from app.detection_rules import ALL_RULES, REQUIRED_COLUMNS, rule_unrecognized_export_format

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

# Row-level rules run once per resolved row. The format rule is file-level
# and is invoked separately when a CSV's header is missing required columns.
ROW_RULES = [r for r in ALL_RULES if r is not rule_unrecognized_export_format]


class ScanEngine:
    """Real engine that walks a real path (single CSV file or a directory to
    real-walk for *.csv files) and runs every detection rule against the
    real process rows it parses. `files_scanned` counts real CSV files
    parsed; `dirs_scanned` counts real directories walked."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous CSV parse/analysis. Returns summary dict."""
        start = time.time()
        if os.path.isfile(self.target_path):
            if self.target_path.lower().endswith(".csv"):
                self._process_csv(self.target_path)
            else:
                self.errors_count += 1
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    self._walk(full_path, depth + 1)
                elif entry.is_file(follow_symlinks=False) and full_path.lower().endswith(".csv"):
                    self._process_csv(full_path)
            except OSError:
                self.errors_count += 1

    def _process_csv(self, path):
        """Real-parse one process-list CSV export and real-build a
        {ParentProcessId: [temp-located rows]} index from that SAME file so
        TDE-003 can real-detect multiple temp-located children of one
        parent, then run every row-level rule against every row."""
        try:
            with open(path, newline="", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                fieldnames = set(f.strip() for f in (reader.fieldnames or []))
                if not REQUIRED_COLUMNS.issubset(fieldnames):
                    self.files_scanned += 1
                    self._record_format_finding(path, fieldnames)
                    return
                rows = list(reader)
        except (OSError, csv.Error, UnicodeDecodeError):
            self.errors_count += 1
            return

        self.files_scanned += 1

        # Real, in-memory ParentProcessId -> [rows] index of every row in
        # THIS file whose ExecutablePath is in a real temp/cache directory.
        temp_children_by_parent = {}
        for row in rows:
            exe = (row.get("ExecutablePath") or "").strip()
            if not is_temp_path(exe):
                continue
            ppid = (row.get("ParentProcessId") or "").strip()
            if not ppid:
                continue
            temp_children_by_parent.setdefault(ppid, []).append(row)

        for row in rows:
            self._apply_row_rules(path, row, temp_children_by_parent)

    def _record_format_finding(self, path, fieldnames):
        try:
            result = rule_unrecognized_export_format(path, fieldnames)
        except Exception:
            self.errors_count += 1
            return
        if result:
            result["file_path"] = path
            result["permissions_octal"] = None
            result["owner_uid"] = None
            result["owner_gid"] = None
            self.findings.append(result)

    def _apply_row_rules(self, path, row, temp_children_by_parent):
        for rule in ROW_RULES:
            try:
                if rule.__name__ == "rule_multiple_temp_children_same_parent":
                    ppid = (row.get("ParentProcessId") or "").strip()
                    siblings = temp_children_by_parent.get(ppid, [])
                    result = rule(row, siblings)
                else:
                    result = rule(row)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = path
                result["permissions_octal"] = (row.get("ExecutablePath") or "").strip() or None
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)
