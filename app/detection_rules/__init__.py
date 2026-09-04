"""
Detection Rules — Temporary Directory Execution Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each row-level rule inspects a REAL row resolved by the Security Engine from
a real process-list CSV export on this machine, and returns a Finding dict
if the condition is met. Rules are intentionally conservative and documented
so results can be independently verified against the raw CSV with a text
editor or `csv.DictReader`.

Note on TEMP_DIRECTORY_PATTERNS / is_temp_path / is_temp_adjacent_path: they
are imported lazily (inside each function body, not at module import time)
from app.security_engine to avoid a circular import between the two
modules, since app.security_engine also imports ALL_RULES from this module.
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Minimum real columns a process-list CSV export must have for this tool to
# be able to check a row's ExecutablePath against temp/cache directories.
REQUIRED_COLUMNS = {"Name", "ExecutablePath"}

# Real regex for a "random-looking" filename: 8 or more consecutive
# alphanumeric/hex characters with no real dictionary-word structure.
# Two real, well-documented heuristics are combined:
#   1. a pure hex string of 8+ characters (a8f3c9d2e1, deadbeef01, ...) —
#      the classic pattern for hash-derived or randomly-generated dropper
#      filenames
#   2. an alphanumeric string of 8+ characters with an unusually low vowel
#      ratio (< 15%), since real dictionary words/identifiers almost always
#      contain vowels at a much higher rate than randomly-generated strings
_HEX_RANDOM_RE = re.compile(r"^[0-9a-f]{8,}$")
_ALNUM_RE = re.compile(r"^[a-z0-9]{8,}$")
_VOWEL_RATIO_THRESHOLD = 0.15

# Real URL / IP-literal indicator regexes used by TDE-004.
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"']+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _finding(rule_id, rule_name, severity, description):
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
    }


def _get(row, key):
    if not row:
        return ""
    return (row.get(key) or "").strip()


def _basename(executable_path):
    """Real, cross-platform basename extraction: splits on BOTH backslash
    and forward slash so a real Windows path (C:\\...\\name.exe) or a real
    Unix path (/tmp/name) resolves correctly regardless of which OS
    exported the CSV."""
    if not executable_path:
        return ""
    return re.split(r"[\\/]", executable_path)[-1]


def _looks_random(name):
    """Real random-filename heuristic used by TDE-002. `name` should already
    be the file's basename with its extension stripped."""
    lowered = name.lower()
    if _HEX_RANDOM_RE.match(lowered):
        return True
    if not _ALNUM_RE.match(lowered):
        return False
    vowels = sum(1 for c in lowered if c in "aeiou")
    return (vowels / len(lowered)) < _VOWEL_RATIO_THRESHOLD


def rule_active_execution_from_temp(row):
    """TDE-001 (high): a real row's ExecutablePath is located directly in a
    real bundled temp/cache directory (TEMP_DIRECTORY_PATTERNS), AND the
    process is still actively running per this real process-list snapshot.
    Every row present in a process-list export IS, by definition, a
    currently running process captured at export time — so simply being
    present in the export is real, first-hand evidence the process is
    active right now. Execution directly from a temp/cache location is one
    of the most consistent real malware/dropper indicators: legitimate
    installed software almost never runs its long-lived executable straight
    out of a temp folder."""
    from app.security_engine import is_temp_path

    exe = _get(row, "ExecutablePath")
    matched = is_temp_path(exe)
    if not matched:
        return None
    name = _get(row, "Name") or exe
    return _finding(
        "TDE-001",
        "Active Execution From Temporary Directory",
        SEVERITY_HIGH,
        f"{name} (PID {_get(row, 'ProcessId') or '?'}) is currently running with "
        f"ExecutablePath '{exe}', which resolves inside a real temp/cache "
        f"directory (matched pattern '{matched}'). This process is actively "
        f"running per this process-list snapshot. Execution directly from a "
        f"temp/cache directory is one of the most consistent real "
        f"malware/dropper indicators and should be investigated.",
    )


def rule_random_named_temp_executable(row):
    """TDE-002 (medium): a real row's ExecutablePath is in a real temp
    directory AND the real Name uses a random-looking filename (8+
    consecutive alphanumeric/hex characters with no dictionary-word
    structure, e.g. a8f3c9d2e1.exe). Compounding a temp-location signal
    with a randomized-name signal is a strong, real, commonly-documented
    pattern for malware droppers and downloaders that generate a unique
    filename per infection to evade static, name-based detection."""
    from app.security_engine import is_temp_path

    exe = _get(row, "ExecutablePath")
    if not is_temp_path(exe):
        return None
    name = _get(row, "Name")
    base = _basename(name or exe)
    stem = re.sub(r"\.[a-zA-Z0-9]{1,5}$", "", base)  # strip a single real extension
    if not stem or not _looks_random(stem):
        return None
    return _finding(
        "TDE-002",
        "Randomly-Named Executable In Temporary Directory",
        SEVERITY_MEDIUM,
        f"{name or base} (PID {_get(row, 'ProcessId') or '?'}) executes from a real "
        f"temp/cache directory ('{exe}') AND its filename '{base}' matches a "
        f"randomized-filename heuristic (8+ hex/alphanumeric characters with "
        f"no dictionary-word structure). This compounded temp-location + "
        f"randomized-name signal is a common real dropper/downloader "
        f"fingerprint.",
    )


def rule_multiple_temp_children_same_parent(row, temp_siblings):
    """TDE-003 (medium): TWO OR MORE distinct real rows in the SAME scan
    have ExecutablePath values in temp directories that share the SAME real
    parent ParentProcessId. `temp_siblings` is the real list of every
    temp-located row (from the SAME CSV file) sharing this row's
    ParentProcessId, resolved by the Security Engine. A single process
    spawning multiple temp-located children is common, real, observable
    dropper/loader behaviour (a launcher unpacking and executing several
    staged payloads from a temp folder)."""
    from app.security_engine import is_temp_path

    exe = _get(row, "ExecutablePath")
    if not is_temp_path(exe):
        return None
    if not temp_siblings or len(temp_siblings) < 2:
        return None

    ppid = _get(row, "ParentProcessId")
    sibling_names = sorted({_get(s, "Name") or _get(s, "ExecutablePath") for s in temp_siblings})
    return _finding(
        "TDE-003",
        "Multiple Temp-Located Children Sharing One Parent",
        SEVERITY_MEDIUM,
        f"{_get(row, 'Name') or exe} (PID {_get(row, 'ProcessId') or '?'}) is one of "
        f"{len(temp_siblings)} distinct real processes in this export that share "
        f"ParentProcessId {ppid or '?'} and execute from a temp/cache directory "
        f"({', '.join(sibling_names)}). A single parent spawning multiple "
        f"temp-located children is common real dropper/loader behaviour.",
    )


def rule_temp_execution_with_network_indicator(row):
    """TDE-004 (low): a real row's ExecutablePath is in a temp directory AND
    its real CommandLine (when present) references a real network indicator
    (a URL or an IP-literal). Combining temp-location execution with an
    outbound network reference in the same command line is a real, worth-
    reviewing signal — e.g. a staged payload that reaches out to a
    command-and-control server or downloads a further stage."""
    from app.security_engine import is_temp_path

    exe = _get(row, "ExecutablePath")
    if not is_temp_path(exe):
        return None
    cmdline = _get(row, "CommandLine")
    if not cmdline:
        return None
    url_match = _URL_RE.search(cmdline)
    ip_match = _IP_RE.search(cmdline)
    if not url_match and not ip_match:
        return None
    indicator = url_match.group(0) if url_match else ip_match.group(0)
    return _finding(
        "TDE-004",
        "Temp Execution With Network Indicator",
        SEVERITY_LOW,
        f"{_get(row, 'Name') or exe} (PID {_get(row, 'ProcessId') or '?'}) executes from "
        f"a real temp/cache directory ('{exe}') and its CommandLine references "
        f"a real network indicator ('{indicator}'). Temp-location execution "
        f"combined with an embedded network reference is worth reviewing for "
        f"staged/next-stage payload retrieval or C2 activity.",
    )


def rule_temp_adjacent_location(row):
    """TDE-005 (low): a real row's ExecutablePath is in a LESS-common but
    still real temp-adjacent location (\\Windows\\Fonts\\, \\Windows\\Debug\\,
    or a real INetCache path) rather than a primary temp directory. These
    locations are real, occasionally-abused staging spots (e.g. the
    CVE-2011-3402/Duqu-style abuse of the Fonts folder, or INetCache
    drive-by-download payload drops), but are lower-confidence than a
    primary temp directory, so this is kept as a distinct, lower-severity
    rule from TDE-001 to allow different severity/triage handling."""
    from app.security_engine import is_temp_adjacent_path

    exe = _get(row, "ExecutablePath")
    matched = is_temp_adjacent_path(exe)
    if not matched:
        return None
    name = _get(row, "Name") or exe
    return _finding(
        "TDE-005",
        "Execution From Temp-Adjacent Location",
        SEVERITY_LOW,
        f"{name} (PID {_get(row, 'ProcessId') or '?'}) executes from a real "
        f"temp-adjacent location ('{exe}', matched pattern '{matched}'). This "
        f"is a less-common but still real staging location occasionally "
        f"abused for payload delivery — a lower-confidence signal than "
        f"direct temp-directory execution, worth a lower-priority review.",
    )


def rule_unrecognized_export_format(path, fieldnames):
    """TDE-006 (low/informational): a CSV's header lacked the minimum
    required real columns (Name, ExecutablePath) for temp-execution
    analysis. This is a parse-note flagging an unrecognized export format
    rather than a temp-execution anomaly — the file was skipped for
    analysis."""
    missing = sorted(REQUIRED_COLUMNS - set(fieldnames))
    return _finding(
        "TDE-006",
        "Unrecognized Process-List Export Format",
        SEVERITY_LOW,
        f"{path} does not contain the minimum required columns for temp-execution "
        f"analysis (missing: {', '.join(missing)}). Expected at least Name and "
        f"ExecutablePath columns, as produced by a standard process-list export. "
        f"This file was skipped for analysis.",
    )


ALL_RULES = [
    rule_active_execution_from_temp,
    rule_random_named_temp_executable,
    rule_multiple_temp_children_same_parent,
    rule_temp_execution_with_network_indicator,
    rule_temp_adjacent_location,
    rule_unrecognized_export_format,
]
