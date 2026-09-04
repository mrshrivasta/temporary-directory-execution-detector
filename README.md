# Temporary Directory Execution Detector

**A real, no-mock-data temp/cache-directory execution analyzer — CLI + Web App.**
Real-parses process-list CSV exports (e.g. `Get-CimInstance Win32_Process | Export-Csv`), real-checks each row's `ExecutablePath` against a bundled, documented list of real Windows and Unix temp/cache directory locations, and real-correlates rows within the same export by `ParentProcessId` — flagging processes actively executing from temp directories, randomly-named temp executables, multiple temp-located children of one parent, temp execution paired with network indicators, and lower-confidence temp-adjacent locations. These are classic, well-documented indicators of malware droppers, downloaders, and loaders.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and digital-forensics/incident-response (DFIR) purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Only analyze process-list exports from systems you own or for which you have explicit, documented authorization to assess. Analyzing exports from systems without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction) and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including missed detections, false positives, response decisions made from these results, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a certified audit.** This tool is **not a substitute** for a professional incident-response engagement, a certified compliance audit, or a review by a qualified security professional. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean. This tool checks a specific, limited set of well-documented temp/cache-directory execution patterns only, against the bundled `TEMP_DIRECTORY_PATTERNS`/`TEMP_ADJACENT_PATTERNS` lists.
- **Read-only by design.** The Security Engine only reads CSV files from disk with `csv.DictReader` — it never modifies, deletes, or writes to the process-list export it analyzes. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given export, **do not run this tool against it.**

---

## Who should use this project

- SOC analysts and DFIR/incident-response practitioners triaging a batch of process-list exports collected from endpoints during an investigation.
- Threat hunters looking for dropper, downloader, and loader indicators in historical or live process snapshots.
- Security students and self-learners studying real temp-directory-abuse techniques and randomized-filename malware conventions.
- CI/CD or scheduled-triage pipelines that want a temp-execution anomaly gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from real rows read from a real CSV export on disk, with real substring/regex matching against a real `ExecutablePath` and real cross-row `ParentProcessId` correlation performed at scan time. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`, backed by a small, documented, bundled `TEMP_DIRECTORY_PATTERNS`/`TEMP_ADJACENT_PATTERNS` list in `app/security_engine/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/scripted triage) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## What it analyzes

This tool does **not** collect process lists itself — it analyzes process-list CSV exports you already have (collected via PowerShell, Sysinternals `pslist /accepteula`, EDR export, `ps`/`lsof`-derived CSVs on Unix, or any other real process enumeration tool). A CSV must contain at minimum these two real columns to be analyzed:

| Column | Required | Meaning |
|---|---|---|
| `Name` | Yes | Process executable name (e.g. `a8f3c9d2e1.exe`) |
| `ExecutablePath` | Yes | Full path to the executable on disk — checked against the bundled temp/cache directory patterns |
| `CommandLine` | No | Full command line (used by TDE-004 to look for embedded network indicators) |
| `ProcessId` | No | Real PID for this row (used for readable descriptions) |
| `ParentProcessId` | No | Real PPID this row claims as its parent (used by TDE-003 to correlate sibling children) |
| `User` | No | Account the process ran under (captured but not currently rule-driving) |
| `CreationDate` | No | Process start time (captured but not currently rule-driving) |

Example export line (as produced by `Get-CimInstance Win32_Process | Select Name,CommandLine,ProcessId,ParentProcessId,ExecutablePath,User,CreationDate | Export-Csv procs.csv -NoTypeInformation`):

```csv
Name,CommandLine,ProcessId,ParentProcessId,ExecutablePath,User,CreationDate
a8f3c9d2e1.exe,a8f3c9d2e1.exe,4100,4000,C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe,bob,2026-08-18T09:14:02
```

On Unix-like systems, an equivalent export can be produced with a short script wrapping `ps -eo comm,args,pid,ppid,user,lstart` and resolving each PID's real executable path via `/proc/<pid>/exe` (Linux) or `lsof -p <pid>` (macOS/BSD), then writing the same column layout with `csv.DictWriter`.

For every row, the Security Engine real-checks the row's `ExecutablePath` against the bundled temp/cache directory patterns, real-builds a `ParentProcessId -> [temp-located rows]` index from the same file, then runs every rule below against the real row.

### Bundled `TEMP_DIRECTORY_PATTERNS` / `TEMP_ADJACENT_PATTERNS`

A small, documented list of real, well-known Windows and Unix temp/cache locations, matched case-insensitively as a substring against `ExecutablePath`:

| Pattern | Platform | Notes |
|---|---|---|
| `\AppData\Local\Temp\` | Windows | Per-user temp folder (`%TEMP%`/`%TMP%`) — the #1 real dropper landing zone |
| `\Windows\Temp\` | Windows | System-wide temp folder, writable by any local user by default |
| `\Temp\` | Windows | Generic/legacy temp folder segment |
| `\Users\Public\` | Windows | World-readable/writable shared profile folder |
| `\ProgramData\` | Windows | Shared, often world-writable application-data folder |
| `~\AppData\Local\Microsoft\Windows\INetCache\` | Windows | Legacy IE/browser cache folder (literal `~` form) |
| `/tmp/` | Unix/Linux | Standard world-writable temp directory |
| `/var/tmp/` | Unix/Linux | Standard "persistent" temp directory (survives reboots) |
| `/dev/shm/` | Linux | Shared-memory tmpfs, world-writable, common fileless-payload staging area |

`TEMP_ADJACENT_PATTERNS` (lower-confidence, drives TDE-005 only): `\Windows\Fonts\`, `\Windows\Debug\`, `\AppData\Local\Microsoft\Windows\INetCache\` (absolute-path form, distinct from the literal-`~` primary pattern above so a real absolute export path matches this rule rather than the primary one).

See `app/security_engine/__init__.py` for the exact, always-current lists used at scan time.

---

## Architecture

```
temporary-directory-execution-detector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real CSV-parsing + temp-directory-matching engine + TEMP_DIRECTORY_PATTERNS
│   ├── detection_rules/      # 6 documented detection rules (TDE-001..TDE-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp CSV files + real host checks
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| TDE-001 | Active Execution From Temporary Directory | High | A real row's `ExecutablePath` is located directly in a real bundled temp/cache directory, and the process is actively running per this process-list snapshot |
| TDE-002 | Randomly-Named Executable In Temporary Directory | Medium | A real row's `ExecutablePath` is in a temp directory AND its `Name` matches a randomized-filename heuristic (8+ hex/alphanumeric characters, no dictionary-word structure) |
| TDE-003 | Multiple Temp-Located Children Sharing One Parent | Medium | Two or more distinct real rows in the same scan have `ExecutablePath` values in temp directories that share the same `ParentProcessId` |
| TDE-004 | Temp Execution With Network Indicator | Low | A real row's `ExecutablePath` is in a temp directory AND its `CommandLine` references a real network indicator (URL or IP literal) |
| TDE-005 | Execution From Temp-Adjacent Location | Low | A real row's `ExecutablePath` is in a less-common but still real temp-adjacent location (`\Windows\Fonts\`, `\Windows\Debug\`, real `INetCache` path) |
| TDE-006 | Unrecognized Process-List Export Format | Low | A CSV's header is missing the minimum required columns (`Name`, `ExecutablePath`) |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS Python runs on (it only parses CSV text files — it never inspects live processes on the machine running it)

### Install

```bash
git clone <this-repository-url>
cd temporary-directory-execution-detector
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
TDED_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                   # port to listen on
FLASK_DEBUG=1                # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/tded.db`. On the Dashboard, enter the real path to a process-list CSV file (or a directory containing multiple `*.csv` exports) and click **Run Scan**.

### Run the CLI

```bash
python3 cli/main.py scan procs.csv
python3 cli/main.py scan /data/process_exports --depth 4
python3 cli/main.py scan procs.csv --json
python3 cli/main.py scan procs.csv --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/triage-pipeline gate) and `0` if the export is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite writes real CSV files to real temp directories with real `csv.DictWriter` (including a genuine row with `ExecutablePath` in `\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe`, three rows sharing one `ParentProcessId` all executing from Temp, and a row with a temp path plus an embedded URL in `CommandLine`) and runs the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Temporary Directory Execution Detector check?**
It real-parses a process-list CSV export and flags rows whose `ExecutablePath` is located in a real Windows or Unix temp/cache directory: actively-running processes executing from temp, random-named temp executables, multiple temp-located children sharing one `ParentProcessId`, temp execution combined with a network indicator in the command line, and lower-confidence temp-adjacent locations.

**Who should use it?**
SOC analysts, DFIR/incident-response practitioners, threat hunters, security students, and system administrators triaging process-list exports from systems they own or are authorized to assess.

**Is it a replacement for a professional security audit?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify my files?**
No. It only reads CSV files with `csv.DictReader`. It never writes to, deletes, or modifies the process-list exports it analyzes.

**Does it collect live process data from my machine?**
No. It only analyzes process-list CSV exports that already exist on disk — it does not enumerate, inspect, or touch any running process on the machine it runs on.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
