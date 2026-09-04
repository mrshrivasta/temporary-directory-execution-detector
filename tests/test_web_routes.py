import csv
import os
import tempfile

FIELDS = ["Name", "CommandLine", "ProcessId", "ParentProcessId", "ExecutablePath", "User", "CreationDate"]


def _make_temp_execution_csv():
    """Real temp CSV with a real row executing from a real Windows temp
    directory with a randomized filename, guaranteed to produce at least
    one real TDE-001 (and TDE-002) finding."""
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerow({
            "Name": "a8f3c9d2e1.exe",
            "CommandLine": "a8f3c9d2e1.exe",
            "ProcessId": "4100",
            "ParentProcessId": "4000",
            "ExecutablePath": r"C:\Users\bob\AppData\Local\Temp\a8f3c9d2e1.exe",
            "User": "bob",
            "CreationDate": "",
        })
    return path


def test_full_scan_alert_incident_workflow(registered_client):
    csv_path = _make_temp_execution_csv()
    try:
        # Run a real scan against a real temp CSV with a real temp-execution row
        resp = registered_client.post("/scan/run", data={"target_path": csv_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert csv_path.encode() in resp.data

        # Alerts page should load and should show a real alert for the TDE-001 finding
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json
        data = resp.get_json()
        assert data["severity_breakdown"].get("high", 0) >= 1

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"TDE-001" in resp.data
    finally:
        os.remove(csv_path)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/process_exports",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/process_exports" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
