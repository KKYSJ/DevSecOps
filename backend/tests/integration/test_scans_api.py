from backend.app.workers import scan_worker
from backend.app.main import startup


def test_submit_scan_defer_processing_skips_sync_fallback(client, monkeypatch):
    startup()
    called = {"sync": False}

    def fake_delay(_scan_id):
        raise RuntimeError("broker unavailable")

    def fake_sync(_scan_id):
        called["sync"] = True

    monkeypatch.setattr(scan_worker.process_scan, "delay", fake_delay)
    monkeypatch.setattr(scan_worker, "_process_scan_sync", fake_sync)

    response = client.post(
        "/api/v1/scans",
        json={
            "tool": "semgrep",
            "raw_result": {},
            "commit_hash": "test-defer-processing",
            "project_name": "secureflow",
            "branch": "test",
            "defer_processing": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["async"] is False
    assert body["deferred"] is True
    assert called["sync"] is False
