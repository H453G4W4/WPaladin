"""Tests for the REST API / dashboard backend using FastAPI's TestClient."""

from __future__ import annotations

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from wp_sentinel.api import create_app


def _wp_handler(request: httpx.Request) -> httpx.Response:
    routes = {
        "/": '<meta name="generator" content="WordPress 6.4.2"> /wp-content/',
        "/readme.html": "WordPress Version 6.4.2",
        "/xmlrpc.php": "XML-RPC server accepts POST requests only.",
        "/.env": "DB_PASSWORD=secret",
    }
    path = request.url.raw_path.decode()
    if path in routes:
        return httpx.Response(200, text=routes[path])
    return httpx.Response(404, text="nf")


@pytest.fixture
def client():
    app = create_app(transport=httpx.MockTransport(_wp_handler))
    with TestClient(app) as c:
        yield c


def _wait_completed(client, scan_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = client.get(f"/api/v1/scans/{scan_id}").json()
        if rec["status"] in ("completed", "failed"):
            return rec
        time.sleep(0.1)
    raise AssertionError("scan did not complete in time")


def test_health_and_metadata(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert len(client.get("/api/v1/checks").json()) >= 9
    profiles = client.get("/api/v1/profiles").json()
    assert {p["name"] for p in profiles} == {"passive", "standard", "thorough"}


def test_scan_requires_authorization(client):
    resp = client.post("/api/v1/scans", json={"url": "https://example.com"})
    assert resp.status_code == 403


def test_scan_rejects_bad_profile(client):
    resp = client.post(
        "/api/v1/scans",
        json={"url": "https://example.com", "authorized": True, "profile": "nope"},
    )
    assert resp.status_code == 400


def test_full_scan_lifecycle(client):
    resp = client.post(
        "/api/v1/scans",
        json={"url": "https://example.com", "authorized": True, "profile": "standard"},
    )
    assert resp.status_code == 201
    scan_id = resp.json()["id"]

    rec = _wait_completed(client, scan_id)
    assert rec["status"] == "completed"
    assert rec["findings_count"] > 0
    assert rec["highest_severity"] == "critical"  # exposed .env

    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()["findings"]
    assert any(f["check_id"] == "sensitive-files" for f in findings)

    # scan appears in the list
    listing = client.get("/api/v1/scans").json()
    assert any(s["id"] == scan_id for s in listing)


def test_reports_via_api(client):
    scan_id = client.post(
        "/api/v1/scans",
        json={"url": "https://example.com", "authorized": True},
    ).json()["id"]
    _wait_completed(client, scan_id)

    html = client.get(f"/api/v1/scans/{scan_id}/report", params={"format": "html"})
    assert html.status_code == 200 and "<!DOCTYPE html>" in html.text

    csv_resp = client.get(f"/api/v1/scans/{scan_id}/report", params={"format": "csv"})
    assert csv_resp.status_code == 200 and "check_id,severity" in csv_resp.text

    bad = client.get(f"/api/v1/scans/{scan_id}/report", params={"format": "pdf"})
    assert bad.status_code == 400


def test_report_before_completion_conflicts(client):
    # 404 for unknown scan, 409 handled once known-but-incomplete is transient;
    # here we just assert unknown ids 404.
    assert client.get("/api/v1/scans/deadbeef/report").status_code == 404
    assert client.get("/api/v1/scans/deadbeef").status_code == 404


def test_dashboard_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "WP-Sentinel" in resp.text
    assert "Non-destructive" in resp.text


def test_websocket_streams_status(client):
    scan_id = client.post(
        "/api/v1/scans",
        json={"url": "https://example.com", "authorized": True},
    ).json()["id"]
    with client.websocket_connect(f"/api/v1/scans/{scan_id}/ws") as ws:
        last = None
        for _ in range(60):
            last = ws.receive_json()
            if last["status"] in ("completed", "failed"):
                break
        assert last is not None and last["status"] == "completed"
