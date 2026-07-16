"""Targeted tests for store lifecycle, profiles, and API pre-completion states."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from wp_sentinel.api import create_app
from wp_sentinel.core.profile import get_profile, PROFILES
from wp_sentinel.core.scanner import ScanResult
from wp_sentinel.core.target import Target
from wp_sentinel.store import ScanStatus, ScanStore


# ---- profiles ----

def test_get_profile_known_and_unknown():
    assert get_profile("standard").name == "standard"
    with pytest.raises(KeyError) as exc:
        get_profile("ludicrous")
    assert "ludicrous" in str(exc.value)
    assert set(PROFILES) == {"passive", "standard", "thorough"}


# ---- store lifecycle ----

async def test_store_lifecycle():
    store = ScanStore()
    rec = await store.create("https://example.com", "standard")
    assert rec.status is ScanStatus.QUEUED
    assert (await store.get(rec.id)) is rec
    assert await store.get("missing") is None

    await store.set_running(rec.id)
    assert (await store.get(rec.id)).status is ScanStatus.RUNNING

    result = ScanResult(target=Target.parse("https://example.com"),
                        profile_name="standard")
    result.findings = []
    await store.set_result(rec.id, result)
    fetched = await store.get(rec.id)
    assert fetched.status is ScanStatus.COMPLETED
    summary = fetched.summary()
    assert summary["findings_count"] == 0 and summary["highest_severity"] is None


async def test_store_set_failed_and_ordering():
    store = ScanStore()
    a = await store.create("https://a.example", "standard")
    b = await store.create("https://b.example", "standard")
    await store.set_failed(b.id, "boom")
    listed = await store.list()
    # newest first
    assert listed[0].id == b.id and listed[0].status is ScanStatus.FAILED
    assert listed[0].summary()["error"] == "boom"
    assert {r.id for r in listed} == {a.id, b.id}


# ---- API states before completion ----

@pytest.fixture
def app_client():
    app = create_app(transport=httpx.MockTransport(
        lambda r: httpx.Response(404, text="nf")))
    with TestClient(app) as c:
        yield app, c


def test_findings_and_report_before_completion(app_client):
    app, client = app_client

    # Insert a queued record directly (result is None) via the app's event loop.
    scan_id = client.portal.call(
        app.state.store.create, "https://x.example", "standard"
    ).id

    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert findings["status"] == "queued" and findings["findings"] == []

    report = client.get(f"/api/v1/scans/{scan_id}/report")
    assert report.status_code == 409


def test_report_unknown_format_for_completed(app_client):
    app, client = app_client
    result = ScanResult(target=Target.parse("https://x.example"), profile_name="standard")
    result.findings = []
    rec = client.portal.call(app.state.store.create, "https://x.example", "standard")
    client.portal.call(app.state.store.set_result, rec.id, result)
    resp = client.get(f"/api/v1/scans/{rec.id}/report", params={"format": "pdf"})
    assert resp.status_code == 400
