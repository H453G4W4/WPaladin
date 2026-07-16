"""In-memory scan store shared by the API and dashboard.

Tracks scan lifecycle (queued → running → completed/failed) and holds results
for retrieval and reporting. Deliberately dependency-free and process-local; a
production deployment would swap this for a database-backed implementation
behind the same interface.
"""

from __future__ import annotations

import asyncio
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .core.scanner import ScanResult


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanRecord:
    """A single tracked scan."""

    id: str
    url: str
    profile: str
    status: ScanStatus = ScanStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: ScanResult | None = None
    error: str | None = None

    def touch(self, status: ScanStatus) -> None:
        self.status = status
        self.updated_at = time.time()

    def summary(self) -> dict[str, Any]:
        """A compact, JSON-serializable status view (no full findings)."""
        data: dict[str, Any] = {
            "id": self.id,
            "url": self.url,
            "profile": self.profile,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "error": self.error,
        }
        if self.result is not None:
            data["severity_counts"] = self.result.severity_counts()
            data["findings_count"] = len(self.result.findings)
            data["highest_severity"] = (
                self.result.highest_severity.value
                if self.result.highest_severity
                else None
            )
            data["duration_seconds"] = round(self.result.duration_seconds, 3)
        return data


class ScanStore:
    """Thread-safe-enough async store keyed by scan id."""

    def __init__(self) -> None:
        self._records: dict[str, ScanRecord] = {}
        self._lock = asyncio.Lock()

    async def create(self, url: str, profile: str) -> ScanRecord:
        record = ScanRecord(id=uuid.uuid4().hex[:12], url=url, profile=profile)
        async with self._lock:
            self._records[record.id] = record
        return record

    async def get(self, scan_id: str) -> ScanRecord | None:
        async with self._lock:
            return self._records.get(scan_id)

    async def list(self) -> list[ScanRecord]:
        async with self._lock:
            return sorted(
                self._records.values(), key=lambda r: r.created_at, reverse=True
            )

    async def set_running(self, scan_id: str) -> None:
        async with self._lock:
            if rec := self._records.get(scan_id):
                rec.touch(ScanStatus.RUNNING)

    async def set_result(self, scan_id: str, result: ScanResult) -> None:
        async with self._lock:
            if rec := self._records.get(scan_id):
                rec.result = result
                rec.touch(ScanStatus.COMPLETED)

    async def set_failed(self, scan_id: str, error: str) -> None:
        async with self._lock:
            if rec := self._records.get(scan_id):
                rec.error = error
                rec.touch(ScanStatus.FAILED)
