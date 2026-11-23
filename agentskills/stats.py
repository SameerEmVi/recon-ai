"""Skill call-stats — a small JSON sidecar beside the skill library.

Records when a skill is loaded into an agent's context: total loads, distinct
scans ("tasks") it covered, and the last-loaded timestamp. Kept as a sidecar file
(`<skills_dir>/.skill_stats.json`) so the library stays self-contained and
portable (no DB coupling). Never raises into the caller — a telemetry write can
never break a scan.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime

_FILE = ".skill_stats.json"
_ZERO = {"total_calls": 0, "tasks_covered": 0, "last_called": None}


class SkillStatsStore:
    def __init__(self, skills_dir: str) -> None:
        self._path = os.path.join(skills_dir, _FILE)
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def record_load(self, name: str, scan_id: str | None = None) -> None:
        if not name:
            return
        with self._lock:
            data = self._read()
            e = data.get(name) or {"total_calls": 0, "scans": [], "last_called": None}
            e["total_calls"] = int(e.get("total_calls", 0)) + 1
            if scan_id:
                scans = e.setdefault("scans", [])
                if scan_id not in scans:
                    scans.append(scan_id)
            e["last_called"] = datetime.now(UTC).isoformat()
            data[name] = e
            try:
                tmp = self._path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.replace(tmp, self._path)
            except OSError:
                pass            # telemetry must never break the caller

    def snapshot(self) -> dict:
        with self._lock:
            data = self._read()
        out: dict = {}
        for name, e in data.items():
            if not isinstance(e, dict):
                continue
            out[name] = {
                "total_calls": int(e.get("total_calls", 0)),
                "tasks_covered": len(e.get("scans", []) or []),
                "last_called": e.get("last_called"),
            }
        return out

    def for_skill(self, name: str) -> dict:
        return self.snapshot().get(name, dict(_ZERO))
