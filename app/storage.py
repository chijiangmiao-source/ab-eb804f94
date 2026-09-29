"""审计结论的持久化：原子写入 JSON 文件，冻结后不可改写。"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .rules import adjudicate, fingerprint, parse_audit


class PayloadConflict(Exception):
    """同一审计标识改换了载荷——明确拒绝，不动既有结论。"""

    def __init__(self, audit_id: str):
        super().__init__(f"审计标识 {audit_id!r} 已冻结为另一份载荷，拒绝改写")
        self.audit_id = audit_id


class Store:
    def __init__(self, data_dir: str | os.PathLike = "/data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.data_dir / ".lock", "w")
        try:
            import fcntl

            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - 非 POSIX 平台退化
            pass

    def _path(self, audit_id: str) -> Path:
        return self.data_dir / f"{audit_id}.json"

    def _read(self, audit_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(audit_id)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _summary(record: Dict[str, Any]) -> Dict[str, Any]:
        return {"rules": record["rules"], "decisions": record["decisions"]}

    def submit(self, payload: Any) -> Dict[str, Any]:
        audit_id, rules = parse_audit(payload)
        fp = fingerprint(audit_id, rules)

        existing = self._read(audit_id)
        if existing is not None:
            if existing["fingerprint"] == fp:
                return {
                    "audit_id": audit_id,
                    "frozen": True,
                    "identical_resubmission": True,
                    **self._summary(existing),
                }
            raise PayloadConflict(audit_id)

        decisions = adjudicate(rules)
        record = {
            "audit_id": audit_id,
            "fingerprint": fp,
            "rules": [r.to_dict() for r in rules],
            "decisions": decisions,
        }
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.replace(tmp, self._path(audit_id))
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        return {
            "audit_id": audit_id,
            "frozen": True,
            "identical_resubmission": False,
            **self._summary(record),
        }

    def get_record(self, audit_id: str) -> Optional[Dict[str, Any]]:
        return self._read(audit_id)

    def list_ids(self) -> List[str]:
        return sorted(p.stem for p in self.data_dir.glob("*.json"))
