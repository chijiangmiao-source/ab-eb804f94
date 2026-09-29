"""零依赖 HTTP 服务：审计规则录入、冻结结论查询、健康检查、静态页面。"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .rules import _AUDIT_RE, ValidationError
from .storage import PayloadConflict, Store

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class AppHandler(BaseHTTPRequestHandler):
    server_version = "FlightRuleAudit/1.0"
    store: Store  # 由 build_server 注入到类上

    # ---- 基础工具 ------------------------------------------------------
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_static(self, filename: str, content_type: str) -> None:
        path = os.path.join(STATIC_DIR, filename)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # 精简访问日志
        print(f"[http] {self.address_string()} - {fmt % args}")

    # ---- 路由 ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/api/audits":
            ids = self.store.list_ids()
            self._send_json(HTTPStatus.OK, {"audit_ids": ids})
            return
        if path.startswith("/api/audits/"):
            audit_id = path.rsplit("/", 1)[-1]
            if not _AUDIT_RE.fullmatch(audit_id):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "审计标识不合法或不存在"})
                return
            record = self.store.get_record(audit_id)
            if record is None:
                self._send_json(HTTPStatus.NOT_FOUND,
                                {"error": f"审计标识 {audit_id!r} 不存在"})
            else:
                self._send_json(HTTPStatus.OK, record)
            return
        if path in ("/", "/index.html"):
            self._send_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/static/app.js":
            self._send_static("app.js", "application/javascript; charset=utf-8")
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/audits":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "请求体不是合法 UTF-8 JSON"})
            return

        try:
            result = self.store.submit(payload)
        except ValidationError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except PayloadConflict as exc:
            self._send_json(HTTPStatus.CONFLICT, {
                "error": str(exc),
                "audit_id": exc.audit_id,
            })
            return

        status = HTTPStatus.OK if result.get("identical_resubmission") else HTTPStatus.CREATED
        self._send_json(status, result)


def build_server(host: str = "0.0.0.0", port: int = 8080, data_dir: str = "/data") -> ThreadingHTTPServer:
    store = Store(data_dir)

    class _Bound(AppHandler):
        pass

    _Bound.store = store
    httpd = ThreadingHTTPServer((host, port), _Bound)
    httpd.store = store  # type: ignore[attr-defined]
    return httpd


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    data_dir = os.environ.get("DATA_DIR", "/data")
    httpd = build_server(host, port, data_dir)
    print(f"[boot] 飞行数据链路规则遮蔽审计服务监听 {host}:{port}，数据目录 {data_dir}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
