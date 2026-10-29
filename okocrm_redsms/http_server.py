from __future__ import annotations

import json
import logging
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .service import Bridge, SendError, verify_signature

log = logging.getLogger("okocrm_redsms.http")

MAX_BODY = 1024 * 1024


def make_server(bridge: Bridge, host: str, port: int) -> ThreadingHTTPServer:
    cfg = bridge.cfg

    class Handler(BaseHTTPRequestHandler):
        server_version = "okocrm-redsms"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s " + fmt, self.client_ip(), *args)

        def client_ip(self) -> str:
            if cfg.trust_x_forwarded_for:
                xff = self.headers.get("X-Forwarded-For")
                if xff:
                    return xff.split(",")[0].strip()
            return self.client_address[0]

        def read_body(self) -> Optional[bytes]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self.reply(413, {"message": "Слишком большое тело"})
                return None
            return self.rfile.read(length) if length else b""

        def reply(self, status: int, body: Optional[Dict[str, Any]] = None) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else b""
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self.reply(200, {"ok": True})
            else:
                self.reply(404, {"message": "Not found"})

        def do_POST(self) -> None:
            path = urllib.parse.urlsplit(self.path).path.rstrip("/")
            body = self.read_body()
            if body is None:
                return
            try:
                if path == "/okocrm/events":
                    self.okocrm_events(body)
                elif path == "/okocrm/send":
                    self.okocrm_send(body)
                elif path.startswith("/redsms/dlr/"):
                    self.redsms_dlr(path, body)
                else:
                    self.reply(404, {"message": "Not found"})
            except Exception:  # noqa: BLE001
                log.exception("ошибка обработки %s", path)
                self.reply(500, {"error": {"code": "internal", "message": "Внутренняя ошибка интеграции REDSMS"}})

        # --- OkoCRM → нам ---------------------------------------------

        def signed_json(self, body: bytes) -> Optional[Dict[str, Any]]:
            # Подпись — по сырым байтам тела, до любого разбора JSON
            if not verify_signature(cfg.widget_private_key, body, self.headers.get("Signature", "")):
                log.warning("неверная подпись запроса %s от %s", self.path, self.client_ip())
                self.reply(403, {"message": "Invalid signature"})
                return None
            try:
                data = json.loads(body.decode("utf-8"))
            except ValueError:
                self.reply(400, {"message": "Invalid JSON"})
                return None
            if not isinstance(data, dict):
                self.reply(400, {"message": "Invalid JSON"})
                return None
            return data

        def okocrm_events(self, body: bytes) -> None:
            event = self.signed_json(body)
            if event is None:
                return
            try:
                bridge.handle_okocrm_event(event)
            except ValueError as e:
                self.reply(400, {"message": str(e)})
                return
            self.reply(200, {"ok": True})

        def okocrm_send(self, body: bytes) -> None:
            req = self.signed_json(body)
            if req is None:
                return
            try:
                message_id = bridge.handle_send(req)
            except SendError as e:
                self.reply(e.http_status, {"error": {"code": e.code, "message": e.message}})
                return
            self.reply(200, {"message_id": message_id})

        # --- REDSMS → нам ---------------------------------------------

        def redsms_dlr(self, path: str, body: bytes) -> None:
            parts = path.split("/")  # ['', 'redsms', 'dlr', ulid, sig]
            if len(parts) != 5 or not bridge.verify_dlr(parts[3], parts[4]):
                self.reply(404, {"message": "Not found"})
                return
            if cfg.redsms_allowed_ips and self.client_ip() not in cfg.redsms_allowed_ips:
                log.warning("DLR с чужого IP %s", self.client_ip())
                self.reply(403, {"message": "Forbidden"})
                return
            ctype = self.headers.get("Content-Type", "")
            if "json" in ctype:
                try:
                    data = json.loads(body.decode("utf-8") or "{}")
                except ValueError:
                    data = {}
            else:
                data = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8")).items()}
            bridge.handle_dlr(parts[3], data if isinstance(data, dict) else {})
            self.reply(200, {"ok": True})

    return ThreadingHTTPServer((host, port), Handler)
