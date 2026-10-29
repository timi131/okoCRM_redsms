"""Имитация OkoCRM для ручной проверки моста с настоящим REDSMS.

Скрипт поднимает «API OkoCRM» на 127.0.0.1:9900 и печатает всё, что туда шлёт мост
(PUT senders, POST status, POST events), а в мост отправляет подписанные installed и sms.send.

Мост запускать так (в другом терминале):
    ALLOW_INSECURE_URLS=true OKOCRM_API_BASE=http://127.0.0.1:9900/v4/sms OKOCRM_WIDGET_PRIVATE_KEY=test \
    APP_SECRET=$(openssl rand -hex 32) \
    ENCRYPTION_KEY=$(python3 -m okocrm_redsms genkey) \
    PUBLIC_BASE_URL=https://<туннель или любой> POLL_AFTER_MINUTES=1 python3 -m okocrm_redsms

Затем:
    python3 tools/simulate.py --login LOGIN --api-key KEY --sender SENDER --phone +79991234567
"""
import argparse
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ULID = "01SIMULATE0000000000000000"


class FakeOko(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8")
        print(f"\n← мост → OkoCRM: {self.command} {self.path}\n  {body}")
        if self.path.endswith("/senders"):
            data, code = json.dumps({"senders": len(json.loads(body))}).encode(), 200
        else:
            data, code = b"", 204
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_POST = do_PUT = handle_any


def signed_post(bridge, path, payload, key, extra_headers=None):
    raw = json.dumps(payload).encode()  # ensure_ascii=True, как у OkoCRM (\uXXXX)
    headers = {"Content-Type": "application/json", "X-Oko-Event": payload["event"],
               "Signature": hmac.new(key.encode(), raw, hashlib.sha256).hexdigest(), **(extra_headers or {})}
    req = urllib.request.Request(bridge + path, data=raw, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bridge", default="http://127.0.0.1:8080")
    p.add_argument("--private-key", default="test", help="OKOCRM_WIDGET_PRIVATE_KEY моста")
    p.add_argument("--login", required=True)
    p.add_argument("--api-key", required=True)
    p.add_argument("--sender", required=True, help="имя отправителя, зарегистрированное в REDSMS")
    p.add_argument("--phone", help="если указан — будет отправлена настоящая SMS (платно)")
    p.add_argument("--text", default="Тест интеграции OkoCRM ↔ REDSMS")
    p.add_argument("--port", type=int, default=9900)
    p.add_argument("--telegram", action="store_true", help="включить каскад Telegram → SMS для кодов")
    a = p.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", a.port), FakeOko)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("→ installed")
    print(" ", signed_post(a.bridge, "/okocrm/events", {
        "event": "installed", "site_id": 1, "subdomain": "simulate", "setting_ulid": ULID,
        "time": int(time.time()), "token": ULID + ".simulated-secret",
        "settings": {"login": a.login, "api_key": a.api_key, "senders": a.sender, "telegram_codes": a.telegram}, "user": None}, a.private_key))

    if a.phone:
        time.sleep(2)
        key = uuid.uuid4().hex
        print("\n→ sms.send")
        print(" ", signed_post(a.bridge, "/okocrm/send", {
            "event": "sms.send", "site_id": 1, "subdomain": "simulate", "setting_ulid": ULID,
            "message_key": key, "phone": a.phone, "text": a.text, "sender": a.sender,
            "send_at": None, "time": int(time.time())}, a.private_key, {"Idempotency-Key": key}))

    print("\nЖду запросов от моста (Ctrl+C — выход). Статус доставки придёт по колбэку или опросом через ~1–2 мин.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
