import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from okocrm_redsms import service  # noqa: E402
from okocrm_redsms.config import Config  # noqa: E402
from okocrm_redsms.http_server import make_server  # noqa: E402
from okocrm_redsms.service import Bridge  # noqa: E402
from okocrm_redsms.crypto import Cipher, generate_key  # noqa: E402
from okocrm_redsms.redsms import extract_code  # noqa: E402
from okocrm_redsms.store import Store, parse_senders, split_senders  # noqa: E402

ENC_KEY = generate_key()

PRIVATE_KEY = "widget-private-key"
ULID = "01J8Z4N6QYUXH2FA3K5T8DGN2E"
TOKEN = ULID + ".secret"


class Fake:
    """Фейковые REDSMS и OkoCRM в одном HTTP-сервере, пишут все запросы в self.calls."""

    def __init__(self):
        self.calls = []
        self.client_info = (200, {"info": {"login": "user", "balance": 100.0, "active": True}, "success": True})
        self.send_reply = (200, {"items": [{"uuid": "uuid-1", "status": "created", "status_time": 1, "to": "+7"}],
                                 "errors": [], "count": 1, "success": True})
        self.get_reply = (200, {"item": {"uuid": "uuid-1", "status": "delivered"}, "success": True})
        self.get_items = {}  # uuid → item для GET /api/message/{uuid}
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"null")
                fake.calls.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                p = self.path
                if p == "/api/client/info":
                    status, data = fake.client_info
                elif p == "/api/message":
                    status, data = fake.send_reply
                elif p.startswith("/api/message/"):
                    message_uuid = p.split("/")[3].split("?")[0]
                    if message_uuid in fake.get_items:
                        status, data = 200, {"item": fake.get_items[message_uuid], "success": True}
                    else:
                        status, data = fake.get_reply
                elif p == "/v4/sms/senders":
                    status, data = 200, {"senders": len(body)}
                elif p.startswith("/v4/sms/"):
                    status, data = 204, None
                else:
                    status, data = 404, {"message": "nope"}
                raw = json.dumps(data).encode() if data is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def find(self, method, path):
        return [c for c in self.calls if c[0] == method and c[1].split("?")[0] == path]


class BridgeTest(unittest.TestCase):
    def setUp(self):
        service.STATUS_DELAY = 0.0
        self.fake = Fake()
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(widget_private_key=PRIVATE_KEY, app_secret="app-secret",
                          public_base_url="https://bridge.example.com",
                          db_path=os.path.join(self.tmp.name, "db.sqlite3"),
                          okocrm_api_base=self.fake.base + "/v4/sms",
                          redsms_api_base=self.fake.base + "/api",
                          redsms_allowed_ips=[])
        self.bridge = Bridge(self.cfg, Store(self.cfg.db_path, Cipher([ENC_KEY])))
        self.bridge.start()
        self.server = make_server(self.bridge, "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.bridge.stop()
        self.fake.server.shutdown()
        self.tmp.cleanup()

    # --- helpers ---------------------------------------------------------

    def post(self, path, body, headers=None, sign=True, raw=None):
        data = raw if raw is not None else json.dumps(body, ensure_ascii=True).encode()
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        if sign:
            hdrs["Signature"] = hmac.new(PRIVATE_KEY.encode(), data, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.base + path, data=data, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def wait(self, predicate, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            if predicate():
                return
            time.sleep(0.05)
        self.fail("не дождались условия; calls=%r" % [(c[0], c[1], c[3]) for c in self.fake.calls])

    def install(self, settings=None):
        settings = settings or {"login": "user", "api_key": "KEY", "senders": "Shop, Shop-24"}
        status, _ = self.post("/okocrm/events", {
            "event": "installed", "site_id": 1, "subdomain": "demo", "setting_ulid": ULID,
            "time": 1, "token": TOKEN, "settings": settings, "user": None})
        self.assertEqual(status, 200)

    def send(self, key="a" * 32, **extra):
        body = {"event": "sms.send", "site_id": 1, "subdomain": "demo", "setting_ulid": ULID,
                "message_key": key, "phone": "+79991234567", "text": "Ваш заказ готов",
                "sender": "Shop", "send_at": None, "time": 1, **extra}
        return self.post("/okocrm/send", body, headers={"Idempotency-Key": key})

    def oko_events(self):
        return [c[3] for c in self.fake.find("POST", "/v4/sms/events")]

    # --- tests -----------------------------------------------------------

    def test_rejects_bad_signature(self):
        status, _ = self.post("/okocrm/events", {"event": "installed"}, headers={"Signature": "00"}, sign=False)
        self.assertEqual(status, 403)

    def test_installed_pushes_senders_and_status_ok(self):
        self.install()
        self.wait(lambda: self.fake.find("PUT", "/v4/sms/senders") and self.fake.find("POST", "/v4/sms/status"))
        m, _, headers, body = self.fake.find("PUT", "/v4/sms/senders")[0]
        self.assertEqual(body, [{"name": "Shop"}, {"name": "Shop-24"}])
        self.assertEqual(headers["authorization"], "Bearer " + TOKEN)
        self.assertEqual(self.fake.find("POST", "/v4/sms/status")[0][3], {"status": "ok"})
        # Подпись REDSMS: secret = md5(ts + api_key)
        _, _, rh, _ = self.fake.find("GET", "/api/client/info")[0]
        self.assertEqual(rh["secret"], hashlib.md5((rh["ts"] + "KEY").encode()).hexdigest())
        self.assertEqual(rh["login"], "user")

    def test_bad_credentials_report_error_status(self):
        self.fake.client_info = (401, {"success": False})
        self.install()
        self.wait(lambda: self.fake.find("POST", "/v4/sms/status"))
        body = self.fake.find("POST", "/v4/sms/status")[0][3]
        self.assertEqual(body["status"], "error")
        self.assertIn("авторизац", body["message"])

    def test_send_delivers_and_reports_statuses(self):
        self.install()
        status, body = self.send()
        self.assertEqual(status, 200)
        message_id = body["message_id"]

        self.wait(lambda: self.fake.find("POST", "/api/message"))
        _, _, _, sent = self.fake.find("POST", "/api/message")[0]
        self.assertEqual(sent["route"], "sms")
        self.assertEqual(sent["to"], "+79991234567")
        self.assertEqual(sent["from"], "Shop")
        self.assertEqual(sent["text"], "Ваш заказ готов")
        self.assertNotIn("startTime", sent)
        dlr_path = urllib.parse.urlsplit(sent["dlrUrl"]).path

        self.wait(lambda: any(e["status"] == "sent" for e in self.oko_events()))

        # Колбэк REDSMS в формате x-www-form-urlencoded
        req = urllib.request.Request(self.base + dlr_path, data=b"uuid=uuid-1&status=delivered&status_time=2",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))
        delivered = [e for e in self.oko_events() if e["status"] == "delivered"][0]
        self.assertEqual(delivered["message_id"], message_id)
        self.assertEqual(delivered["event"], "sms.status")

    def test_idempotent_repeat_returns_same_id(self):
        self.install()
        _, first = self.send()
        _, second = self.send()
        self.assertEqual(first["message_id"], second["message_id"])
        time.sleep(0.5)
        self.assertEqual(len(self.fake.find("POST", "/api/message")), 1)

    def test_redsms_rejection_becomes_failed_status(self):
        self.fake.send_reply = (400, {"error_message": "error while creating messages",
                                      "errors": [{"to": "+7", "message": "bad number rejected"}], "success": False})
        self.install()
        self.send()
        self.wait(lambda: any(e["status"] == "failed" for e in self.oko_events()))
        failed = [e for e in self.oko_events() if e["status"] == "failed"][0]
        self.assertIn("bad number rejected", failed["error"]["message"])

    def test_failed_dlr_maps_reason(self):
        self.install()
        self.send()
        self.wait(lambda: self.fake.find("POST", "/api/message"))
        dlr_path = urllib.parse.urlsplit(self.fake.find("POST", "/api/message")[0][3]["dlrUrl"]).path
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        self.post(dlr_path, None, sign=False, raw=b'{"uuid":"uuid-1","status":"stop_list"}')
        self.wait(lambda: any(e["status"] == "failed" for e in self.oko_events()))
        failed = [e for e in self.oko_events() if e["status"] == "failed"][0]
        self.assertEqual(failed["error"]["code"], "stop_list")

    def test_dlr_with_forged_signature_is_ignored(self):
        status, _ = self.post(f"/redsms/dlr/{ULID}/deadbeef", None, sign=False, raw=b"uuid=uuid-1&status=delivered")
        self.assertEqual(status, 404)

    def test_deferred_send_passes_start_time(self):
        self.install()
        at = int(time.time()) + 3600
        self.send(send_at=at)
        self.wait(lambda: self.fake.find("POST", "/api/message"))
        self.assertEqual(self.fake.find("POST", "/api/message")[0][3]["startTime"], at)

    def test_send_at_beyond_seven_days_is_rejected(self):
        self.install()
        status, body = self.send(send_at=int(time.time()) + 8 * 86400)
        self.assertEqual(status, 422)
        self.assertIn("7 дней", body["error"]["message"])

    def test_unknown_connection_is_rejected(self):
        status, body = self.send()
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "not_connected")

    def test_uninstalled_drops_token(self):
        self.install()
        self.post("/okocrm/events", {"event": "uninstalled", "site_id": 1, "subdomain": "demo",
                                     "setting_ulid": ULID, "time": 2})
        status, _ = self.send()
        self.assertEqual(status, 409)

    def test_poll_picks_up_missed_status(self):
        self.install()
        self.send()
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        self.cfg.poll_after_minutes = 0
        msg = self.bridge.store.find_by_uuid(ULID, "uuid-1")
        self.bridge.store.update_message(msg["id"], created_at=int(time.time()) - 5)
        self.bridge.poll_stale_messages()
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))

    def test_invalid_senders_are_named_in_status(self):
        self.install({"login": "user", "api_key": "KEY", "senders": "Магазин, ThisNameIsWayTooLong"})
        self.wait(lambda: self.fake.find("POST", "/v4/sms/status"))
        body = self.fake.find("POST", "/v4/sms/status")[0][3]
        self.assertEqual(body["status"], "error")
        self.assertIn("Магазин", body["message"])
        self.assertFalse(self.fake.find("PUT", "/v4/sms/senders"))

    def test_garbage_phone_rejected_synchronously(self):
        self.install()
        status, body = self.send(phone="123")
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "bad_number")
        time.sleep(0.3)
        self.assertFalse(self.fake.find("POST", "/api/message"))

    def test_status_is_pushed_once_under_races(self):
        self.install()
        _, body = self.send()
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        msg = self.bridge.store.find_by_uuid(ULID, "uuid-1")
        # Колбэк и опрос одновременно сообщают delivered
        threads = [threading.Thread(target=self.bridge.apply_redsms_status, args=(msg, "delivered")) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))
        time.sleep(0.3)
        self.assertEqual(sum(e["status"] == "delivered" for e in self.oko_events()), 1)
        # failed после delivered не отправляется
        self.bridge.apply_redsms_status(msg, "undelivered")
        time.sleep(0.3)
        self.assertFalse(any(e["status"] == "failed" for e in self.oko_events()))

    def test_purge_removes_old_messages(self):
        self.install()
        _, body = self.send()
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        self.bridge.store.update_message(body["message_id"], created_at=int(time.time()) - 40 * 86400)
        self.bridge.purge()
        self.assertIsNone(self.bridge.store.get_message(body["message_id"]))

    def test_healthz_checks_database(self):
        with urllib.request.urlopen(self.base + "/healthz", timeout=5) as r:
            self.assertEqual(json.loads(r.read()), {"ok": True})

    # --- лимиты ----------------------------------------------------------

    def test_rate_limit_per_phone(self):
        self.cfg.rate_limit_per_phone_hour = 2
        self.install()
        self.assertEqual(self.send(key="1" * 32, text="один")[0], 200)
        self.assertEqual(self.send(key="2" * 32, text="два")[0], 200)
        status, body = self.send(key="3" * 32, text="три")
        self.assertEqual(status, 429)
        self.assertEqual(body["error"]["code"], "rate_limited")
        self.assertIn("на один номер", body["error"]["message"])
        # другой номер — можно
        self.assertEqual(self.send(key="4" * 32, text="три", phone="+79990000001")[0], 200)

    def test_duplicate_text_rejected_but_retry_after_failure_allowed(self):
        self.install()
        _, first = self.send(key="1" * 32)
        status, body = self.send(key="2" * 32)
        self.assertEqual(status, 429)
        self.assertIn("такое же SMS", body["error"]["message"])
        # Менеджер жмёт «Повторить» после ошибки — лимит не мешает
        self.wait(lambda: any(e["status"] == "sent" for e in self.oko_events()))
        self.bridge._fail(self.bridge.store.get_message(first["message_id"]), "x", "ошибка")
        self.bridge.apply_redsms_status(self.bridge.store.get_message(first["message_id"]), "progress")  # запоздавший sent
        self.assertEqual(self.bridge.store.get_message(first["message_id"])["oko_status"], "failed")
        self.assertEqual(self.send(key="3" * 32)[0], 200)

    def test_limit_from_widget_settings(self):
        self.install({"login": "user", "api_key": "KEY", "senders": "Shop", "limit_per_hour": "1"})
        self.assertEqual(self.send(key="1" * 32, text="один")[0], 200)
        status, body = self.send(key="2" * 32, text="два", phone="+79990000001")
        self.assertEqual(status, 429)
        self.assertIn("1 SMS в час", body["error"]["message"])

    # --- каскад Telegram → SMS ------------------------------------------

    def install_tg(self):
        self.install({"login": "user", "api_key": "KEY", "senders": "Shop", "telegram_codes": True})

    def dlr(self, body):
        path = urllib.parse.urlsplit(self.bridge.dlr_url(ULID)).path
        req = urllib.request.Request(self.base + path, data=body.encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)

    def test_cascade_sends_code_via_telegram_then_sms(self):
        self.install_tg()
        _, body = self.send(text="Ваш код подтверждения: 4821")
        self.wait(lambda: self.fake.find("POST", "/api/message"))
        sent = self.fake.find("POST", "/api/message")[0][3]
        self.assertEqual(sent["route"], "tgauth,sms")
        self.assertEqual(sent["tgauth_text"], "4821")
        self.assertEqual(sent["sms_text"], "Ваш код подтверждения: 4821")
        self.assertEqual(sent["sms_from"], "Shop")
        self.assertEqual(sent["tgauth_validity"], 180)
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)

        # Telegram не доставил — это не ошибка, REDSMS создал SMS-шаг uuid-2
        self.fake.get_items["uuid-1"] = {"uuid": "uuid-1", "status": "undelivered", "child_uuid": "uuid-2"}
        self.dlr("uuid=uuid-1&status=undelivered")
        self.wait(lambda: self.bridge.store.get_message(body["message_id"])["redsms_uuid"] == "uuid-2")
        self.assertFalse(any(e["status"] == "failed" for e in self.oko_events()))

        self.dlr("uuid=uuid-1&status=timeout")  # запоздалый статус Telegram игнорируется
        self.dlr("uuid=uuid-2&status=delivered")
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))
        time.sleep(0.3)
        self.assertFalse(any(e["status"] == "failed" for e in self.oko_events()))

    def test_cascade_sms_callback_before_telegram_status(self):
        self.install_tg()
        _, body = self.send(text="Code 123456")
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        self.fake.get_items["uuid-2"] = {"uuid": "uuid-2", "status": "delivered", "parent_uuid": "uuid-1"}
        self.dlr("uuid=uuid-2&status=delivered")
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))
        self.assertEqual(self.bridge.store.get_message(body["message_id"])["redsms_uuid"], "uuid-2")

    def test_cascade_telegram_delivered(self):
        self.install_tg()
        self.send(text="Ваш код 4821")
        self.wait(lambda: self.bridge.store.find_by_uuid(ULID, "uuid-1") is not None)
        self.dlr("uuid=uuid-1&status=delivered")
        self.wait(lambda: any(e["status"] == "delivered" for e in self.oko_events()))

    def test_notification_without_code_goes_as_plain_sms(self):
        self.install_tg()
        self.send(text="Заказ 12345 готов к выдаче")
        self.wait(lambda: self.fake.find("POST", "/api/message"))
        self.assertEqual(self.fake.find("POST", "/api/message")[0][3]["route"], "sms")

    # --- шифрование -------------------------------------------------------

    def test_secrets_are_encrypted_at_rest(self):
        self.install()
        import sqlite3
        raw = sqlite3.connect(self.cfg.db_path).execute(
            "SELECT token, api_key FROM connections WHERE setting_ulid = ?", (ULID,)).fetchone()
        for value in raw:
            self.assertTrue(value.startswith("enc:"))
        self.assertNotIn("secret", raw[0])
        conn = self.bridge.store.get_connection(ULID)
        self.assertEqual((conn["token"], conn["api_key"]), (TOKEN, "KEY"))


class CryptoTest(unittest.TestCase):
    def test_plaintext_migration_and_key_rotation(self):
        import sqlite3
        old_key, new_key = generate_key(), generate_key()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "db.sqlite3")
            Store(path, Cipher([old_key]))
            c = sqlite3.connect(path)
            c.execute("INSERT INTO connections (setting_ulid, token, api_key) VALUES (?, ?, ?)", (ULID, TOKEN, "KEY"))
            c.commit()
            # Старая версия хранила открытым текстом — при старте шифруется
            store = Store(path, Cipher([old_key]))
            self.assertTrue(c.execute("SELECT api_key FROM connections").fetchone()[0].startswith("enc:"))
            self.assertEqual(store.get_connection(ULID)["api_key"], "KEY")
            # Смена ключа: «новый,старый» → перешифровано новым, старый можно убрать
            Store(path, Cipher([new_key, old_key]))
            self.assertEqual(Store(path, Cipher([new_key])).get_connection(ULID)["token"], TOKEN)
            with self.assertRaises(RuntimeError):  # чужой ключ — отказ при старте, а не порча данных
                Store(path, Cipher([generate_key()]))

    def test_extract_code(self):
        self.assertEqual(extract_code("Ваш код: 4821"), "4821")
        self.assertEqual(extract_code("Code 12345678 for login"), "12345678")
        self.assertEqual(extract_code("Пароль для входа 0042"), "0042")
        self.assertIsNone(extract_code("Заказ 12345 готов"))            # нет слова «код»
        self.assertIsNone(extract_code("Код 1234 действует до 2026 г."))  # два числа — неоднозначно
        self.assertIsNone(extract_code("Ваш код 123"))                   # короче 4 цифр
        self.assertIsNone(extract_code("Код по номеру +79991234567"))   # телефон — не код


class SendersTest(unittest.TestCase):
    def test_parse_senders(self):
        self.assertEqual(parse_senders("Shop, Shop-24;Shop\nТест, ThisNameIsWayTooLong, "),
                         ["Shop", "Shop-24"])

    def test_split_senders_reports_rejected(self):
        self.assertEqual(split_senders("Shop, Тест, ,Shop"), (["Shop"], ["Тест"]))

    def test_migration_adds_column(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.sqlite3")
            c = sqlite3.connect(path)
            c.execute("CREATE TABLE connections (setting_ulid TEXT PRIMARY KEY, site_id INTEGER, subdomain TEXT, "
                      "token TEXT, login TEXT, api_key TEXT, senders TEXT NOT NULL DEFAULT '[]', status TEXT, "
                      "status_message TEXT, installed_at INTEGER, updated_at INTEGER, deleted_at INTEGER)")
            c.commit()
            c.close()
            store = Store(path, Cipher([ENC_KEY]))
            store.upsert_connection(ULID, 1, "demo", {"login": "u", "api_key": "k", "senders": "Shop, Тест"})
            self.assertEqual(json.loads(store.get_connection(ULID)["senders_rejected"]), ["Тест"])


if __name__ == "__main__":
    unittest.main()
