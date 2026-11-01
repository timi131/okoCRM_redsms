"""Нагрузочный тест моста: N подключений, заданный поток sms.send в секунду.

Поднимает в отдельных процессах:
  * фейковые REDSMS и OkoCRM с задержками и лимитами как у настоящих
    (OkoCRM — 5 запросов/с на токен с ответом 429, REDSMS — колбэк delivered через ~1,5 с);
  * сам мост (python -m okocrm_redsms) с временной БД.

Затем устанавливает N подключений, даёт нагрузку и печатает отчёт: задержки ответа на sms.send,
задержку до передачи в REDSMS и до статуса «доставлено» в OkoCRM, новые TCP-соединения в секунду
к REDSMS (у REDSMS лимит 100/с с одного IP), 429 от OkoCRM, память и CPU моста.

    python3 tools/loadtest.py --connections 1000 --rps 100 --duration 60
"""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRIVATE_KEY = "loadtest-widget-key"


# ---------------------------------------------------------------------------
# Фейковые REDSMS + OkoCRM (отдельный процесс)
# ---------------------------------------------------------------------------

def serve_fakes(port: int, redsms_latency: float, okocrm_latency: float, dlr_delay: float) -> None:
    lock = threading.Lock()
    stats = {"redsms_messages": 0, "okocrm_429": 0, "okocrm_ok": 0, "senders": 0, "status": 0}
    submits = {}                      # phone → время получения POST /api/message
    events = defaultdict(dict)        # message_id → {status: время}
    new_conns = defaultdict(lambda: defaultdict(int))  # "redsms"/"okocrm" → секунда → новых соединений
    token_hits = defaultdict(deque)   # token → времена запросов за последнюю секунду
    dlr_pool = ThreadPoolExecutor(64)
    dlr_queue = []  # (когда отправить, url, uuid) — ждёт планировщик, а не потоки пула
    dlr_cv = threading.Condition()

    def dlr_scheduler() -> None:
        import heapq
        while True:
            with dlr_cv:
                while not dlr_queue or dlr_queue[0][0] > time.time():
                    dlr_cv.wait(max(0.0, dlr_queue[0][0] - time.time()) if dlr_queue else None)
                _, url, message_uuid = heapq.heappop(dlr_queue)
            dlr_pool.submit(send_dlr, url, message_uuid)

    def schedule_dlr(url: str, message_uuid: str) -> None:
        import heapq
        with dlr_cv:
            heapq.heappush(dlr_queue, (time.time() + dlr_delay, url, message_uuid))
            dlr_cv.notify()

    threading.Thread(target=dlr_scheduler, daemon=True).start()

    def send_dlr(url: str, message_uuid: str) -> None:
        u = urllib.parse.urlsplit(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        try:
            c.request("POST", u.path, body=f"uuid={message_uuid}&status=delivered&status_time={int(time.time())}",
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            c.getresponse().read()
        except OSError:
            pass
        finally:
            c.close()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        _kind = None

        def log_message(self, *a):
            pass

        def reply(self, status, data=None, headers=None):
            raw = json.dumps(data).encode() if data is not None else b""
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def count_conn(self, kind):
            if self._kind is None:  # первый запрос в этом TCP-соединении
                self._kind = kind
                with lock:
                    new_conns[kind][int(time.time())] += 1

        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            p = self.path
            if p == "/stats":
                with lock:
                    data = {"stats": stats, "submits": submits, "events": events,
                            "max_new_conns": {k: max(v.values() or [0]) for k, v in new_conns.items()}}
                return self.reply(200, data)
            if p.startswith("/api/"):
                self.count_conn("redsms")
                time.sleep(redsms_latency)
                if p == "/api/client/info":
                    return self.reply(200, {"info": {"login": "u", "balance": 1e6, "active": True}, "success": True})
                if p == "/api/message":
                    body = json.loads(raw)
                    message_uuid = str(uuid.uuid4())
                    with lock:
                        stats["redsms_messages"] += 1
                        submits[body.get("to")] = time.time()
                    schedule_dlr(body["dlrUrl"], message_uuid)
                    return self.reply(200, {"items": [{"uuid": message_uuid, "status": "created",
                                                       "to": body.get("to")}], "errors": [], "success": True})
                return self.reply(200, {"item": {"uuid": p.split("/")[3].split("?")[0], "status": "delivered"}})
            if p.startswith("/v4/sms/"):
                self.count_conn("okocrm")
                token = self.headers.get("Authorization", "")
                now = time.time()
                with lock:
                    q = token_hits[token]
                    while q and q[0] < now - 1:
                        q.popleft()
                    limited = len(q) >= 5
                    if limited:
                        stats["okocrm_429"] += 1
                    else:
                        q.append(now)
                if limited:
                    return self.reply(429, {"message": "Too Many Attempts."}, {"Retry-After": "1"})
                time.sleep(okocrm_latency)
                with lock:
                    stats["okocrm_ok"] += 1
                    if p.endswith("/senders"):
                        stats["senders"] += 1
                    elif p.endswith("/status"):
                        stats["status"] += 1
                    elif p.endswith("/events"):
                        e = json.loads(raw)
                        events[e["message_id"]].setdefault(e["status"], time.time())
                if p.endswith("/senders"):
                    return self.reply(200, {"senders": 1})
                return self.reply(204)
            self.reply(404, {"message": "nope"})

        do_GET = do_POST = do_PUT = handle_any

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 1024  # действует только как атрибут класса: listen() вызывается в __init__

    Server(("127.0.0.1", port), H).serve_forever()


# ---------------------------------------------------------------------------
# Генератор нагрузки
# ---------------------------------------------------------------------------

class Client:
    """Keep-alive соединение на поток, чтобы генератор сам не был узким местом."""

    def __init__(self, port: int):
        self.port = port
        self.local = threading.local()

    def post(self, path: str, payload: dict, headers: dict = None):
        raw = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json",
                "Signature": hmac.new(PRIVATE_KEY.encode(), raw, hashlib.sha256).hexdigest(), **(headers or {})}
        for attempt in range(2):
            c = getattr(self.local, "c", None)
            if c is None:
                c = self.local.c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            try:
                c.request("POST", path, body=raw, headers=hdrs)
                r = c.getresponse()
                return r.status, json.loads(r.read() or b"null")
            except (http.client.HTTPException, OSError):
                c.close()
                self.local.c = None
                if attempt:
                    return 0, None
        return 0, None


def stats(redsms_port: int, okocrm_port: int) -> dict:
    r, o = get_json(redsms_port, "/stats"), get_json(okocrm_port, "/stats")
    return {"stats": {**o["stats"], "redsms_messages": r["stats"]["redsms_messages"]},
            "submits": r["submits"], "events": o["events"],
            "max_new_conns": {"redsms": r["max_new_conns"].get("redsms", 0),
                              "okocrm": o["max_new_conns"].get("okocrm", 0)}}


def get_json(port: int, path: str):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        c.request("GET", path)
        return json.loads(c.getresponse().read())
    finally:
        c.close()


def pct(values, p):
    if not values:
        return float("nan")
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


def fmt(values):
    if not values:
        return "нет данных"
    return (f"p50 {pct(values, 50) * 1000:7.0f} мс   p95 {pct(values, 95) * 1000:7.0f} мс   "
            f"p99 {pct(values, 99) * 1000:7.0f} мс   max {max(values) * 1000:7.0f} мс")


def wait_port(port: int, timeout: float = 15) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            get_json(port, "/healthz" if port else "/stats")
            return
        except OSError:
            time.sleep(0.2)
        except ValueError:
            return
    raise SystemExit(f"порт {port} не поднялся")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--connections", type=int, default=1000)
    ap.add_argument("--rps", type=float, default=100)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--redsms-latency", type=float, default=0.15)
    ap.add_argument("--okocrm-latency", type=float, default=0.08)
    ap.add_argument("--dlr-delay", type=float, default=1.5)
    ap.add_argument("--drain-timeout", type=int, default=180)
    ap.add_argument("--fake-port", type=int, default=19900)
    ap.add_argument("--bridge-port", type=int, default=19901)
    ap.add_argument("--serve-fakes", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.serve_fakes:
        serve_fakes(a.fake_port, a.redsms_latency, a.okocrm_latency, a.dlr_delay)
        return

    tmp = tempfile.mkdtemp(prefix="okocrm-loadtest-")
    sys.path.insert(0, ROOT)
    from okocrm_redsms.crypto import generate_key
    # Фейки REDSMS и OkoCRM — в разных процессах, чтобы при сотнях запросов в секунду
    # узким местом не стал GIL самого теста
    redsms_port, okocrm_port = a.fake_port, a.fake_port + 2
    fakes = [subprocess.Popen([sys.executable, __file__, "--serve-fakes", "--fake-port", str(port),
                               "--redsms-latency", str(a.redsms_latency), "--okocrm-latency", str(a.okocrm_latency),
                               "--dlr-delay", str(a.dlr_delay)]) for port in (redsms_port, okocrm_port)]
    env = dict(os.environ,
               OKOCRM_WIDGET_PRIVATE_KEY=PRIVATE_KEY, APP_SECRET="x" * 64, ENCRYPTION_KEY=generate_key(),
               PUBLIC_BASE_URL=f"http://127.0.0.1:{a.bridge_port}", ALLOW_INSECURE_URLS="true",
               OKOCRM_API_BASE=f"http://127.0.0.1:{okocrm_port}/v4/sms",
               REDSMS_API_BASE=f"http://127.0.0.1:{redsms_port}/api",
               REDSMS_ALLOWED_IPS="", DB_PATH=os.path.join(tmp, "db.sqlite3"),
               LISTEN_HOST="127.0.0.1", LISTEN_PORT=str(a.bridge_port), LOG_LEVEL="WARNING",
               HEALTHCHECK_INTERVAL="100000", MAX_CONCURRENT_REQUESTS="256")
    log_path = os.path.join(tmp, "bridge.log")
    bridge = subprocess.Popen([sys.executable, "-m", "okocrm_redsms"], cwd=ROOT, env=env,
                              stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
    samples = []
    stop_sampling = threading.Event()

    def sample():
        while not stop_sampling.wait(1):
            out = subprocess.run(["ps", "-o", "rss=,%cpu=", "-p", str(bridge.pid)], capture_output=True, text=True)
            parts = out.stdout.split()
            if len(parts) == 2:
                samples.append((int(parts[0]) / 1024, float(parts[1].replace(",", "."))))

    try:
        wait_port(redsms_port)
        wait_port(okocrm_port)
        wait_port(a.bridge_port)
        threading.Thread(target=sample, daemon=True).start()
        client = Client(a.bridge_port)
        ulids = ["01LOAD" + f"{i:020d}" for i in range(a.connections)]

        # --- установка подключений ---
        t0 = time.time()
        with ThreadPoolExecutor(32) as ex:
            list(ex.map(lambda u: client.post("/okocrm/events", {
                "event": "installed", "site_id": 1, "subdomain": u[-6:], "setting_ulid": u,
                "time": int(time.time()), "token": u + ".secret",
                "settings": {"login": "u", "api_key": "k", "senders": "Shop"}, "user": None}), ulids))
        while time.time() - t0 < 300:
            st = stats(redsms_port, okocrm_port)["stats"]
            if st["status"] >= a.connections and st["senders"] >= a.connections:
                break
            time.sleep(1)
        print(f"Установка {a.connections} подключений: {time.time() - t0:.1f} с "
              f"(senders {st['senders']}, status {st['status']})")

        # --- нагрузка ---
        results = []
        res_lock = threading.Lock()

        def one(i: int, planned: float):
            ulid = random.choice(ulids)
            phone = "+79" + f"{random.randrange(10 ** 9):09d}"
            key = uuid.uuid4().hex
            started = time.time()
            status, body = client.post("/okocrm/send", {
                "event": "sms.send", "site_id": 1, "subdomain": "x", "setting_ulid": ulid, "message_key": key,
                "phone": phone, "text": f"Нагрузочный тест {i}", "sender": "Shop", "send_at": None,
                "time": int(started)}, {"Idempotency-Key": key})
            done = time.time()
            with res_lock:
                results.append({"phone": phone, "status": status, "started": started, "lag": started - planned,
                                "latency": done - started, "body": body})

        total = int(a.rps * a.duration)
        interval = 1.0 / a.rps
        print(f"Нагрузка: {a.rps:g} sms.send/с × {a.duration} с = {total} запросов…")
        t_load = time.time()
        with ThreadPoolExecutor(256) as ex:
            for i in range(total):
                planned = t_load + i * interval
                delay = planned - time.time()
                if delay > 0:
                    time.sleep(delay)
                ex.submit(one, i, planned)
        load_time = time.time() - t_load

        # --- ожидание доставки статусов ---
        ok = [r for r in results if r["status"] == 200 and r["body"] and r["body"].get("message_id")]
        ids = {r["body"]["message_id"] for r in ok}
        t_drain = time.time()
        while time.time() - t_drain < a.drain_timeout:
            data = stats(redsms_port, okocrm_port)
            delivered = sum(1 for m in ids if "delivered" in data["events"].get(m, {}))
            if delivered >= len(ids):
                break
            time.sleep(2)
        drain = time.time() - t_drain
        stop_sampling.set()

        # --- отчёт ---
        errors = defaultdict(int)
        for r in results:
            if r not in ok:
                code = (r["body"] or {}).get("error", {}).get("code") if isinstance(r["body"], dict) else None
                errors[f"HTTP {r['status']} {code or ''}".strip()] += 1
        submit_lag = [data["submits"][r["phone"]] - r["started"] for r in ok if r["phone"] in data["submits"]]
        e2e = [data["events"][r["body"]["message_id"]]["delivered"] - r["started"]
               for r in ok if "delivered" in data["events"].get(r["body"]["message_id"], {})]
        st = data["stats"]
        print()
        print("=" * 78)
        print(f"Отправлено запросов:       {len(results)} за {load_time:.1f} с ({len(results) / load_time:.1f}/с)")
        print(f"Принято (200):             {len(ok)}   ошибки: {dict(errors) or 'нет'}")
        print(f"Ответ на sms.send:         {fmt([r['latency'] for r in ok])}   (лимит OkoCRM — 4 с)")
        print(f"  из них дольше 4 с:       {sum(r['latency'] > 4 for r in results)}")
        print(f"До передачи в REDSMS:      {fmt(submit_lag)}")
        print(f"До «доставлено» в OkoCRM:  {fmt(e2e)}")
        print(f"Статус дошёл до OkoCRM:    {len(e2e)} из {len(ok)}, догоняли после нагрузки {drain:.0f} с")
        print(f"REDSMS: сообщений {st['redsms_messages']}, новых TCP-соединений в секунду max "
              f"{data['max_new_conns'].get('redsms', 0)} (лимит REDSMS — 100/с с IP)")
        print(f"OkoCRM: успешных {st['okocrm_ok']}, 429 {st['okocrm_429']}, новых соединений в секунду max "
              f"{data['max_new_conns'].get('okocrm', 0)}")
        if samples:
            print(f"Мост: память max {max(s[0] for s in samples):.0f} МБ, CPU среднее "
                  f"{sum(s[1] for s in samples) / len(samples):.0f}% / max {max(s[1] for s in samples):.0f}%")
        print(f"Генератор опаздывал (p99): {pct([r['lag'] for r in results], 99) * 1000:.0f} мс")
        print(f"Лог моста: {log_path}")
        print("=" * 78)
    finally:
        stop_sampling.set()
        for proc in [bridge, *fakes]:
            proc.terminate()
        for proc in [bridge, *fakes]:
            proc.wait(10)


if __name__ == "__main__":
    main()
