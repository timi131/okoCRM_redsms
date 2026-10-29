from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, Tuple

from . import http_client
from .config import Config
from .redsms import PENDING_STATUSES, RedsmsClient, to_oko_status
from .store import Store

log = logging.getLogger("okocrm_redsms")

MAX_START_AHEAD = 7 * 86400 - 300  # REDSMS: startTime не позднее 7 дней
STATUS_DELAY = 2.0                 # OkoCRM: статус не раньше, чем через 1–2 с после ответа на sms.send
OUTBOX_GIVE_UP = 24 * 3600
SEND_RETRIES = 3

STATUS_RANK = {"sent": 1, "delivered": 2, "read": 3, "failed": 0}


class SendError(Exception):
    """Отказ на sms.send: HTTP-код и тело {"error": {...}} для OkoCRM."""

    def __init__(self, http_status: int, code: str, message: str):
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message


def verify_signature(private_key: str, body: bytes, signature: str) -> bool:
    expected = hmac.new(private_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, (signature or "").strip().lower())


class Bridge:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="bridge")
        self._stop = threading.Event()
        self._outbox_wakeup = threading.Event()
        self._threads = []

    # ------------------------------------------------------------------
    # Вебхуки OkoCRM: installed / settings_updated / uninstalled
    # ------------------------------------------------------------------

    def handle_okocrm_event(self, event: Dict[str, Any]) -> None:
        name = event.get("event")
        ulid = str(event.get("setting_ulid") or "")
        if not ulid:
            raise ValueError("нет setting_ulid")
        if name == "installed":
            self.store.upsert_connection(ulid, event.get("site_id"), event.get("subdomain"),
                                         _settings(event), token=event.get("token"))
            log.info("installed: %s (%s)", ulid, event.get("subdomain"))
            self.pool.submit(self._safe, self.sync_connection, ulid)
        elif name == "settings_updated":
            self.store.upsert_connection(ulid, event.get("site_id"), event.get("subdomain"), _settings(event))
            log.info("settings_updated: %s", ulid)
            self.pool.submit(self._safe, self.sync_connection, ulid)
        elif name == "uninstalled":
            self.store.delete_connection(ulid)
            log.info("uninstalled: %s", ulid)
        else:
            log.warning("неизвестное событие %r", name)

    def sync_connection(self, ulid: str) -> None:
        """Отправить в OkoCRM список отправителей и проверить ключ/баланс REDSMS."""
        conn = self.store.get_connection(ulid)
        if conn is None or not conn["token"]:
            return
        senders = json.loads(conn["senders"])
        if senders:
            self._enqueue(ulid, "senders", [{"name": s} for s in senders])
        rejected = json.loads(conn["senders_rejected"] or "[]")
        if rejected:
            log.warning("%s: имена отправителей отклонены проверкой: %s", ulid, rejected)
        self.check_health(ulid)

    def check_health(self, ulid: str) -> None:
        conn = self.store.get_connection(ulid)
        if conn is None or not conn["token"]:
            return
        status, message = self._evaluate(conn)
        if status is None:
            return  # REDSMS недоступен — состояние не меняем
        if status == conn["status"] and message == conn["status_message"]:
            return  # каждое переключение ok → error шлёт письмо администратору — не дёргаем зря
        self.store.set_connection_status(ulid, status, message)
        payload: Dict[str, Any] = {"status": status}
        if status == "error":
            payload["message"] = message
        log.info("status %s → %s %s", ulid, status, message or "")
        self._enqueue(ulid, "status", payload)

    def _evaluate(self, conn) -> Tuple[Optional[str], Optional[str]]:
        if not conn["login"] or not conn["api_key"]:
            return "error", "Укажите логин и ключ API REDSMS в настройках виджета"
        if not json.loads(conn["senders"]):
            rejected = json.loads(conn["senders_rejected"] or "[]")
            hint = f" Не подошли: {', '.join(rejected[:5])}." if rejected else ""
            return "error", ("Укажите хотя бы одно имя отправителя, зарегистрированное в REDSMS "
                             "(латиница, цифры, пробел . _ -, до 15 символов)." + hint)
        try:
            r = self._redsms(conn).client_info()
        except http_client.TransportError as e:
            log.warning("REDSMS client/info %s: %s", conn["setting_ulid"], e)
            return None, None
        if r.status == 401:
            return "error", ("REDSMS отклонил авторизацию: проверьте логин и ключ API, "
                             "а также белый список IP в настройках HTTP API REDSMS")
        if r.status != 200:
            log.warning("REDSMS client/info %s: HTTP %s %s", conn["setting_ulid"], r.status, r.body[:200])
            return None, None
        info = (r.json() or {}).get("info") or {}
        if info.get("active") is False:
            return "error", "Аккаунт REDSMS не активирован: нужен подтверждённый договор"
        balance = float(info.get("balance") or 0) + float(info.get("overdraft") or 0)
        if balance <= 0:
            return "error", "Закончился баланс в кабинете REDSMS"
        return "ok", None

    # ------------------------------------------------------------------
    # sms.send — отвечаем за 4 секунды, отправка в REDSMS — в фоне
    # ------------------------------------------------------------------

    def handle_send(self, req: Dict[str, Any]) -> str:
        ulid = str(req.get("setting_ulid") or "")
        key = str(req.get("message_key") or "")
        if not ulid or not key:
            raise SendError(422, "bad_request", "Некорректный запрос: нет setting_ulid или message_key")

        existing = self.store.find_by_key(ulid, key)
        if existing is not None:
            return existing["id"]

        conn = self.store.get_connection(ulid)
        if conn is None or not conn["token"]:
            raise SendError(409, "not_connected", "Подключение REDSMS не найдено: пересохраните настройки виджета")
        if not conn["login"] or not conn["api_key"]:
            raise SendError(409, "no_credentials", "Укажите логин и ключ API REDSMS в настройках виджета")

        phone = str(req.get("phone") or "").strip()
        text = str(req.get("text") or "")
        sender = str(req.get("sender") or "").strip()
        digits = sum(ch.isdigit() for ch in phone)
        if not 10 <= digits <= 15:
            raise SendError(422, "bad_number", f"Некорректный номер получателя: {phone or 'не указан'}"[:255])
        if not text.strip():
            raise SendError(422, "empty_text", "Пустой текст SMS")
        if not sender:
            senders = json.loads(conn["senders"])
            sender = senders[0] if senders else ""
        send_at = req.get("send_at")
        if send_at is not None:
            send_at = int(send_at)
            if send_at - time.time() > MAX_START_AHEAD:
                raise SendError(422, "send_at_too_far",
                                "REDSMS принимает отложенную отправку не более чем на 7 дней вперёд")

        message_id = self.store.insert_message({
            "id": "rs-" + uuid.uuid4().hex,
            "setting_ulid": ulid,
            "message_key": key,
            "phone": phone,
            "sender": sender,
            "text": text,
            "send_at": send_at,
        })
        self.pool.submit(self._safe, self.submit_message, message_id)
        return message_id

    def submit_message(self, message_id: str) -> None:
        if not self.store.claim_for_sending(message_id):
            return
        msg = self.store.get_message(message_id)
        conn = self.store.get_connection(msg["setting_ulid"])
        if conn is None or not conn["api_key"]:
            self._fail(msg, "not_connected", "Подключение REDSMS удалено до отправки сообщения")
            return

        start_time = msg["send_at"] if msg["send_at"] and msg["send_at"] > time.time() + 60 else None
        dlr_url = self.dlr_url(msg["setting_ulid"])
        client = self._redsms(conn)

        r = None
        for attempt in range(SEND_RETRIES):
            try:
                r = client.send_sms(_normalize_phone(msg["phone"]), msg["text"], msg["sender"], dlr_url, start_time)
                break
            except http_client.TransportError as e:
                if e.not_sent and attempt + 1 < SEND_RETRIES:
                    time.sleep(1 + attempt * 2)
                    continue
                log.warning("REDSMS send %s: %s", message_id, e)
                if e.not_sent:
                    self._fail(msg, "gateway_unavailable", "REDSMS недоступен, сообщение не отправлено. Повторите позже")
                else:
                    # Запрос мог дойти — повтор вслепую рискует задвоить SMS
                    self._fail(msg, "gateway_timeout", "REDSMS не ответил вовремя. Проверьте сообщение "
                                                       "в кабинете REDSMS, прежде чем повторять отправку")
                return

        data = r.json() or {}
        items = data.get("items") or []
        if r.status == 200 and items and items[0].get("uuid"):
            item = items[0]
            status = item.get("status") or "created"
            self.store.update_message(message_id, state="submitted", redsms_uuid=item["uuid"], redsms_status=status)
            log.info("submitted %s → REDSMS %s (%s)", message_id, item["uuid"], status)
            if status not in PENDING_STATUSES:
                self.apply_redsms_status(self.store.get_message(message_id), status)
            elif not start_time:
                # Шлюз принял сообщение в отправку — одна галка в ленте
                self._push_status(self.store.get_message(message_id), {"status": "sent"})
            return

        reason = _redsms_error_text(data)
        log.warning("REDSMS send %s: HTTP %s %s", message_id, r.status, r.body[:300])
        if r.status == 401:
            self._fail(msg, "unauthorized", "REDSMS отклонил авторизацию: проверьте логин и ключ API")
            self.pool.submit(self._safe, self.check_health, msg["setting_ulid"])
        elif r.status == 420:
            self._fail(msg, "no_money", "Недостаточно средств на балансе REDSMS")
            self.pool.submit(self._safe, self.check_health, msg["setting_ulid"])
        elif r.status == 400:
            self._fail(msg, "rejected", "REDSMS отклонил сообщение" + (f": {reason}" if reason else ""))
        else:
            self._fail(msg, f"http_{r.status}", "Ошибка REDSMS" + (f": {reason}" if reason else f" (HTTP {r.status})"))

    def _fail(self, msg, code: str, message: str) -> None:
        self.store.update_message(msg["id"], state="final", redsms_status=msg["redsms_status"] or "error")
        self._push_status(self.store.get_message(msg["id"]),
                          {"status": "failed", "error": {"code": code, "message": message[:255]}})

    # ------------------------------------------------------------------
    # Статусы из REDSMS: колбэк dlrUrl и опрос
    # ------------------------------------------------------------------

    def dlr_url(self, ulid: str) -> str:
        return f"{self.cfg.public_base_url}/redsms/dlr/{ulid}/{self._dlr_sig(ulid)}"

    def _dlr_sig(self, ulid: str) -> str:
        return hmac.new(self.cfg.app_secret.encode(), ("dlr:" + ulid).encode(), hashlib.sha256).hexdigest()[:32]

    def verify_dlr(self, ulid: str, sig: str) -> bool:
        return hmac.compare_digest(self._dlr_sig(ulid), sig)

    def handle_dlr(self, ulid: str, data: Dict[str, Any]) -> None:
        message_uuid = str(data.get("uuid") or "")
        status = str(data.get("status") or "")
        if not message_uuid or not status:
            return
        msg = self.store.find_by_uuid(ulid, message_uuid)
        if msg is None:
            log.info("DLR для неизвестного сообщения %s / %s", ulid, message_uuid)
            return
        self.apply_redsms_status(msg, status)

    def apply_redsms_status(self, msg, status: str) -> None:
        fields: Dict[str, Any] = {"redsms_status": status}
        if status not in PENDING_STATUSES:
            fields["state"] = "final"
        self.store.update_message(msg["id"], **fields)
        event = to_oko_status(status)
        if event:
            self._push_status(self.store.get_message(msg["id"]), event)
        if status == "no_money":
            self.pool.submit(self._safe, self.check_health, msg["setting_ulid"])

    def _push_status(self, msg, event: Dict[str, Any]) -> None:
        new = event["status"]
        # OkoCRM сам игнорирует понижения, но лишние запросы не шлём: после delivered/read — только повышение
        blocked = [s for s in ("delivered", "read") if STATUS_RANK[new] <= STATUS_RANK[s]]
        if not self.store.advance_oko_status(msg["id"], new, blocked):
            return
        payload = {"event": "sms.status", "message_id": msg["id"], "time": int(time.time()), **event}
        delay = max(0.0, msg["created_at"] + STATUS_DELAY - time.time())
        self._enqueue(msg["setting_ulid"], "events", payload, delay)

    def poll_stale_messages(self) -> None:
        now = int(time.time())
        rows = self.store.messages_to_poll(older_than=now - self.cfg.poll_after_minutes * 60,
                                           newer_than=now - 3 * 86400,
                                           polled_before=now - self.cfg.poll_after_minutes * 60)
        for msg in rows:
            self.store.update_message(msg["id"], polled_at=now)
            conn = self.store.get_connection(msg["setting_ulid"])
            if conn is None or not conn["api_key"]:
                self.store.update_message(msg["id"], state="final")
                continue
            try:
                r = self._redsms(conn).get_message(msg["redsms_uuid"])
            except http_client.TransportError as e:
                log.warning("REDSMS poll %s: %s", msg["id"], e)
                continue
            item = (r.json() or {}).get("item") or {}
            if r.status == 200 and item.get("status") and item["status"] != msg["redsms_status"]:
                self.apply_redsms_status(msg, item["status"])

    # ------------------------------------------------------------------
    # Outbox: доставка запросов в OkoCRM с повторами
    # ------------------------------------------------------------------

    def _enqueue(self, ulid: str, kind: str, payload: Any, delay: float = 0.0) -> None:
        self.store.enqueue(ulid, kind, payload, delay)
        self._outbox_wakeup.set()

    def flush_outbox(self) -> None:
        for item in self.store.due_outbox():
            conn = self.store.get_connection(item["setting_ulid"])
            if conn is None or not conn["token"]:
                self.store.outbox_done(item["id"])
                continue
            method, path = {"events": ("POST", "/events"), "status": ("POST", "/status"),
                            "senders": ("PUT", "/senders")}[item["kind"]]
            headers = {"Authorization": f"Bearer {conn['token']}", "Accept": "application/json"}
            try:
                r = http_client.request(method, self.cfg.okocrm_api_base + path, headers,
                                        json_body=json.loads(item["payload"]), timeout=10)
            except http_client.TransportError as e:
                self._retry(item, _backoff(item["attempts"]), str(e))
                continue
            if 200 <= r.status < 300:
                self.store.outbox_done(item["id"])
            elif r.status == 429:
                self._retry(item, float(r.headers.get("retry-after") or 5), "429")
            elif r.status in (409, 402) or r.status >= 500:
                # 409 — клиент ещё не сохранил настройки / параллельный запрос; 402 — не оплачен тариф
                delay = 600 if r.status == 402 else _backoff(item["attempts"])
                self._retry(item, delay, f"HTTP {r.status} {r.body[:200]!r}")
            else:
                # 401/404 — токен отозван, 422 — невалидное тело: повтор не поможет
                log.error("OkoCRM %s %s → HTTP %s %s", method, path, r.status, r.body[:300])
                self.store.outbox_done(item["id"])

    def _retry(self, item, delay: float, error: str) -> None:
        if time.time() - item["created_at"] > OUTBOX_GIVE_UP:
            log.error("OkoCRM: бросаем %s для %s после суток попыток: %s", item["kind"], item["setting_ulid"], error)
            self.store.outbox_done(item["id"])
        else:
            self.store.outbox_retry(item["id"], delay, error)

    # ------------------------------------------------------------------
    # Фоновые потоки
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.recover()
        for target in (self._outbox_loop, self._maintenance_loop):
            t = threading.Thread(target=target, daemon=True, name=target.__name__)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        self._outbox_wakeup.set()
        self.pool.shutdown(wait=True)

    def recover(self) -> None:
        """После перезапуска: queued — отправить, sending — результат неизвестен, повторять нельзя."""
        for msg in self.store.messages_in_state("sending"):
            self._fail(msg, "interrupted", "Отправка прервана перезапуском интеграции. Проверьте сообщение "
                                           "в кабинете REDSMS, прежде чем повторять")
        for msg in self.store.messages_in_state("queued"):
            self.pool.submit(self._safe, self.submit_message, msg["id"])

    def _outbox_loop(self) -> None:
        while not self._stop.is_set():
            self._safe(self.flush_outbox)
            self._outbox_wakeup.wait(1.0)
            self._outbox_wakeup.clear()

    def _maintenance_loop(self) -> None:
        last_health = last_purge = 0.0
        while not self._stop.wait(30):
            self._safe(self.poll_stale_messages)
            if time.time() - last_health >= self.cfg.healthcheck_interval:
                last_health = time.time()
                # Параллельно: у каждого подключения запрос в REDSMS до 10 с
                for conn in self.store.active_connections():
                    self.pool.submit(self._safe, self.check_health, conn["setting_ulid"])
            if time.time() - last_purge >= 3600:
                last_purge = time.time()
                self._safe(self.purge)

    def purge(self) -> None:
        if self.cfg.retention_days <= 0:
            return
        messages, connections = self.store.purge(int(time.time()) - self.cfg.retention_days * 86400)
        if messages or connections:
            log.info("очистка: удалено сообщений %s, подключений %s", messages, connections)

    def _redsms(self, conn) -> RedsmsClient:
        return RedsmsClient(self.cfg.redsms_api_base, conn["login"], conn["api_key"])

    @staticmethod
    def _safe(fn, *args) -> None:
        try:
            fn(*args)
        except Exception:  # noqa: BLE001 — фоновая задача не должна ронять поток
            log.exception("ошибка в %s", getattr(fn, "__name__", fn))


def _settings(event: Dict[str, Any]) -> Dict[str, Any]:
    s = event.get("settings")
    return s if isinstance(s, dict) else {}  # без полей OkoCRM присылает пустой массив


def _normalize_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) == 11 and digits[0] == "8":
        digits = "7" + digits[1:]
    elif len(digits) == 10 and digits[0] == "9":
        digits = "7" + digits
    return "+" + digits


def _redsms_error_text(data: Dict[str, Any]) -> str:
    errors = data.get("errors") or []
    if errors and isinstance(errors[0], dict) and errors[0].get("message"):
        return str(errors[0]["message"])
    return str(data.get("error_message") or "")


def _backoff(attempts: int) -> float:
    return float(min(600, 5 * 2 ** attempts))
