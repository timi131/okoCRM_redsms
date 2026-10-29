from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any, Dict, Optional

from . import http_client
from .http_client import Response

# Статусы REDSMS, после которых сообщение больше не меняется (для SMS delivered тоже конечный)
PENDING_STATUSES = {"created", "moderation", "progress"}

# Конечные статусы-ошибки REDSMS → текст для менеджера в ленте OkoCRM
FAILED_STATUSES = {
    "reject": "Сообщение отклонено модератором REDSMS",
    "undelivered": "Сообщение не доставлено абоненту",
    "timeout": "Оператор не подтвердил доставку за отведённое время",
    "no_money": "Недостаточно средств на балансе REDSMS",
    "doubled": "REDSMS отклонил сообщение как дубликат (лимит на дубликаты в настройках REDSMS)",
    "limit_exceeded": "Превышен лимит отправки, заданный в настройках REDSMS",
    "bad_number": "Некорректный номер телефона получателя",
    "stop_list": "Номер получателя находится в стоп-листе REDSMS",
    "route_closed": "Направление закрыто для отправки в настройках REDSMS",
    "error": "Неизвестная ошибка REDSMS",
}


CASCADE_ROUTE = "tgauth,sms"
_CODE_WORD = re.compile(r"(код|code|парол|pin)", re.IGNORECASE)
_CODE = re.compile(r"(?<!\d)\d{4,8}(?!\d)")


def extract_code(text: str) -> Optional[str]:
    """Код подтверждения для Telegram Gateway, если текст похож на сообщение с кодом.

    Telegram Gateway REDSMS принимает только код из 4–8 цифр, поэтому берём текст, где есть слово
    «код»/«code»/«пароль»/«pin» и ровно одно число из 4–8 цифр. Иначе («Заказ 12345 готов»,
    «код 1234 действует до 2026 года») — None, и сообщение уходит обычной SMS.
    """
    if not _CODE_WORD.search(text):
        return None
    codes = set(_CODE.findall(text))
    return codes.pop() if len(codes) == 1 else None


def to_oko_status(redsms_status: str) -> Optional[Dict[str, Any]]:
    """Тело события sms.status (без message_id) или None, если сообщать пока нечего."""
    if redsms_status == "progress":
        return {"status": "sent"}
    if redsms_status == "delivered":
        return {"status": "delivered"}
    if redsms_status in ("read", "reply"):
        return {"status": "read"}
    if redsms_status in FAILED_STATUSES:
        return {"status": "failed", "error": {"code": redsms_status, "message": FAILED_STATUSES[redsms_status]}}
    return None


class RedsmsClient:
    """HTTP API REDSMS: https://docs.redsms.ru/http/"""

    def __init__(self, base_url: str, login: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.login = login
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        # secret = md5(ts + API_KEY); ts — произвольная строка, делаем её уникальной на каждый запрос
        ts = f"{time.time():.6f}-{uuid.uuid4().hex[:8]}"
        secret = hashlib.md5((ts + self.api_key).encode("utf-8")).hexdigest()
        return {"login": self.login, "ts": ts, "secret": secret, "Accept": "application/json"}

    def client_info(self) -> Response:
        # URL в REDSMS не должен заканчиваться на «/» — иначе 404
        return http_client.request("GET", f"{self.base_url}/client/info", self._headers(), timeout=self.timeout)

    def send_sms(self, to: str, text: str, sender: str, dlr_url: str, start_time: Optional[int] = None) -> Response:
        return self._send({"route": "sms", "from": sender, "to": to, "text": text, "dlrUrl": dlr_url}, start_time)

    def send_tg_then_sms(self, to: str, code: str, text: str, sender: str, dlr_url: str, tg_validity: int,
                         start_time: Optional[int] = None) -> Response:
        """Каскад: код через Telegram Gateway; если не доставлен за tg_validity секунд — SMS с полным текстом.
        В Telegram платят только за delivered/read, недоставка (нет аккаунта) бесплатна."""
        return self._send({
            "route": CASCADE_ROUTE, "to": to, "dlrUrl": dlr_url,
            "tgauth_text": code, "tgauth_validity": max(60, tg_validity),
            "sms_from": sender, "sms_text": text,
        }, start_time)

    def _send(self, body: Dict[str, Any], start_time: Optional[int]) -> Response:
        if start_time:
            body["startTime"] = start_time
        return http_client.request("POST", f"{self.base_url}/message", self._headers(), json_body=body,
                                   timeout=self.timeout)

    def get_message(self, message_uuid: str, fields: str = "uuid,status,status_time") -> Response:
        return http_client.request("GET", f"{self.base_url}/message/{message_uuid}?fields={fields}",
                                   self._headers(), timeout=self.timeout)
