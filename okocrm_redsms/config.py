from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

# Адреса, с которых REDSMS шлёт вебхуки (docs.redsms.ru/http/webhook/)
REDSMS_CALLBACK_IPS = ["37.9.15.244", "5.188.131.157", "5.188.131.158", "82.202.237.68"]


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


SECRETS = ("OKOCRM_WIDGET_PRIVATE_KEY", "APP_SECRET", "ENCRYPTION_KEY")


def _secret(name: str) -> str:
    """Секрет из NAME или из файла NAME_FILE (Docker/Kubernetes secrets) — тогда его не видно в docker inspect."""
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return os.environ.get(name, "")


def _list(name: str, default: List[str], value: Optional[str] = None) -> List[str]:
    v = os.environ.get(name) if value is None else value
    if v is None:
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


@dataclass
class Config:
    # Секретный ключ виджета: OkoStore → «Мои виджеты» → виджет → «Секретный ключ»
    widget_private_key: str
    # Секрет сервиса для подписи dlrUrl, которые мы отдаём REDSMS
    app_secret: str
    # Внешний https-адрес этого сервиса, например https://sms.example.com
    public_base_url: str
    db_path: str = "data/okocrm_redsms.sqlite3"
    # Внутри контейнера слушаем все интерфейсы; наружу публикуется только 127.0.0.1, см. docs/CONNECT.md
    listen_host: str = "0.0.0.0"  # nosec B104
    listen_port: int = 8080
    okocrm_api_base: str = "https://webhook.okocrm.com/v4/sms"
    redsms_api_base: str = "https://cp.redsms.ru/api"
    # Пустой список отключает проверку IP для колбэков REDSMS
    redsms_allowed_ips: List[str] = field(default_factory=lambda: list(REDSMS_CALLBACK_IPS))
    # Брать IP клиента из X-Forwarded-For (только если сервис стоит за своим reverse proxy)
    trust_x_forwarded_for: bool = False
    # Как часто перепроверять ключ и баланс REDSMS у всех подключений, сек
    healthcheck_interval: int = 600
    # Через сколько минут без колбэка опрашивать статус сообщения в REDSMS
    poll_after_minutes: int = 10
    # Сколько дней хранить завершённые сообщения и удалённые подключения; 0 — хранить всегда
    retention_days: int = 30
    # Ключи Fernet для шифрования секретов в БД; первый шифрует, остальные — для смены ключа
    encryption_keys: List[str] = field(default_factory=list)
    # Лимиты на одно подключение (0 — выключен). Клиент может переопределить часовые в настройках виджета
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    rate_limit_per_phone_hour: int = 10
    # Одинаковый текст на тот же номер чаще, чем раз в столько секунд, отклоняется (0 — не проверять)
    duplicate_window: int = 300
    # Сколько секунд ждать доставки кода в Telegram, прежде чем каскад отправит SMS (минимум 60)
    tg_validity: int = 180
    # Подписанный запрос OkoCRM старше стольких секунд (по полю time) отклоняется — защита от повтора; 0 — не проверять
    signature_max_age: int = 900
    # Сколько запросов обрабатывать одновременно; сверх — сразу 503
    max_concurrent_requests: int = 64

    @classmethod
    def from_env(cls) -> "Config":
        secrets = {n: _secret(n) for n in SECRETS}
        missing = [n for n, v in secrets.items() if not v] + ([] if os.environ.get("PUBLIC_BASE_URL") else ["PUBLIC_BASE_URL"])
        if missing:
            raise SystemExit("Не заданы переменные окружения: " + ", ".join(missing))
        if len(secrets["APP_SECRET"]) < 32:
            raise SystemExit("APP_SECRET короче 32 символов. Сгенерируйте: openssl rand -hex 32")
        cfg = cls(
            widget_private_key=secrets["OKOCRM_WIDGET_PRIVATE_KEY"],
            app_secret=secrets["APP_SECRET"],
            public_base_url=os.environ["PUBLIC_BASE_URL"].rstrip("/"),
            db_path=os.environ.get("DB_PATH", cls.db_path),
            listen_host=os.environ.get("LISTEN_HOST", cls.listen_host),
            listen_port=int(os.environ.get("LISTEN_PORT", cls.listen_port)),
            okocrm_api_base=os.environ.get("OKOCRM_API_BASE", cls.okocrm_api_base).rstrip("/"),
            redsms_api_base=os.environ.get("REDSMS_API_BASE", cls.redsms_api_base).rstrip("/"),
            redsms_allowed_ips=_list("REDSMS_ALLOWED_IPS", REDSMS_CALLBACK_IPS),
            trust_x_forwarded_for=_bool("TRUST_X_FORWARDED_FOR", False),
            healthcheck_interval=int(os.environ.get("HEALTHCHECK_INTERVAL", cls.healthcheck_interval)),
            poll_after_minutes=int(os.environ.get("POLL_AFTER_MINUTES", cls.poll_after_minutes)),
            retention_days=int(os.environ.get("RETENTION_DAYS", cls.retention_days)),
            encryption_keys=_list("ENCRYPTION_KEY", [], secrets["ENCRYPTION_KEY"]),
            rate_limit_per_minute=int(os.environ.get("RATE_LIMIT_PER_MINUTE", cls.rate_limit_per_minute)),
            rate_limit_per_hour=int(os.environ.get("RATE_LIMIT_PER_HOUR", cls.rate_limit_per_hour)),
            rate_limit_per_phone_hour=int(os.environ.get("RATE_LIMIT_PER_PHONE_HOUR", cls.rate_limit_per_phone_hour)),
            duplicate_window=int(os.environ.get("DUPLICATE_WINDOW", cls.duplicate_window)),
            tg_validity=int(os.environ.get("TG_VALIDITY", cls.tg_validity)),
            signature_max_age=int(os.environ.get("SIGNATURE_MAX_AGE", cls.signature_max_age)),
            max_concurrent_requests=int(os.environ.get("MAX_CONCURRENT_REQUESTS", cls.max_concurrent_requests)),
        )
        if not _bool("ALLOW_INSECURE_URLS", False):
            # Ключ API REDSMS и токены OkoCRM не должны уходить по открытому HTTP
            for name, url in (("PUBLIC_BASE_URL", cfg.public_base_url), ("OKOCRM_API_BASE", cfg.okocrm_api_base),
                              ("REDSMS_API_BASE", cfg.redsms_api_base)):
                if urlsplit(url).scheme != "https":
                    raise SystemExit(f"{name} должен начинаться с https:// (для локальной отладки: ALLOW_INSECURE_URLS=true)")
        return cfg
