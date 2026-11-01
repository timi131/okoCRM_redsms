from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .crypto import Cipher

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    setting_ulid    TEXT PRIMARY KEY,
    site_id         INTEGER,
    subdomain       TEXT,
    token           TEXT,             -- зашифрован (enc:…)
    login           TEXT,
    api_key         TEXT,             -- зашифрован (enc:…)
    senders         TEXT NOT NULL DEFAULT '[]',
    senders_rejected TEXT NOT NULL DEFAULT '[]', -- имена из настроек, не прошедшие проверку
    tg_cascade      INTEGER NOT NULL DEFAULT 0, -- коды сначала через Telegram, потом SMS
    limit_per_hour  INTEGER,          -- переопределение лимитов из настроек виджета; NULL — по умолчанию
    limit_per_phone_hour INTEGER,
    status          TEXT,            -- последний отправленный в OkoCRM статус: ok | error
    status_message  TEXT,
    installed_at    INTEGER,
    updated_at      INTEGER,
    deleted_at      INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY, -- message_id, который знает OkoCRM
    setting_ulid    TEXT NOT NULL,
    message_key     TEXT NOT NULL,
    phone           TEXT NOT NULL,    -- зашифрован (enc:…)
    phone_hash      TEXT,             -- HMAC номера для лимитов
    sender          TEXT NOT NULL,
    text            TEXT NOT NULL,    -- зашифрован; стирается после передачи в REDSMS (в нём бывают коды)
    text_hash       TEXT,             -- HMAC текста для защиты от дублей
    send_at         INTEGER,
    route           TEXT NOT NULL DEFAULT 'sms', -- sms | tgauth,sms
    state           TEXT NOT NULL,    -- queued | sending | submitted | final
    redsms_uuid     TEXT,             -- отслеживаемое сообщение REDSMS (в каскаде — текущий канал)
    root_uuid       TEXT,             -- первое сообщение каскада
    redsms_status   TEXT,
    oko_status      TEXT,             -- последний отправленный в OkoCRM sms.status
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    polled_at       INTEGER,
    UNIQUE (setting_ulid, message_key)
);
CREATE INDEX IF NOT EXISTS messages_uuid ON messages (redsms_uuid);
CREATE INDEX IF NOT EXISTS messages_state ON messages (state, created_at);
CREATE INDEX IF NOT EXISTS messages_rate ON messages (setting_ulid, created_at);

CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_ulid    TEXT NOT NULL,
    kind            TEXT NOT NULL,    -- events | status | senders
    payload         TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    not_before      REAL NOT NULL,
    created_at      INTEGER NOT NULL,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (not_before);
"""


class Store:
    """SQLite-хранилище. Отдельное соединение на поток, WAL — чтобы HTTP-потоки и воркеры не мешали друг другу."""

    def __init__(self, path: str, cipher: Cipher):
        self.path = path
        self.cipher = cipher
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        c = self.conn()
        c.executescript(SCHEMA)
        # Миграции для баз, созданных предыдущими версиями
        for table, column, ddl in MIGRATIONS:
            if column not in {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        c.execute("CREATE INDEX IF NOT EXISTS messages_root ON messages (root_uuid)")
        c.execute("DROP INDEX IF EXISTS messages_rate_phone")  # был по открытому номеру
        c.execute("CREATE INDEX IF NOT EXISTS messages_rate_phone_hash ON messages (setting_ulid, phone_hash, created_at)")
        self._encrypt_secrets()
        self._encrypt_messages()

    def _encrypt_messages(self) -> None:
        """Шифрует номера и тексты сообщений из старых версий; тексты уже отправленных — стирает."""
        c = self.conn()
        rows = c.execute("SELECT id, phone, text, state FROM messages WHERE phone NOT LIKE 'enc:%' "
                         "OR (text != '' AND text NOT LIKE 'enc:%')").fetchall()
        for r in rows:
            phone = self.cipher.decrypt(r["phone"])
            text = self.cipher.decrypt(r["text"])
            keep_text = r["state"] in ("queued", "sending")
            c.execute("UPDATE messages SET phone = ?, phone_hash = ?, text = ?, text_hash = ? WHERE id = ?",
                      (self.cipher.encrypt(phone), self.cipher.blind_index(phone),
                       self.cipher.encrypt(text) if keep_text else "", self.cipher.blind_index(text), r["id"]))

    def _msg(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        d["phone"] = self.cipher.decrypt(d["phone"])
        d["text"] = self.cipher.decrypt(d["text"])
        return d

    def _encrypt_secrets(self) -> None:
        """Шифрует открытые секреты из старых версий и перешифровывает текущим ключом после его смены."""
        c = self.conn()
        for row in c.execute("SELECT setting_ulid, token, api_key FROM connections").fetchall():
            c.execute("UPDATE connections SET token = ?, api_key = ? WHERE setting_ulid = ?",
                      (self.cipher.reencrypt(row["token"]), self.cipher.reencrypt(row["api_key"]), row["setting_ulid"]))

    def _decrypt(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        d["token"] = self.cipher.decrypt(d["token"])
        d["api_key"] = self.cipher.decrypt(d["api_key"])
        return d

    def ping(self) -> None:
        self.conn().execute("SELECT 1").fetchone()

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.conn = c
        return c

    # --- подключения -------------------------------------------------------

    def upsert_connection(self, ulid: str, site_id: int, subdomain: str, settings: Dict[str, Any],
                          token: Optional[str] = None) -> None:
        now = int(time.time())
        login = str(settings.get("login") or "").strip()
        api_key = str(settings.get("api_key") or "").strip()
        valid, rejected = split_senders(settings.get("senders"))
        senders, senders_rejected = json.dumps(valid), json.dumps(rejected, ensure_ascii=False)
        tg_cascade = 1 if _truthy(settings.get("telegram_codes")) else 0
        limit_hour = _optional_int(settings.get("limit_per_hour"))
        limit_phone = _optional_int(settings.get("limit_per_phone_hour"))
        c = self.conn()
        c.execute(
            """INSERT INTO connections (setting_ulid, site_id, subdomain, token, login, api_key, senders,
                                        senders_rejected, tg_cascade, limit_per_hour, limit_per_phone_hour,
                                        installed_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (setting_ulid) DO UPDATE SET
                   site_id = excluded.site_id, subdomain = excluded.subdomain,
                   token = COALESCE(excluded.token, connections.token),
                   login = excluded.login, api_key = excluded.api_key, senders = excluded.senders,
                   senders_rejected = excluded.senders_rejected, tg_cascade = excluded.tg_cascade,
                   limit_per_hour = excluded.limit_per_hour, limit_per_phone_hour = excluded.limit_per_phone_hour,
                   updated_at = excluded.updated_at, deleted_at = NULL""",
            (ulid, site_id, subdomain, self.cipher.encrypt(token), login, self.cipher.encrypt(api_key), senders,
             senders_rejected, tg_cascade, limit_hour, limit_phone, now, now),
        )
        if token:
            # Новый токен (установка или перевыпуск) — статус в OkoCRM надо прислать заново
            c.execute("UPDATE connections SET status = NULL, status_message = NULL WHERE setting_ulid = ?", (ulid,))

    def delete_connection(self, ulid: str) -> None:
        c = self.conn()
        c.execute("UPDATE connections SET token = NULL, api_key = NULL, deleted_at = ? WHERE setting_ulid = ?",
                  (int(time.time()), ulid))
        c.execute("DELETE FROM outbox WHERE setting_ulid = ?", (ulid,))

    def get_connection(self, ulid: str) -> Optional[Dict[str, Any]]:
        return self._decrypt(self.conn().execute(
            "SELECT * FROM connections WHERE setting_ulid = ? AND deleted_at IS NULL", (ulid,)).fetchone())

    def active_connections(self) -> List[Dict[str, Any]]:
        return [self._decrypt(r) for r in self.conn().execute(
            "SELECT * FROM connections WHERE deleted_at IS NULL AND token IS NOT NULL").fetchall()]

    def set_connection_status(self, ulid: str, status: str, message: Optional[str]) -> None:
        self.conn().execute("UPDATE connections SET status = ?, status_message = ? WHERE setting_ulid = ?",
                            (status, message, ulid))

    # --- сообщения ---------------------------------------------------------

    def insert_message(self, msg: Dict[str, Any]) -> str:
        """Вставляет сообщение; при повторе message_key возвращает id уже принятого."""
        now = int(time.time())
        c = self.conn()
        try:
            c.execute(
                """INSERT INTO messages (id, setting_ulid, message_key, phone, phone_hash, sender, text, text_hash,
                                         send_at, route, state, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                (msg["id"], msg["setting_ulid"], msg["message_key"],
                 self.cipher.encrypt(msg["phone"]), self.cipher.blind_index(msg["phone"]), msg["sender"],
                 self.cipher.encrypt(msg["text"]), self.cipher.blind_index(msg["text"]),
                 msg["send_at"], msg.get("route", "sms"), now, now),
            )
            return msg["id"]
        except sqlite3.IntegrityError:
            row = self.find_by_key(msg["setting_ulid"], msg["message_key"])
            if row is None:
                raise
            return row["id"]

    def find_by_key(self, ulid: str, message_key: str) -> Optional[Dict[str, Any]]:
        return self._msg(self.conn().execute("SELECT * FROM messages WHERE setting_ulid = ? AND message_key = ?",
                                             (ulid, message_key)).fetchone())

    def get_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        return self._msg(self.conn().execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone())

    def wipe_text(self, message_id: str) -> None:
        """Текст передан в REDSMS и больше не нужен — не держим коды подтверждения в БД."""
        self.conn().execute("UPDATE messages SET text = '' WHERE id = ?", (message_id,))

    def find_by_uuid(self, ulid: str, uuid: str) -> Optional[Dict[str, Any]]:
        """Сообщение по uuid REDSMS: текущему или первому в каскаде."""
        return self._msg(self.conn().execute(
            "SELECT * FROM messages WHERE setting_ulid = ? AND (redsms_uuid = ? OR root_uuid = ?)",
            (ulid, uuid, uuid)).fetchone())

    def count_recent(self, ulid: str, since: int, phone: Optional[str] = None, text: Optional[str] = None) -> int:
        """Сколько сообщений подключения принято с момента since; с phone/text — только на этот номер/с этим текстом.
        Сообщения, о неудаче которых уже сообщили в OkoCRM, не считаются: «Повторить» после ошибки не упирается в лимит."""
        sql = "SELECT COUNT(*) FROM messages WHERE setting_ulid = ? AND created_at >= ? AND COALESCE(oko_status, '') != 'failed'"
        args: List[Any] = [ulid, since]
        if phone is not None:
            sql += " AND phone_hash = ?"
            args.append(self.cipher.blind_index(phone))
        if text is not None:
            sql += " AND text_hash = ?"
            args.append(self.cipher.blind_index(text))
        return self.conn().execute(sql, args).fetchone()[0]

    def claim_for_sending(self, message_id: str) -> bool:
        cur = self.conn().execute(
            "UPDATE messages SET state = 'sending', updated_at = ? WHERE id = ? AND state = 'queued'",
            (int(time.time()), message_id))
        return cur.rowcount == 1

    def update_message(self, message_id: str, **fields: Any) -> None:
        unknown = set(fields) - UPDATABLE_MESSAGE_COLUMNS
        if unknown:
            raise ValueError(f"нельзя обновлять колонки {sorted(unknown)}")
        fields["updated_at"] = int(time.time())
        cols = ", ".join(f"{k} = ?" for k in fields)
        # Имена колонок — из белого списка выше, значения передаются параметрами
        self.conn().execute(f"UPDATE messages SET {cols} WHERE id = ?", (*fields.values(), message_id))  # nosec B608

    def advance_oko_status(self, message_id: str, new: str, blocked_from: List[str]) -> bool:
        """Атомарно ставит oko_status = new, если текущее значение не new и не входит в blocked_from.
        Защищает от двойной отправки статуса, когда колбэк и опрос приходят одновременно."""
        marks = ",".join("?" * len(blocked_from)) or "NULL"  # в запрос подставляются только «?»
        sql = ("UPDATE messages SET oko_status = ?, updated_at = ? WHERE id = ? "
               f"AND (oko_status IS NULL OR (oko_status != ? AND oko_status NOT IN ({marks})))")  # nosec B608
        cur = self.conn().execute(sql, (new, int(time.time()), message_id, new, *blocked_from))
        return cur.rowcount == 1

    def purge(self, older_than: int) -> Tuple[int, int]:
        """Удаляет завершённые сообщения и удалённые подключения старше older_than (unix-время)."""
        c = self.conn()
        m = c.execute("DELETE FROM messages WHERE created_at < ? AND state IN ('final', 'submitted')", (older_than,)).rowcount
        d = c.execute("DELETE FROM connections WHERE deleted_at IS NOT NULL AND deleted_at < ?", (older_than,)).rowcount
        return m, d

    def messages_in_state(self, state: str) -> List[Dict[str, Any]]:
        return [self._msg(r) for r in self.conn().execute("SELECT * FROM messages WHERE state = ?", (state,))]

    def messages_to_poll(self, older_than: int, newer_than: int, polled_before: int,
                         limit: int = 100) -> List[Dict[str, Any]]:
        return [self._msg(r) for r in self.conn().execute(
            """SELECT * FROM messages
               WHERE state = 'submitted' AND redsms_uuid IS NOT NULL
                 AND created_at < ? AND created_at > ?
                 AND COALESCE(send_at, 0) < ?
                 AND (polled_at IS NULL OR polled_at < ?)
               ORDER BY created_at LIMIT ?""",
            (older_than, newer_than, older_than, polled_before, limit))]

    # --- outbox (запросы к OkoCRM с повторами) -----------------------------

    def enqueue(self, ulid: str, kind: str, payload: Any, delay: float = 0.0) -> None:
        c = self.conn()
        if kind in ("status", "senders"):
            # Важно только последнее значение — старые неотправленные заменяем
            c.execute("DELETE FROM outbox WHERE setting_ulid = ? AND kind = ?", (ulid, kind))
        c.execute("INSERT INTO outbox (setting_ulid, kind, payload, not_before, created_at) VALUES (?, ?, ?, ?, ?)",
                  (ulid, kind, json.dumps(payload, ensure_ascii=False), time.time() + delay, int(time.time())))

    def due_outbox(self, limit: int = 50) -> List[sqlite3.Row]:
        return self.conn().execute("SELECT * FROM outbox WHERE not_before <= ? ORDER BY id LIMIT ?",
                                   (time.time(), limit)).fetchall()

    def outbox_exists(self, item_id: int) -> bool:
        return self.conn().execute("SELECT 1 FROM outbox WHERE id = ?", (item_id,)).fetchone() is not None

    def outbox_done(self, item_id: int) -> None:
        self.conn().execute("DELETE FROM outbox WHERE id = ?", (item_id,))

    def outbox_retry(self, item_id: int, delay: float, error: str) -> None:
        self.conn().execute(
            "UPDATE outbox SET attempts = attempts + 1, not_before = ?, last_error = ? WHERE id = ?",
            (time.time() + delay, error[:500], item_id))


# Что сервис меняет в сообщениях через update_message; phone/text — только через insert и wipe_text
UPDATABLE_MESSAGE_COLUMNS = {"state", "redsms_uuid", "root_uuid", "redsms_status", "oko_status", "polled_at",
                             "created_at"}

MIGRATIONS = [
    ("connections", "senders_rejected", "TEXT NOT NULL DEFAULT '[]'"),
    ("connections", "tg_cascade", "INTEGER NOT NULL DEFAULT 0"),
    ("connections", "limit_per_hour", "INTEGER"),
    ("connections", "limit_per_phone_hour", "INTEGER"),
    ("messages", "route", "TEXT NOT NULL DEFAULT 'sms'"),
    ("messages", "root_uuid", "TEXT"),
    ("messages", "phone_hash", "TEXT"),
    ("messages", "text_hash", "TEXT"),
]


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "да", "y")


def _optional_int(v: Any) -> Optional[int]:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


SENDER_ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._-")


def split_senders(raw: Any) -> Tuple[List[str], List[str]]:
    """Имена отправителей из поля настроек: через запятую, точку с запятой или с новой строки.
    Возвращает (подходящие, отклонённые). Подходящие — то, что примет PUT senders:
    1–15 символов A-Z a-z 0-9 пробел . _ -, без повторов, не больше 100."""
    if raw is None:
        return [], []
    if isinstance(raw, list):
        parts = [str(x) for x in raw]
    else:
        parts = str(raw).replace(";", ",").replace("\n", ",").split(",")
    valid: List[str] = []
    rejected: List[str] = []
    for p in parts:
        name = p.strip()
        if not name or name in valid:
            continue
        if len(name) <= 15 and set(name) <= SENDER_ALLOWED and len(valid) < 100:
            valid.append(name)
        else:
            rejected.append(name)
    return valid, rejected


def parse_senders(raw: Any) -> List[str]:
    return split_senders(raw)[0]
