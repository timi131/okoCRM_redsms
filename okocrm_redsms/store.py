from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    setting_ulid    TEXT PRIMARY KEY,
    site_id         INTEGER,
    subdomain       TEXT,
    token           TEXT,
    login           TEXT,
    api_key         TEXT,
    senders         TEXT NOT NULL DEFAULT '[]',
    senders_rejected TEXT NOT NULL DEFAULT '[]', -- имена из настроек, не прошедшие проверку
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
    phone           TEXT NOT NULL,
    sender          TEXT NOT NULL,
    text            TEXT NOT NULL,
    send_at         INTEGER,
    state           TEXT NOT NULL,    -- queued | sending | submitted | final
    redsms_uuid     TEXT,
    redsms_status   TEXT,
    oko_status      TEXT,             -- последний отправленный в OkoCRM sms.status
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    polled_at       INTEGER,
    UNIQUE (setting_ulid, message_key)
);
CREATE INDEX IF NOT EXISTS messages_uuid ON messages (redsms_uuid);
CREATE INDEX IF NOT EXISTS messages_state ON messages (state, created_at);

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

    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        c = self.conn()
        c.executescript(SCHEMA)
        # Миграции для баз, созданных предыдущими версиями
        cols = {r["name"] for r in c.execute("PRAGMA table_info(connections)")}
        if "senders_rejected" not in cols:
            c.execute("ALTER TABLE connections ADD COLUMN senders_rejected TEXT NOT NULL DEFAULT '[]'")

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
        c = self.conn()
        c.execute(
            """INSERT INTO connections (setting_ulid, site_id, subdomain, token, login, api_key, senders,
                                        senders_rejected, installed_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (setting_ulid) DO UPDATE SET
                   site_id = excluded.site_id, subdomain = excluded.subdomain,
                   token = COALESCE(excluded.token, connections.token),
                   login = excluded.login, api_key = excluded.api_key, senders = excluded.senders,
                   senders_rejected = excluded.senders_rejected,
                   updated_at = excluded.updated_at, deleted_at = NULL""",
            (ulid, site_id, subdomain, token, login, api_key, senders, senders_rejected, now, now),
        )
        if token:
            # Новый токен (установка или перевыпуск) — статус в OkoCRM надо прислать заново
            c.execute("UPDATE connections SET status = NULL, status_message = NULL WHERE setting_ulid = ?", (ulid,))

    def delete_connection(self, ulid: str) -> None:
        c = self.conn()
        c.execute("UPDATE connections SET token = NULL, api_key = NULL, deleted_at = ? WHERE setting_ulid = ?",
                  (int(time.time()), ulid))
        c.execute("DELETE FROM outbox WHERE setting_ulid = ?", (ulid,))

    def get_connection(self, ulid: str) -> Optional[sqlite3.Row]:
        return self.conn().execute(
            "SELECT * FROM connections WHERE setting_ulid = ? AND deleted_at IS NULL", (ulid,)).fetchone()

    def active_connections(self) -> List[sqlite3.Row]:
        return self.conn().execute(
            "SELECT * FROM connections WHERE deleted_at IS NULL AND token IS NOT NULL").fetchall()

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
                """INSERT INTO messages (id, setting_ulid, message_key, phone, sender, text, send_at, state,
                                         created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                (msg["id"], msg["setting_ulid"], msg["message_key"], msg["phone"], msg["sender"], msg["text"],
                 msg["send_at"], now, now),
            )
            return msg["id"]
        except sqlite3.IntegrityError:
            row = self.find_by_key(msg["setting_ulid"], msg["message_key"])
            if row is None:
                raise
            return row["id"]

    def find_by_key(self, ulid: str, message_key: str) -> Optional[sqlite3.Row]:
        return self.conn().execute("SELECT * FROM messages WHERE setting_ulid = ? AND message_key = ?",
                                   (ulid, message_key)).fetchone()

    def get_message(self, message_id: str) -> Optional[sqlite3.Row]:
        return self.conn().execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()

    def find_by_uuid(self, ulid: str, uuid: str) -> Optional[sqlite3.Row]:
        return self.conn().execute("SELECT * FROM messages WHERE setting_ulid = ? AND redsms_uuid = ?",
                                   (ulid, uuid)).fetchone()

    def claim_for_sending(self, message_id: str) -> bool:
        cur = self.conn().execute(
            "UPDATE messages SET state = 'sending', updated_at = ? WHERE id = ? AND state = 'queued'",
            (int(time.time()), message_id))
        return cur.rowcount == 1

    def update_message(self, message_id: str, **fields: Any) -> None:
        fields["updated_at"] = int(time.time())
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.conn().execute(f"UPDATE messages SET {cols} WHERE id = ?", (*fields.values(), message_id))

    def advance_oko_status(self, message_id: str, new: str, blocked_from: List[str]) -> bool:
        """Атомарно ставит oko_status = new, если текущее значение не new и не входит в blocked_from.
        Защищает от двойной отправки статуса, когда колбэк и опрос приходят одновременно."""
        marks = ",".join("?" * len(blocked_from)) or "NULL"
        cur = self.conn().execute(
            f"""UPDATE messages SET oko_status = ?, updated_at = ?
                WHERE id = ? AND (oko_status IS NULL OR (oko_status != ? AND oko_status NOT IN ({marks})))""",
            (new, int(time.time()), message_id, new, *blocked_from))
        return cur.rowcount == 1

    def purge(self, older_than: int) -> Tuple[int, int]:
        """Удаляет завершённые сообщения и удалённые подключения старше older_than (unix-время)."""
        c = self.conn()
        m = c.execute("DELETE FROM messages WHERE created_at < ? AND state IN ('final', 'submitted')", (older_than,)).rowcount
        d = c.execute("DELETE FROM connections WHERE deleted_at IS NOT NULL AND deleted_at < ?", (older_than,)).rowcount
        return m, d

    def messages_in_state(self, state: str) -> List[sqlite3.Row]:
        return self.conn().execute("SELECT * FROM messages WHERE state = ?", (state,)).fetchall()

    def messages_to_poll(self, older_than: int, newer_than: int, polled_before: int, limit: int = 100) -> List[sqlite3.Row]:
        return self.conn().execute(
            """SELECT * FROM messages
               WHERE state = 'submitted' AND redsms_uuid IS NOT NULL
                 AND created_at < ? AND created_at > ?
                 AND COALESCE(send_at, 0) < ?
                 AND (polled_at IS NULL OR polled_at < ?)
               ORDER BY created_at LIMIT ?""",
            (older_than, newer_than, older_than, polled_before, limit)).fetchall()

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

    def outbox_done(self, item_id: int) -> None:
        self.conn().execute("DELETE FROM outbox WHERE id = ?", (item_id,))

    def outbox_retry(self, item_id: int, delay: float, error: str) -> None:
        self.conn().execute(
            "UPDATE outbox SET attempts = attempts + 1, not_before = ?, last_error = ? WHERE id = ?",
            (time.time() + delay, error[:500], item_id))


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
