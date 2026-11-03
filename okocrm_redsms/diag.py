"""Диагностика для технической поддержки: только чтение, секреты не выводятся.

    python -m okocrm_redsms diag --subdomain client-fravpa      подключение клиента + последние сообщения
    python -m okocrm_redsms diag --subdomain client-fravpa --check   + живая проверка ключа и баланса в REDSMS
    python -m okocrm_redsms diag --message rs-0bdb…              одно сообщение по message_id из OkoCRM
    python -m okocrm_redsms diag --uuid a3bf3b78-…               одно сообщение по uuid из кабинета REDSMS
    python -m okocrm_redsms diag --list                          все подключения

В контейнере: docker compose exec bridge python -m okocrm_redsms diag …
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .config import Config
from .crypto import Cipher
from .redsms import FAILED_STATUSES
from .service import Bridge, mask_phone
from .store import Store

MSK = timezone(timedelta(hours=3))


def _when(ts: Optional[float]) -> str:
    if not ts:
        return "—"
    utc = datetime.fromtimestamp(ts, timezone.utc)
    return f"{utc:%d.%m.%Y %H:%M:%S} UTC ({utc.astimezone(MSK):%H:%M} МСК)"


def _ago(ts: Optional[float]) -> str:
    if not ts:
        return ""
    s = int(time.time() - ts)
    if s < 0:
        return f" (через {-s // 60} мин)"
    if s < 3600:
        return f" ({s // 60} мин назад)"
    if s < 86400:
        return f" ({s // 3600} ч назад)"
    return f" ({s // 86400} дн назад)"


def _connections(store: Store, where: str, args: List[Any]) -> List[Dict[str, Any]]:
    rows = store.conn().execute(f"SELECT * FROM connections WHERE {where} ORDER BY updated_at DESC", args).fetchall()  # nosec B608
    return [dict(r) for r in rows]


def _print_connection(store: Store, c: Dict[str, Any], limit: int) -> None:
    print("=" * 78)
    print(f"Подключение  {c['subdomain']}  (site_id {c['site_id']}, setting_ulid {c['setting_ulid']})")
    print("=" * 78)
    if c["deleted_at"]:
        print(f"  УДАЛЕНО клиентом: {_when(c['deleted_at'])}{_ago(c['deleted_at'])} — виджет удалён, токен недействителен")
    print(f"  Установлено:          {_when(c['installed_at'])}")
    print(f"  Настройки изменены:   {_when(c['updated_at'])}{_ago(c['updated_at'])}")
    print(f"  Токен OkoCRM:         {'есть' if c['token'] else 'НЕТ'}")
    print(f"  Логин REDSMS:         {c['login'] or 'НЕ УКАЗАН'}")
    print(f"  Ключ API REDSMS:      {'указан' if c['api_key'] else 'НЕ УКАЗАН'}")
    senders = json.loads(c["senders"] or "[]")
    rejected = json.loads(c.get("senders_rejected") or "[]")
    print(f"  Имена отправителей:   {', '.join(senders) if senders else 'НЕТ'}")
    if rejected:
        print(f"  Отклонены проверкой:  {', '.join(rejected)}  (кириллица / длиннее 15 / недопустимые символы)")
    print(f"  Лимиты из виджета:    в час {c.get('limit_per_hour') if c.get('limit_per_hour') is not None else 'не задан'}, "
          f"на номер {c.get('limit_per_phone_hour') if c.get('limit_per_phone_hour') is not None else 'не задан'}")
    status = c["status"] or "ещё не отправлялся"
    print(f"  Статус в OkoCRM:      {status}{(' — ' + c['status_message']) if c['status_message'] else ''}")

    db = store.conn()
    now = int(time.time())
    hour = db.execute("SELECT COUNT(*) FROM messages WHERE setting_ulid = ? AND created_at >= ?",
                      (c["setting_ulid"], now - 3600)).fetchone()[0]
    day = db.execute("SELECT COUNT(*) FROM messages WHERE setting_ulid = ? AND created_at >= ?",
                     (c["setting_ulid"], now - 86400)).fetchone()[0]
    print(f"\n  Сообщений: за час {hour}, за сутки {day}")
    fails = db.execute(
        "SELECT redsms_status, COUNT(*) FROM messages WHERE setting_ulid = ? AND created_at >= ? AND oko_status = 'failed' "
        "GROUP BY redsms_status ORDER BY 2 DESC", (c["setting_ulid"], now - 86400)).fetchall()
    if fails:
        print("  Не доставлено за сутки:")
        for st, n in fails:
            print(f"    {n:>4} × {st}: {FAILED_STATUSES.get(st, 'ошибка на стороне интеграции или REDSMS API')}")

    out = db.execute("SELECT kind, attempts, not_before, last_error FROM outbox WHERE setting_ulid = ? ORDER BY id",
                     (c["setting_ulid"],)).fetchall()
    if out:
        print(f"\n  Очередь в OkoCRM: {len(out)} (не доставлено в OkoCRM — статусы/отправители/состояние)")
        for kind, attempts, nb, err in out[:10]:
            print(f"    {kind:<8} попыток {attempts}, следующая {_when(nb)}{_ago(nb)}; ошибка: {err or '—'}")
    else:
        print("\n  Очередь в OkoCRM: пусто (всё доставлено)")

    msgs = db.execute("SELECT * FROM messages WHERE setting_ulid = ? ORDER BY created_at DESC LIMIT ?",
                      (c["setting_ulid"], limit)).fetchall()
    print(f"\n  Последние сообщения ({len(msgs)}):")
    for r in msgs:
        m = store._msg(r)
        print(f"    {_when(m['created_at'])}  {m['id']}")
        print(f"        номер {mask_phone(m['phone'])}, отправитель {m['sender']}, канал {m['route']}, "
              f"REDSMS {m['redsms_status'] or '—'}, в OkoCRM {m['oko_status'] or '—'}, состояние {m['state']}")
        if m["redsms_uuid"]:
            print(f"        uuid в кабинете REDSMS: {m['redsms_uuid']}")


def _print_message(store: Store, m: Dict[str, Any]) -> None:
    print("=" * 78)
    print(f"Сообщение {m['id']}")
    print("=" * 78)
    print(f"  Создано:            {_when(m['created_at'])}{_ago(m['created_at'])}")
    print(f"  Обновлено:          {_when(m['updated_at'])}")
    if m["send_at"]:
        print(f"  Отложено до:        {_when(m['send_at'])}")
    print(f"  Номер:              {mask_phone(m['phone'])}")
    print(f"  Отправитель:        {m['sender']}, канал {m['route']}")
    print(f"  Состояние:          {m['state']}  (queued — в очереди, sending — отправляется, submitted — у REDSMS, final — завершено)")
    print(f"  uuid в REDSMS:      {m['redsms_uuid'] or '— (до REDSMS не дошло)'}")
    if m.get("root_uuid") and m["root_uuid"] != m["redsms_uuid"]:
        print(f"  Первый шаг каскада: {m['root_uuid']}")
    st = m["redsms_status"]
    print(f"  Статус REDSMS:      {st or '—'}{(' — ' + FAILED_STATUSES[st]) if st in FAILED_STATUSES else ''}")
    print(f"  Статус в OkoCRM:    {m['oko_status'] or '— (ещё не отправлялся)'}")
    print(f"  Последний опрос:    {_when(m['polled_at'])}")
    print(f"  Текст:              {'стёрт после передачи в REDSMS' if not m['text'] else 'ещё в очереди'}")
    conns = _connections(store, "setting_ulid = ?", [m["setting_ulid"]])
    if conns:
        c = conns[0]
        print(f"  Подключение:        {c['subdomain']} (setting_ulid {c['setting_ulid']}), статус {c['status']}")


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(prog="python -m okocrm_redsms diag", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--subdomain", help="поддомен аккаунта OkoCRM, например client-fravpa")
    g.add_argument("--ulid", help="setting_ulid подключения")
    g.add_argument("--message", help="message_id сообщения (rs-…), как его знает OkoCRM")
    g.add_argument("--uuid", help="uuid сообщения из кабинета REDSMS")
    g.add_argument("--list", action="store_true", help="все подключения")
    p.add_argument("--limit", type=int, default=20, help="сколько последних сообщений показать (20)")
    p.add_argument("--check", action="store_true", help="проверить сейчас логин, ключ и баланс в REDSMS")
    a = p.parse_args(argv)

    cfg = Config.from_env()
    store = Store(cfg.db_path, Cipher(cfg.encryption_keys), migrate=False)

    if a.list:
        rows = _connections(store, "1 = 1", [])
        print(f"{'поддомен':<24} {'статус':<8} {'удалено':<8} {'изменено':<20} setting_ulid")
        for c in rows:
            print(f"{(c['subdomain'] or '—'):<24} {(c['status'] or '—'):<8} {('да' if c['deleted_at'] else ''):<8} "
                  f"{datetime.fromtimestamp(c['updated_at'] or 0, MSK):%d.%m %H:%M МСК}   {c['setting_ulid']}")
        return 0

    if a.message or a.uuid:
        row = (store.get_message(a.message) if a.message else
               store._msg(store.conn().execute("SELECT * FROM messages WHERE redsms_uuid = ? OR root_uuid = ?",
                                                (a.uuid, a.uuid)).fetchone()))
        if row is None:
            print("Сообщение не найдено. Возможные причины: удалено по сроку хранения (RETENTION_DAYS), "
                  "OkoCRM не дошёл до интеграции, или это сообщение отправлено не через интеграцию.")
            return 1
        _print_message(store, row)
        return 0

    conns = (_connections(store, "subdomain = ?", [a.subdomain]) if a.subdomain
             else _connections(store, "setting_ulid = ?", [a.ulid]))
    if not conns:
        print("Подключение не найдено. Клиент не устанавливал виджет, не сохранял настройки, "
              "или OkoCRM не смог доставить событие installed (проверьте доступность интеграции).")
        return 1
    for c in conns:
        _print_connection(store, c, a.limit)
        if a.check:
            full = store.get_connection(c["setting_ulid"])
            if full is None:
                print("\n  Проверка REDSMS: подключение удалено — проверять нечего")
                continue
            status, message = Bridge(cfg, store)._evaluate(full)
            if status is None:
                print("\n  Проверка REDSMS сейчас: REDSMS API не ответил — сеть или REDSMS недоступны")
            else:
                print(f"\n  Проверка REDSMS сейчас: {status}{(' — ' + message) if message else ' — логин, ключ и баланс в порядке'}")
    return 0
