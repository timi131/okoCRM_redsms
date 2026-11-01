from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit


@dataclass
class Response:
    status: int
    body: bytes
    headers: Dict[str, str]

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8")) if self.body else None
        except ValueError:
            return None


class TransportError(Exception):
    """Ответа нет. not_sent=True — запрос точно не дошёл до сервера и его безопасно повторить."""

    def __init__(self, message: str, not_sent: bool):
        super().__init__(message)
        self.not_sent = not_sent


# Постоянные соединения: по одному на поток и хост. У REDSMS лимит 100 новых подключений в секунду с IP,
# а TLS-рукопожатие на каждый запрос при 100 SMS/с — лишние сотни миллисекунд и CPU.
IDLE_TIMEOUT = 20.0
_ssl_context = ssl.create_default_context()
_local = threading.local()


def _pool() -> Dict[Tuple[str, str, int], Tuple[http.client.HTTPConnection, float]]:
    p = getattr(_local, "pool", None)
    if p is None:
        p = _local.pool = {}
    return p


def _connection(key: Tuple[str, str, int], timeout: float) -> Tuple[http.client.HTTPConnection, bool]:
    pool = _pool()
    entry = pool.pop(key, None)
    if entry is not None:
        conn, last_used = entry
        if time.monotonic() - last_used < IDLE_TIMEOUT:
            conn.timeout = timeout
            if conn.sock is not None:
                conn.sock.settimeout(timeout)
            return conn, True
        conn.close()  # сервер мог уже закрыть простаивающее соединение
    scheme, host, port = key
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=_ssl_context), False
    return http.client.HTTPConnection(host, port, timeout=timeout), False


def request(method: str, url: str, headers: Optional[Dict[str, str]] = None, json_body: Any = None,
            timeout: float = 10.0) -> Response:
    """HTTP-запрос через постоянное соединение. Редиректы не выполняются: 3xx возвращается как есть."""
    u = urlsplit(url)
    key = (u.scheme, u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    data = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    for attempt in range(2):
        conn, reused = _connection(key, timeout)
        try:
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            body = r.read()
        except (ConnectionRefusedError, socket.gaierror) as e:
            conn.close()
            raise TransportError(f"{type(e).__name__}: {e}", not_sent=True) from e
        except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError) as e:
            conn.close()
            if reused and attempt == 0:
                # Сервер закрыл простаивавшее keep-alive соединение раньше нас: запрос он не обработал,
                # повторяем один раз на новом соединении
                continue
            raise TransportError(f"{type(e).__name__}: {e}", not_sent=False) from e
        except (socket.timeout, TimeoutError) as e:
            conn.close()
            raise TransportError(f"{type(e).__name__}: {e}", not_sent=False) from e
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise TransportError(f"{type(e).__name__}: {e}", not_sent=False) from e

        if r.will_close:
            conn.close()
        else:
            _pool()[key] = (conn, time.monotonic())
        return Response(r.status, body, {k.lower(): v for k, v in r.getheaders()})
    raise TransportError("соединение закрыто сервером", not_sent=False)  # pragma: no cover
