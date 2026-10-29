from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional


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
    """Ответа нет. not_sent=True — соединение не установилось, запрос точно не дошёл и его безопасно повторить."""

    def __init__(self, message: str, not_sent: bool):
        super().__init__(message)
        self.not_sent = not_sent


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 — редиректы считаем ошибкой
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def request(method: str, url: str, headers: Optional[Dict[str, str]] = None, json_body: Any = None,
            timeout: float = 10.0) -> Response:
    data = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with _opener.open(req, timeout=timeout) as r:
            return Response(r.status, r.read(), {k.lower(): v for k, v in r.headers.items()})
    except urllib.error.HTTPError as e:
        return Response(e.code, e.read() or b"", {k.lower(): v for k, v in (e.headers or {}).items()})
    except urllib.error.URLError as e:
        reason = e.reason
        not_sent = isinstance(reason, (ConnectionRefusedError, socket.gaierror))
        raise TransportError(f"{type(reason).__name__}: {reason}", not_sent=not_sent) from e
    except (socket.timeout, TimeoutError, ConnectionError) as e:
        raise TransportError(f"{type(e).__name__}: {e}", not_sent=False) from e
