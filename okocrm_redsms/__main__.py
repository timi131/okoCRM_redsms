from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from .config import Config
from .crypto import Cipher, generate_key
from .http_server import make_server
from .service import Bridge
from .store import Store


def main() -> None:
    if sys.argv[1:] == ["genkey"]:
        print(generate_key())
        return
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    bridge = Bridge(cfg, Store(cfg.db_path, Cipher(cfg.encryption_keys)))
    bridge.start()
    server = make_server(bridge, cfg.listen_host, cfg.listen_port)
    # shutdown() ждёт выхода из serve_forever, поэтому из обработчика сигнала — только в отдельном потоке
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    logging.getLogger("okocrm_redsms").info("слушаю %s:%s", cfg.listen_host, cfg.listen_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        bridge.stop()


if __name__ == "__main__":
    main()
