from __future__ import annotations

from typing import List, Optional

try:
    from cryptography.fernet import Fernet, InvalidToken, MultiFernet
except ImportError as e:  # pragma: no cover
    raise SystemExit("Нужен пакет cryptography: pip install -r requirements.txt") from e

PREFIX = "enc:"


class Cipher:
    """Шифрование секретов в БД (Fernet: AES-128-CBC + HMAC-SHA256).

    keys — один или несколько ключей Fernet. Первым шифруется, остальными только расшифровывается:
    так ключ меняют без простоя — ENCRYPTION_KEY="новый,старый", перезапуск, затем убрать старый.
    """

    def __init__(self, keys: List[str]):
        if not keys:
            raise ValueError("нет ключа шифрования")
        try:
            self._f = MultiFernet([Fernet(k.encode()) for k in keys])
        except (ValueError, TypeError) as e:
            raise SystemExit("ENCRYPTION_KEY: неверный ключ Fernet. Сгенерируйте: python3 -m okocrm_redsms genkey") from e

    def encrypt(self, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return value
        return PREFIX + self._f.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: Optional[str]) -> Optional[str]:
        if not value or not value.startswith(PREFIX):
            return value  # пусто или открытый текст из старой версии — его зашифрует migrate()
        try:
            return self._f.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
        except InvalidToken as e:
            raise RuntimeError("не удалось расшифровать секрет: ENCRYPTION_KEY не совпадает с тем, "
                               "которым шифровали") from e

    def reencrypt(self, value: Optional[str]) -> Optional[str]:
        """Открытый текст — зашифровать; зашифрованное старым ключом — перешифровать первым."""
        if not value:
            return value
        if not value.startswith(PREFIX):
            return self.encrypt(value)
        try:
            return PREFIX + self._f.rotate(value[len(PREFIX):].encode("ascii")).decode("ascii")
        except InvalidToken as e:
            raise RuntimeError("не удалось расшифровать секреты в БД: ENCRYPTION_KEY не совпадает с тем, "
                               "которым шифровали. Верните прежний ключ (можно вторым: ENCRYPTION_KEY=новый,старый)") from e


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")
