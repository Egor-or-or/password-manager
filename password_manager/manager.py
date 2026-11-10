"""Логика хранения, шифрования и управления записями паролей."""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import string
from pathlib import Path
from typing import TypedDict, cast

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
VAULT_VERSION = 1


class StoredEntry(TypedDict):
    """Зашифрованная запись в JSON-хранилище."""

    token: str


class EntryData(TypedDict):
    """Расшифрованные данные одной записи."""

    login: str
    password: str


class VaultData(TypedDict):
    """Структура файла хранилища."""

    version: int
    salt: str
    master_hash: str
    entries: dict[str, StoredEntry]


class PasswordManager:
    """Управляет мастер-паролем и зашифрованными записями."""

    def __init__(self, storage_path: str | Path = "vault.json") -> None:
        """Создаёт менеджер для указанного файла хранилища."""
        self.storage_path = Path(storage_path)
        self._data = self._load()
        self._cipher: Fernet | None = None

    @property
    def is_initialized(self) -> bool:
        """Возвращает True, если мастер-пароль уже создан."""
        return self._data is not None

    def init_master(self, password: str) -> None:
        """Создаёт мастер-пароль и начальное зашифрованное хранилище."""
        if self.is_initialized:
            raise ValueError("Хранилище уже инициализировано.")

        self._validate_text(password, "Мастер-пароль")
        salt = secrets.token_bytes(SALT_SIZE)
        self._data = {
            "version": VAULT_VERSION,
            "salt": base64.b64encode(salt).decode("ascii"),
            "master_hash": self._master_hash(password, salt),
            "entries": {},
        }
        self._cipher = Fernet(self._fernet_key(password, salt))
        self._persist()

    def unlock(self, password: str) -> bool:
        """Проверяет мастер-пароль и открывает хранилище в памяти."""
        if self._data is None:
            return False

        salt = self._decode_base64(self._data["salt"], "соли")
        actual_hash = self._master_hash(password, salt)
        expected_hash = self._data["master_hash"]

        if not hmac.compare_digest(actual_hash, expected_hash):
            self._cipher = None
            return False

        self._cipher = Fernet(self._fernet_key(password, salt))
        return True

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Добавляет новую запись с логином и паролем."""
        normalized_name = self._normalize_name(name)
        self._validate_text(login, "Логин")
        self._validate_text(pwd, "Пароль")

        data = self._require_data()
        if normalized_name in data["entries"]:
            raise ValueError("Запись с таким названием уже существует.")

        data["entries"][normalized_name] = self._encrypt_entry(login, pwd)
        self._persist()

    def list_entries(self, query: str | None = None) -> list[str]:
        """Возвращает названия записей, при необходимости отфильтрованные."""
        names = list(self._require_data()["entries"])

        if query is not None and query.strip():
            search_text = query.strip().casefold()
            names = [name for name in names if search_text in name.casefold()]

        return sorted(names, key=str.casefold)

    def get_entry(self, name: str) -> tuple[str, str]:
        """Возвращает логин и пароль записи."""
        normalized_name = self._normalize_name(name)
        entry = self._require_data()["entries"].get(normalized_name)

        if entry is None:
            raise KeyError("Запись не найдена.")

        decrypted = self._decrypt_entry(entry["token"])
        return decrypted["login"], decrypted["password"]

    def update_entry(
        self,
        name: str,
        login: str | None = None,
        pwd: str | None = None,
    ) -> None:
        """Обновляет логин, пароль или оба значения существующей записи."""
        if login is None and pwd is None:
            raise ValueError("Нужно указать новый логин или пароль.")

        old_login, old_password = self.get_entry(name)
        new_login = old_login if login is None else login
        new_password = old_password if pwd is None else pwd

        self._validate_text(new_login, "Логин")
        self._validate_text(new_password, "Пароль")

        normalized_name = self._normalize_name(name)
        self._require_data()["entries"][normalized_name] = self._encrypt_entry(
            new_login,
            new_password,
        )
        self._persist()

    def delete_entry(self, name: str) -> None:
        """Удаляет запись по названию."""
        normalized_name = self._normalize_name(name)
        entries = self._require_data()["entries"]

        if normalized_name not in entries:
            raise KeyError("Запись не найдена.")

        del entries[normalized_name]
        self._persist()

    def _load(self) -> VaultData | None:
        """Читает и проверяет JSON-хранилище."""
        if not self.storage_path.exists():
            return None

        try:
            raw_value: object = json.loads(
                self.storage_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("Не удалось прочитать файл хранилища.") from error

        if not isinstance(raw_value, dict):
            raise ValueError("Файл хранилища имеет неверный формат.")

        raw_data = cast(dict[str, object], raw_value)
        version = raw_data.get("version")
        salt = raw_data.get("salt")
        master_hash = raw_data.get("master_hash")
        raw_entries = raw_data.get("entries")

        if version != VAULT_VERSION:
            raise ValueError("Неподдерживаемая версия хранилища.")

        if not isinstance(salt, str) or not isinstance(master_hash, str):
            raise ValueError("В хранилище отсутствуют данные мастер-пароля.")

        if not isinstance(raw_entries, dict):
            raise ValueError("В хранилище отсутствуют записи.")

        self._decode_base64(salt, "соли")
        self._decode_base64(master_hash, "хэша")

        entries: dict[str, StoredEntry] = {}
        raw_entry_data = cast(dict[str, object], raw_entries)

        for name, raw_entry in raw_entry_data.items():
            if not isinstance(name, str) or not isinstance(raw_entry, dict):
                raise ValueError("В хранилище найдена неверная запись.")

            entry_data = cast(dict[str, object], raw_entry)
            token = entry_data.get("token")

            if not isinstance(token, str):
                raise ValueError("В хранилище найдена неверная запись.")

            entries[name] = {"token": token}

        return {
            "version": version,
            "salt": salt,
            "master_hash": master_hash,
            "entries": entries,
        }

    def _persist(self) -> None:
        """Сохраняет текущее состояние в JSON-файл."""
        data = self._require_data()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        temporary_path = self.storage_path.with_suffix(
            f"{self.storage_path.suffix}.tmp"
        )
        temporary_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary_path.replace(self.storage_path)

    def _encrypt_entry(self, login: str, password: str) -> StoredEntry:
        """Шифрует логин и пароль в одну запись."""
        cipher = self._require_unlocked()
        plaintext = json.dumps(
            {"login": login, "password": password},
            ensure_ascii=False,
        )
        token = cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return {"token": token}

    def _decrypt_entry(self, token: str) -> EntryData:
        """Расшифровывает и проверяет данные записи."""
        cipher = self._require_unlocked()

        try:
            decrypted = cipher.decrypt(token.encode("ascii")).decode("utf-8")
            raw_value: object = json.loads(decrypted)
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Не удалось расшифровать запись.") from error

        if not isinstance(raw_value, dict):
            raise ValueError("Расшифрованная запись имеет неверный формат.")

        entry_data = cast(dict[str, object], raw_value)
        login = entry_data.get("login")
        password = entry_data.get("password")

        if not isinstance(login, str) or not isinstance(password, str):
            raise ValueError("Расшифрованная запись имеет неверный формат.")

        return {"login": login, "password": password}

    def _require_data(self) -> VaultData:
        """Возвращает данные хранилища или сообщает об отсутствии инициализации."""
        if self._data is None:
            raise ValueError("Сначала создайте мастер-пароль через --init.")

        return self._data

    def _require_unlocked(self) -> Fernet:
        """Возвращает шифр для открытого хранилища."""
        if self._cipher is None:
            raise PermissionError("Хранилище закрыто мастер-паролем.")

        return self._cipher

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Проверяет и нормализует название сервиса."""
        normalized_name = name.strip()
        PasswordManager._validate_text(normalized_name, "Название сервиса")
        return normalized_name

    @staticmethod
    def _validate_text(value: str, field_name: str) -> None:
        """Проверяет, что текстовое значение не пустое."""
        if not value:
            raise ValueError(f"{field_name} не может быть пустым.")

    @staticmethod
    def _decode_base64(value: str, field_name: str) -> bytes:
        """Декодирует строку Base64 из хранилища."""
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise ValueError(f"Некорректное значение {field_name}.") from error

    @staticmethod
    def _derive_secret(password: str, salt: bytes, purpose: bytes) -> bytes:
        """Получает секрет из пароля, соли и назначения ключа."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt + purpose,
            PBKDF2_ITERATIONS,
        )

    @classmethod
    def _master_hash(cls, password: str, salt: bytes) -> str:
        """Создаёт проверочный хэш мастер-пароля."""
        derived = cls._derive_secret(password, salt, b"master-verifier")
        return base64.b64encode(derived).decode("ascii")

    @classmethod
    def _fernet_key(cls, password: str, salt: bytes) -> bytes:
        """Создаёт ключ Fernet для шифрования записей."""
        derived = cls._derive_secret(password, salt, b"vault-encryption")
        return base64.urlsafe_b64encode(derived)


def generate_password(length: int = 16) -> str:
    """Генерирует пароль с буквами, цифрами и специальными символами."""
    if length < 12:
        raise ValueError("Длина надёжного пароля должна быть не меньше 12.")

    special_characters = "!@#$%^&*()-_=+"
    characters = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(special_characters),
    ]
    alphabet = string.ascii_letters + string.digits + special_characters

    for _ in range(length - len(characters)):
        characters.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)
