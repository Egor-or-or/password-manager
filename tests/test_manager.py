"""Тесты основной логики менеджера паролей."""

from pathlib import Path

import pytest

from password_manager.manager import PasswordManager, generate_password

MASTER_PASSWORD = "VeryStrongMasterPassword!2026"


def test_default_storage_path() -> None:
    """Менеджер использует vault.json по умолчанию."""
    manager = PasswordManager()

    assert manager.storage_path == Path("vault.json")


def test_master_password_unlock_and_storage_safety(tmp_path: Path) -> None:
    """Верный пароль открывает хранилище, а открытый пароль не сохраняется."""
    vault_path = tmp_path / "vault.json"
    manager = PasswordManager(vault_path)

    manager.init_master(MASTER_PASSWORD)

    assert manager.unlock("wrong-password") is False
    assert manager.unlock(MASTER_PASSWORD) is True
    assert MASTER_PASSWORD not in vault_path.read_text(encoding="utf-8")


def test_add_list_get_and_encrypt_entry(tmp_path: Path) -> None:
    """Запись добавляется, читается и не хранится в открытом виде."""
    vault_path = tmp_path / "vault.json"
    manager = PasswordManager(vault_path)
    manager.init_master(MASTER_PASSWORD)

    manager.add_entry("GitHub", "student", "SecretPassword!42")

    assert manager.list_entries() == ["GitHub"]
    assert manager.get_entry("GitHub") == ("student", "SecretPassword!42")

    stored_text = vault_path.read_text(encoding="utf-8")
    assert "SecretPassword!42" not in stored_text
    assert '"password"' not in stored_text


def test_delete_entry_removes_it_from_list(tmp_path: Path) -> None:
    """Удалённая запись больше не отображается."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER_PASSWORD)
    manager.add_entry("Telegram", "student", "Password!42")

    manager.delete_entry("Telegram")

    assert manager.list_entries() == []


def test_duplicate_update_search_and_password_generator(tmp_path: Path) -> None:
    """Проверяет расширения поиска, обновления и генератора паролей."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER_PASSWORD)
    manager.add_entry("GitHub", "student", "OldPassword!42")
    manager.add_entry("GitLab", "student", "Password!43")

    with pytest.raises(ValueError, match="уже существует"):
        manager.add_entry("GitHub", "another", "Password!44")

    manager.update_entry("GitHub", pwd="NewPassword!42")

    assert manager.list_entries("git") == ["GitHub", "GitLab"]
    assert manager.get_entry("GitHub") == ("student", "NewPassword!42")

    password = generate_password(16)

    assert len(password) == 16
    assert any(symbol.islower() for symbol in password)
    assert any(symbol.isupper() for symbol in password)
    assert any(symbol.isdigit() for symbol in password)
    assert any(not symbol.isalnum() for symbol in password)
