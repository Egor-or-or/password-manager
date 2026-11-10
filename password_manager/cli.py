"""Командная строка и интерактивное меню менеджера паролей."""

import argparse
from collections.abc import Sequence
from getpass import getpass

from .manager import PasswordManager, generate_password


def main(argv: Sequence[str] | None = None) -> int:
    """Запускает программу и возвращает код завершения."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    selected_actions = (
        int(args.init) + int(args.unlock) + int(args.generate is not None)
    )

    if selected_actions > 1:
        parser.error(
            "Используйте только один аргумент: --init, --unlock или --generate."
        )

    if args.generate is not None:
        try:
            print(generate_password(args.generate))
        except ValueError as error:
            print(f"Ошибка: {error}")
            return 1
        return 0

    manager = PasswordManager()

    if args.init:
        return _initialize_manager(manager)

    if args.unlock:
        return _unlock_manager(manager)

    parser.print_help()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Создаёт обработчик аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description="Консольный менеджер паролей.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="создать мастер-пароль и хранилище",
    )
    parser.add_argument(
        "--unlock",
        action="store_true",
        help="открыть интерактивное меню",
    )
    parser.add_argument(
        "--generate",
        nargs="?",
        const=16,
        default=None,
        type=int,
        metavar="LENGTH",
        help="сгенерировать надёжный пароль длиной от 12 символов",
    )
    return parser


def _initialize_manager(manager: PasswordManager) -> int:
    """Создаёт новый мастер-пароль."""
    password = getpass("Создайте мастер-пароль: ")
    repeated_password = getpass("Повторите мастер-пароль: ")

    if password != repeated_password:
        print("Ошибка: пароли не совпадают.")
        return 1

    try:
        manager.init_master(password)
    except ValueError as error:
        print(f"Ошибка: {error}")
        return 1

    print("Хранилище создано и открыто.")
    return 0


def _unlock_manager(manager: PasswordManager) -> int:
    """Открывает хранилище и запускает меню."""
    if not manager.is_initialized:
        print("Хранилище не найдено. Сначала выполните команду --init.")
        return 1

    password = getpass("Введите мастер-пароль: ")

    if not manager.unlock(password):
        print("Неверный мастер-пароль.")
        return 1

    print("Хранилище открыто. Введите help для списка команд.")
    _run_menu(manager)
    return 0


def _run_menu(manager: PasswordManager) -> None:
    """Обрабатывает команды интерактивного меню."""
    while True:
        command_line = input("vault> ").strip()

        if not command_line:
            continue

        command, _, argument = command_line.partition(" ")
        command = command.casefold()
        argument = argument.strip()

        try:
            if command == "help":
                _print_help()
            elif command == "add":
                _add_entry(manager)
            elif command == "list":
                _list_entries(manager, argument)
            elif command == "get":
                _show_entry(manager, argument)
            elif command == "update":
                _update_entry(manager, argument)
            elif command == "delete":
                _delete_entry(manager, argument)
            elif command == "exit":
                print("Работа завершена.")
                return
            else:
                print("Неизвестная команда. Введите help.")
        except (KeyError, PermissionError, ValueError) as error:
            print(f"Ошибка: {error}")


def _print_help() -> None:
    """Показывает доступные команды меню."""
    print(
        "\n"
        "add                добавить запись\n"
        "list [текст]       показать записи или найти по части названия\n"
        "get <название>     показать логин и пароль после подтверждения\n"
        "update <название>  изменить логин или пароль\n"
        "delete <название>  удалить запись после подтверждения\n"
        "exit               завершить работу\n"
    )


def _add_entry(manager: PasswordManager) -> None:
    """Запрашивает данные и добавляет запись."""
    name = input("Название сервиса: ")
    login = input("Логин: ")
    password = getpass("Пароль: ")
    manager.add_entry(name, login, password)
    print("Запись добавлена.")


def _list_entries(manager: PasswordManager, query: str) -> None:
    """Показывает названия записей."""
    entries = manager.list_entries(query or None)

    if not entries:
        print("Записи не найдены.")
        return

    for entry_name in entries:
        print(f"- {entry_name}")


def _show_entry(manager: PasswordManager, name: str) -> None:
    """Подтверждает мастер-пароль и показывает запись."""
    if not name:
        raise ValueError("Укажите название, например: get GitHub")

    password = getpass("Подтвердите мастер-пароль: ")

    if not manager.unlock(password):
        print("Неверный мастер-пароль.")
        return

    login, entry_password = manager.get_entry(name)
    print(f"Логин: {login}")
    print(f"Пароль: {entry_password}")


def _update_entry(manager: PasswordManager, name: str) -> None:
    """Запрашивает новые данные и обновляет запись."""
    if not name:
        raise ValueError("Укажите название, например: update GitHub")

    new_login = input("Новый логин, Enter чтобы оставить прежний: ")
    new_password = getpass("Новый пароль, Enter чтобы оставить прежний: ")

    manager.update_entry(
        name,
        login=new_login or None,
        pwd=new_password or None,
    )
    print("Запись обновлена.")


def _delete_entry(manager: PasswordManager, name: str) -> None:
    """Подтверждает и удаляет запись."""
    if not name:
        raise ValueError("Укажите название, например: delete GitHub")

    confirmation = input(f"Удалить запись «{name}»? Введите yes для подтверждения: ")

    if confirmation.casefold() != "yes":
        print("Удаление отменено.")
        return

    manager.delete_entry(name)
    print("Запись удалена.")
