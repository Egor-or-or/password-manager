# Менеджер паролей

Петров Егор 25КНТ6

Консольное приложение для безопасного хранения паролей. Программа создаёт мастер-пароль, сохраняет только его хэш с солью и шифрует все записи алгоритмом Fernet.

## Возможности

- создание и проверка мастер-пароля;
- скрытый ввод паролей через `getpass`;
- добавление, просмотр, обновление и удаление записей;
- поиск сервисов по части названия без учёта регистра;
- шифрование логинов и паролей;
- генератор надёжных паролей;
- автоматические тесты и GitHub Actions.

## Установка зависимостей

```powershell
uv sync
```

## Запуск

Создать хранилище:

```powershell
uv run python -m password_manager --init
```

Открыть интерактивное меню:

```powershell
uv run python -m password_manager --unlock
```

Сгенерировать пароль длиной 20 символов:

```powershell
uv run python -m password_manager --generate 20
```

## Команды интерактивного меню

```text
add
list
list git
get GitHub
update GitHub
delete GitHub
exit
```

Команда `get` повторно запрашивает мастер-пароль. Для удаления записи нужно ввести `yes`.

## Проверка качества

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict password_manager tests
uv run python -m pytest
```