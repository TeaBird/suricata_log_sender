# Монитор событий IDECO

Небольшой скрипт для опроса IDECO/Suricata по API `/ips/alerts`, фильтрации шумных событий и отправки уведомлений о реально заблокированных (`result = blocked`) срабатываниях в Telegram.

Скрипт:
- подключается к IDECO по HTTPS;
- фильтрует события по времени (последний час) и по результату (`blocked`);
- отбрасывает заданные noisy‑типы;
- следит за новыми событиями и шлёт форматированное сообщение в Telegram‑чат;
- при истечении сессии IDECO может автоматически перелогиниться по логину/паролю и обновить cookie.

## Требования

- Python 3.10+ (рекомендуется 3.11)
- Библиотеки:
  - `requests`

Установка зависимостей:

```bash
pip install requests
```

## Переменные окружения

Все секреты задаются через переменные окружения, в коде они не хранятся.

- **Telegram**
  - `BOT_TOKEN` — токен Telegram‑бота.
  - `CHAT_ID` — ID чата/канала, куда слать уведомления.

- **IDECO / Suricata**
  - `BASE_URL` — базовый адрес веб‑интерфейса IDECO, по умолчанию `https://localhost:8443`.
  - `IDECO_TOKEN` — имя cookie сессии IDECO (например, `__Secure-ideco-AAAA`).
  - `SESSION_TOKEN` — значение этой cookie (например, `BBBB:CCCC`).
  - `IDECO_USERNAME` — логин пользователя IDECO (для автологина).
  - `IDECO_PASSWORD` — пароль пользователя IDECO (для автологина).
  
## Пример запуска (PowerShell)

```powershell
# ==== Telegram ====
$env:BOT_TOKEN      = "ВАШ_TELEGRAM_BOT_TOKEN"
$env:CHAT_ID        = "ВАШ_CHAT_ID"

# ==== IDECO: базовый адрес ====
$env:BASE_URL       = "https://localhost:8443"

# ==== IDECO: cookie из браузера ====
$env:IDECO_TOKEN    = "__Secure-ideco-AAAA"   # имя cookie
$env:SESSION_TOKEN  = "BBBB:CCCC"            # значение cookie

# ==== IDECO: логин/пароль для автологина ====
$env:IDECO_USERNAME = "ВАШ_ЛОГИН_IDECO"
$env:IDECO_PASSWORD = "ВАШ_ПАРОЛЬ_IDECO"

python .\run_monitor.py
```

## Логика фильтрации

- Берутся события за последний час (`date_time` с оператором `date_range` = `["hour"]`).
- Оставляются только события с `result = "blocked"`.
- Отбрасываются noisy‑типы, перечисленные в словаре `NOISY_ALERTS`.
- Для новых (ещё не отправленных) событий формируется сообщение с:
  - критичностью (`severity`);
  - описанием (`description`);
  - IP/портом источника и назначения;
  - страной источника и назначения (если есть);
  - текстом security‑события (`security_event`).

## Безопасность

- Не коммитьте реальные токены/пароли в репозиторий. Все секреты должны задаваться только через переменные окружения.


