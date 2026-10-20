# Команды CLI

```
RdpGuard <команда> [аргументы] [--опции]
```

- Все команды требуют консоли администратора.
- Примеры ниже предполагают, что вы в папке с exe или она добавлена в `PATH`;
  иначе пишите полный путь: `& "C:\Program Files\RdpGuard\RdpGuard.exe" status`.
- Время в выводе — местное; в CSV и API — UTC.
- Коды возврата: `0` — успех; `1` — запись не найдена (`disallow`, `api-token revoke`) или непредвиденная ошибка;
  `2` — ошибка в аргументах, конфиге или нет прав администратора.

## Служба

### `install [--no-start]`

Регистрирует службу и запускает её. Повторный вызов обновляет настройки существующей службы.
Подробно — [установка](installation.md#установка-службы).

### `uninstall [--purge]`

Останавливает и удаляет службу, удаляет **все** правила брандмауэра `RdpGuard-*`.
`--purge` удаляет также `%ProgramData%\RdpGuard` (БД, логи) и источник журнала событий.

### `run`

Запуск в консоли с выводом лога — для диагностики. Если служба запущена, команда откажется работать:
два экземпляра конкурировали бы за брандмауэр. `Ctrl+C` — остановка.

### `status`

```
Service:          Running
Mode:             enforcing
Database:         C:\ProgramData\RdpGuard\rdpguard.db (schema v2)
Ban rules:        5 wrong passwords/1d, 3 unknown users/1d, 3 bad credentials/1d, 5 at regular intervals, 5/10m, 15/1d
Ban duration:     1d x2 per offense, max 30d
Active bans:      49 (permanent: 0)
Attempts 1h:      1504 from 38 IP(s)
Attempts 24h:     21652 from 65 IP(s)
New bans 24h:     49
External logons:  0 in 24h (see the Application log, event 1003)
Last record:      Security #58926437, RdpCoreTS #864817311
Firewall rules:   1 RdpGuard-* rule(s), 49 address(es)
```

## Баны

### `bans [--active] [--limit N] [--ip IP]`

История банов, новые сверху. `--active` — только действующие; `--ip` — по одному адресу; `--limit` — по умолчанию 100.

```
ID  IP              #  Banned            Expires           Left     State             Fails  Reason
--  --------------  -  ----------------  ----------------  -------  ----------------  -----  ---------------------------
52  203.0.113.7     3  2026-10-07 17:49  2026-10-11 17:49  3d 23h   active            10     10 failed logons within 10m
41  198.51.100.20   1  2026-10-05 09:12  2026-10-06 09:12           expired           10     10 failed logons within 10m
38  192.0.2.44      2  2026-10-04 11:00  2026-10-06 11:00           lifted: manual    0      manual: test
```

`#` — номер нарушения, `Fails` — сколько попыток было в окне в момент бана.

### `top [--hours 24] [--limit 20]`

Самые активные адреса за период (с тремя самыми подбираемыми именами для каждого) и самые подбираемые имена.

### `ban <ip> [--days N | --hours N | --permanent] [--reason TEXT] [--force]`

Ручной бан. Без срока используется политика: номер нарушения увеличивается, срок нарастает.

```powershell
RdpGuard ban 203.0.113.7                       # по политике
RdpGuard ban 203.0.113.7 --days 7 --reason "scanner"
RdpGuard ban 2001:db8::bad --permanent
```

- адрес из белого списка забанить нельзя — сначала `disallow`;
- если с адреса был успешный вход за `SuccessTrustDays`, нужен `--force`;
- активный бан этого адреса заменяется новым.

### `unban <ip> [--reset]`

Снимает активный бан. `--reset` дополнительно обнуляет счётчик нарушений — следующий бан будет первым.

## Белый список

### `allow <ip|cidr> [--note TEXT]`

Добавляет адрес или сеть; активные баны адресов из неё снимаются сразу.

```powershell
RdpGuard allow 198.51.100.0/24 --note "office"
RdpGuard allow 2001:db8:1234::/48 --note "VPN"
```

### `disallow <ip|cidr>`

Удаляет запись, добавленную `allow`. Записи из `appsettings.json` удаляются только правкой конфига.

### `whitelist`

Показывает весь белый список: встроенные диапазоны, записи конфига и записи `allow`.

## API-токены

Токены для [HTTP API](api.md). Сам токен показывается один раз, в БД хранится только его SHA-256.

### `api-token create <name>`

```
Token 'grafana' created. Copy it now, it is not stored and will not be shown again:

  rg_EXAMPLE-not-a-real-token-xxxxxxxxxxxxxxxxx

Use it as the HTTP header:  Authorization: Bearer <token>
```

Заведите отдельный токен на каждого потребителя (`prometheus`, `grafana-infinity`), чтобы отзывать их по одному.

### `api-token list`

```
Name        Token       Created           State
----------  ----------  ----------------  -----------------------
prometheus  rg_EXAMPL…  2026-10-19 17:41  active
old         rg_a81Kd0…  2026-09-01 10:00  revoked 2026-10-19 17:45
```

### `api-token revoke <name>`

Отзывает токен; он отклоняется начиная со следующего запроса. Перезапуск службы не нужен.

## Прочее

### `export --csv [--out DIR]`

Записывает `ips.csv` и `bans.csv` (UTF-8 с BOM, время в UTC) в текущую папку или в `DIR`.
Значения, начинающиеся с `= + - @`, экранируются апострофом — имена пользователей приходят
от атакующих, а файл могут открыть в Excel.

### `sync`

Немедленно сверяет брандмауэр с БД: через службу, если она запущена, иначе напрямую.

## Журнал аудита

Ручные действия пишутся в журнал Application от имени пользователя, запустившего CLI:

| ID | Действие |
|---|---|
| 1004 | `ban` |
| 1005 | `unban` |
| 1006 | `allow` / `disallow` |
| 1007 | `api-token create` / `revoke` |
