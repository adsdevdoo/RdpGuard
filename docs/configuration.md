# Конфигурация

Файл `appsettings.json` рядом с `RdpGuard.exe`, секция `RdpGuard`. Комментарии `//` допускаются.
Конфиг читается при старте: после правки перезапустите службу (`Restart-Service RdpGuard`).
Если в конфиге ошибка, служба не стартует и пишет причину в журнал Application (событие 1900);
CLI выводит её в консоль.

Любой параметр можно переопределить переменной окружения с префиксом `RDPGUARD_`
(`:` заменяется на `__`): `RDPGUARD_RdpGuard__DryRun=false`, `RDPGUARD_RdpGuard__Api__Urls__0=http://+:9645/`.

Длительности задаются в формате `d.hh:mm:ss`: `"00:10:00"` — 10 минут, `"1.00:00:00"` — сутки.

## Общие

| Параметр | По умолчанию | Описание |
|---|---|---|
| `DryRun` | `true` | Считать и логировать, но не менять брандмауэр |
| `DataDirectory` | `%ProgramData%\RdpGuard` | БД (`rdpguard.db`) и логи (`logs\`). Переменные окружения раскрываются. `install` ограничивает доступ к папке, только если в её имени есть «RdpGuard» |

## Detection — что считать попыткой

| Параметр | По умолчанию | Описание |
|---|---|---|
| `LogonTypes` | `[3, 10]` | Типы входа: 3 — сетевой (SMB, RDP с NLA), 10 — RDP без NLA. Добавлять 2 (консоль) обычно не нужно |
| `EnableRdpCoreTs` | `true` | Читать событие 140 из журнала RdpCoreTS/Operational |
| `RdpCoreTsDedupSeconds` | `5` | Окно склейки 4625 и 140 с одного IP; 0 — не склеивать |
| `InitialLookbackMinutes` | `60` | Насколько назад читать журналы при самом первом запуске |
| `TrackSuccessfulLogons` | `true` | Обрабатывать 4624 с внешних адресов (см. [успешные входы](how-it-works.md#успешные-входы)) |
| `EnsureLogonAuditing` | `true` | При старте и раз в час проверять, что аудит входов включён (Success и Failure), и включать его. `false` — только предупреждать |

## Policy — когда и насколько банить

| Параметр | По умолчанию | Описание |
|---|---|---|
| `MaxFailures` | `10` | Порог: столько неудачных входов… |
| `FailureWindow` | `00:10:00` | …за это окно дают бан |
| `BaseBanDuration` | `1.00:00:00` | Срок первого бана |
| `MaxBanDuration` | `30.00:00:00` | Потолок срока |
| `PermanentAfterOffenses` | `0` | K > 0: нарушение K+1 и далее — навсегда; 0 — выключено |
| `OffenseResetDays` | `90` | Сбрасывать счётчик нарушений после стольких дней тишины; 0 — никогда |
| `SuccessTrustDays` | `30` | Не банить адрес столько дней после успешного входа; 0 — выключено |
| `SuccessfulLogonLiftsBan` | `true` | Успешный вход снимает активный бан адреса |

Формула и примеры — в разделе [нарастание срока](how-it-works.md#нарастание-срока).

## Whitelist — кого не банить никогда

| Параметр | По умолчанию | Описание |
|---|---|---|
| `TrustPrivateRanges` | `true` | Частные и служебные диапазоны IPv4/IPv6 |
| `Cidrs` | `[]` | Дополнительные адреса и сети: `"203.0.113.7"`, `"198.51.100.0/24"`, `"2001:db8::/32"` |

Записи, добавленные командой `RdpGuard allow`, хранятся в БД и применяются без перезапуска.

## Firewall

| Параметр | По умолчанию | Описание |
|---|---|---|
| `Scope` | `AllPorts` | `AllPorts` — блокировать весь входящий трафик с адреса; `RdpPort` — только TCP-порт RDP |
| `RdpPort` | `0` | Порт для `RdpPort`; 0 — взять из реестра (`RDP-Tcp\PortNumber`), иначе 3389 |
| `MaxAddressesPerRule` | `1000` | Адресов в одном правиле `RdpGuard-Block-NN`, 1..1000 |

При смене `Scope` правила пересоздаются при следующем старте.

## Storage

| Параметр | По умолчанию | Описание |
|---|---|---|
| `AttemptRetentionDays` | `30` | Сколько хранить `attempts` и `successes`. Таблицы `bans` и `ips` не чистятся |

## Api — статистика для Grafana

| Параметр | По умолчанию | Описание |
|---|---|---|
| `Enabled` | `true` | Включить HTTP API |
| `Urls` | `["http://127.0.0.1:9645/"]` | Префиксы `HttpListener`, каждый с `/` в конце. Все интерфейсы: `http://+:9645/` |
| `AllowedClients` | `["127.0.0.0/8", "::1/128"]` | IP или CIDR, с которых принимаются запросы; остальным — 403 |
| `RequireToken` | `true` | Требовать `Authorization: Bearer <token>` для всего, кроме `/health` |

Токены создаются командой `RdpGuard api-token create <name>`. Подробнее — [HTTP API](api.md).

## FileLog

| Параметр | По умолчанию | Описание |
|---|---|---|
| `Enabled` | `true` | Писать `logs\rdpguard.log` |
| `MaxFileSizeMB` | `10` | Размер файла до ротации |
| `RetainedFiles` | `10` | Сколько архивов хранить: `rdpguard.1.log` … `rdpguard.N.log` |

## Logging

Стандартная секция .NET (вне `RdpGuard`). Провайдеры: `File` (файл), `EventLog` (журнал Application),
`Console` (только в режиме `run`).

```json
"Logging": {
  "LogLevel": { "Default": "Information", "Microsoft": "Warning" },
  "EventLog": { "LogLevel": { "Default": "Warning", "RdpGuard.Audit": "Information" } }
}
```

Категория `RdpGuard.Audit` — баны, разбаны, успешные входы извне, ручные действия; по умолчанию она
попадает в журнал Application с уровня Information, всё остальное — с Warning.

## Пример: строгая политика

```json
"Policy": {
  "MaxFailures": 5,
  "FailureWindow": "00:30:00",
  "BaseBanDuration": "7.00:00:00",
  "MaxBanDuration": "90.00:00:00",
  "PermanentAfterOffenses": 3,
  "OffenseResetDays": 365
}
```

5 неудач за 30 минут → 7 суток, затем 14, 28, а четвёртое нарушение — навсегда.
