# HTTP API статистики

Служба отдаёт статистику по HTTP:

- **`/metrics`** — метрики в формате Prometheus (для графиков и алертов в Grafana через Prometheus);
- **`/api/*`** — JSON (для таблиц в Grafana через плагин Infinity, скриптов, своих интеграций).

API только читает данные: управлять банами через него нельзя.

## Безопасность

Ответы содержат адреса атакующих и **имена учётных записей, которые подбирают** — среди них бывают
настоящие логины. Поэтому защита в три слоя:

| Слой | Что делает | По умолчанию |
|---|---|---|
| Адрес прослушивания | `Api:Urls` | только `http://127.0.0.1:9645/` |
| Белый список клиентов | `Api:AllowedClients`; остальным — `403` | `127.0.0.0/8`, `::1` |
| Токен | `Authorization: Bearer <token>`; без него — `401` | обязателен для всего, кроме `/health` |

### Токены

```powershell
RdpGuard api-token create prometheus
RdpGuard api-token list
RdpGuard api-token revoke prometheus
```

- Формат: `rg_` + 32 случайных байта (base64url), 256 бит энтропии — перебор бесполезен.
- В БД хранится только SHA-256 токена; сам токен показывается один раз при создании.
  Папка с БД доступна только SYSTEM и Administrators.
- Отзыв действует со следующего запроса, без перезапуска службы.
- Отказы логируются (Warning, не чаще раза в минуту на адрес).
- Токены не хранятся в `appsettings.json`: файл в Program Files читают обычные пользователи.

`RequireToken: false` отключает проверку токена — разумно, только если API слушает `127.0.0.1`
и его читает Prometheus (или агент) на этом же сервере.

### Доступ с другого сервера

1. Слушать все интерфейсы и пустить только сервер мониторинга:

   ```json
   "Api": {
     "Enabled": true,
     "Urls": [ "http://+:9645/" ],
     "AllowedClients": [ "10.0.5.20/32" ],
     "RequireToken": true
   }
   ```

2. Открыть порт в брандмауэре **только для этого адреса**:

   ```powershell
   New-NetFirewallRule -DisplayName "RdpGuard API" -Direction Inbound -Protocol TCP -LocalPort 9645 `
       -RemoteAddress 10.0.5.20 -Action Allow
   ```

   Имя правила — с пробелом, не `RdpGuard-…`: правила с префиксом `RdpGuard-` служба считает своими и удаляет.

3. `Restart-Service RdpGuard`.

Если сервер мониторинга может попасть под бан (например, публичный адрес), добавьте его в белый список:
`RdpGuard allow 10.0.5.20`. Частные адреса в белом списке по умолчанию.

### HTTPS

Токен по HTTP передаётся открытым текстом. В пределах сегмента мониторинга или VPN это обычно приемлемо;
иначе используйте HTTPS. `HttpListener` берёт сертификат из привязки HTTP.sys:

```powershell
# сертификат с закрытым ключом в LocalMachine\My; appid — любой GUID
netsh http add sslcert ipport=0.0.0.0:9645 certhash=<THUMBPRINT> appid="{6f0f5d5e-2b8b-4d4e-9a8f-5d3c7b1e9a01}"
```

```json
"Urls": [ "https://+:9645/" ]
```

Альтернатива — обратный прокси (IIS, nginx) с TLS перед `http://127.0.0.1:9645/`.

## Эндпоинты

Все ответы — `Cache-Control: no-store`; время в JSON — ISO 8601 UTC (`2026-10-19T15:41:51.731Z`).

| Метод и путь | Токен | Ответ |
|---|---|---|
| `GET /health` | нет | `ok` — сервер работает (без проверки БД) |
| `GET /` или `/api` | да | Список эндпоинтов и версия |
| `GET /metrics` | да | Prometheus text format 0.0.4 |
| `GET /api/summary` | да | Сводка |
| `GET /api/bans?active=true&limit=100&ip=…` | да | Баны, новые сверху |
| `GET /api/top?hours=24&limit=20` | да | Самые активные адреса |
| `GET /api/users?hours=24&limit=20` | да | Самые подбираемые имена |
| `GET /api/timeseries/attempts?hours=24&step=300` | да | Неудачные попытки по интервалам |
| `GET /api/timeseries/bans?hours=168&step=3600` | да | Новые баны по интервалам |

Ограничения параметров: `hours` 1..2160 (90 дней), `limit` 1..1000, `step` 60..86400 секунд,
не больше 5000 точек (иначе `step` увеличивается). Нечисловой параметр — `400`.

Коды ошибок: `401` — нет или неверный токен; `403` — адрес клиента не в `AllowedClients`;
`404` — неизвестный путь; `405` — не GET/HEAD; `503` — БД ещё не создана или занято.

### Примеры

```powershell
$h = @{ Authorization = "Bearer rg_..." }
Invoke-RestMethod http://127.0.0.1:9645/api/summary -Headers $h
```

```bash
curl -H "Authorization: Bearer rg_..." http://win-server-01:9645/metrics
```

### `/api/summary`

```json
{
  "generatedUtc": "2026-10-19T15:41:51.731Z",
  "dryRun": false,
  "activeBans": 22,
  "permanentBans": 0,
  "failedLogons1h": 1919,
  "attackingIps1h": 65,
  "failedLogons24h": 1922,
  "attackingIps24h": 65,
  "bans24h": 22,
  "externalLogons24h": 0,
  "trackedIps": 65,
  "whitelistEntries": 0,
  "totalBans": 22,
  "activeBansByOffense": { "1": 22, "2": 0, "3": 0, "4": 0, "5+": 0, "permanent": 0 },
  "lastFailureUtc": "2026-10-19T15:41:49.840Z",
  "firewallRules": 1,
  "firewallAddresses": 22,
  "lastFirewallSyncUtc": "2026-10-19T15:41:40.410Z",
  "startedUtc": "2026-10-19T15:41:39.813Z"
}
```

`firewallRules`, `firewallAddresses`, `lastFirewallSyncUtc` — `null` в DryRun и до первой синхронизации.

### `/api/top`

```json
[
  {
    "ip": "203.0.113.10",
    "attempts": 128,
    "users": 1,
    "firstUtc": "2026-10-19T14:41:52.384Z",
    "lastUtc": "2026-10-19T15:41:46.792Z",
    "offenses": 1,
    "banned": true,
    "banExpiresUtc": "2026-10-20T15:41:40.203Z",
    "banPermanent": false,
    "topUsers": "admin(128)"
  }
]
```

### `/api/bans`

```json
[
  {
    "id": 52,
    "ip": "203.0.113.7",
    "offenseNo": 3,
    "bannedAtUtc": "2026-10-07T15:49:44.052Z",
    "expiresAtUtc": "2026-10-11T15:49:44.052Z",
    "permanent": false,
    "active": true,
    "remainingSeconds": 341210,
    "failuresInWindow": 10,
    "reason": "10 failed logons within 10m",
    "unbannedAtUtc": null,
    "unbanReason": null
  }
]
```

### `/api/users`

```json
[ { "user": "admin", "attempts": 12161, "ips": 33 } ]
```

`user` = `?` для событий без имени (событие 140).

### `/api/timeseries/attempts`, `/api/timeseries/bans`

```json
[
  { "time": "2026-10-19T14:40:00.000Z", "timeMs": 1792421200000, "count": 41, "ips": 7 },
  { "time": "2026-10-19T14:45:00.000Z", "timeMs": 1792421500000, "count": 0, "ips": 0 }
]
```

Пустые интервалы заполнены нулями. `ips` — число разных адресов в интервале.

## Метрики Prometheus

**Счётчики** (`counter`) живут в памяти процесса и обнуляются при перезапуске службы — используйте
`rate()` / `increase()`, Prometheus учитывает сбросы.

| Метрика | Метки | Что считает |
|---|---|---|
| `rdpguard_events_read_total` | `channel` (`Security`, `RdpCoreTS`) | Прочитано записей журнала |
| `rdpguard_failed_logons_total` | `event_id` (`4625`, `140`) | Неудачные входы, записанные в БД (после склейки) |
| `rdpguard_failed_logons_duplicate_total` | `event_id` | Отброшено как дубли 4625/140 |
| `rdpguard_external_logons_total` | `whitelisted` (`true`, `false`) | Успешные входы с внешних адресов |
| `rdpguard_bans_total` | `offense` (`1`…`4`, `5+`) | Автоматические баны (ручные из CLI не входят) |
| `rdpguard_unbans_total` | `reason` (`expired`, `successful_logon`, `whitelisted`) | Снятые службой баны |
| `rdpguard_errors_total` | `stage` (`event`, `batch`, `maintenance`, `firewall`) | Ошибки обработки |
| `rdpguard_firewall_syncs_total` | `result` (`ok`, `error`) | Сверки брандмауэра |

**Состояние** (`gauge`), считается из БД на каждый запрос:

| Метрика | Что показывает |
|---|---|
| `rdpguard_active_bans` | Активные баны |
| `rdpguard_active_bans_by_offense{offense="1".."4","5+","permanent"}` | Активные баны по номеру нарушения |
| `rdpguard_failed_logons_last_1h`, `_last_24h` | Неудачные входы за час / сутки |
| `rdpguard_attacking_ips_last_1h`, `_last_24h` | Разных атакующих адресов за час / сутки |
| `rdpguard_bans_last_24h` | Баны за сутки (включая ручные) |
| `rdpguard_external_logons_last_24h` | Успешные входы извне за сутки |
| `rdpguard_tracked_ips` | Адресов в БД |
| `rdpguard_whitelist_entries` | Записей `allow` |
| `rdpguard_bans_recorded` | Всего банов в истории |
| `rdpguard_database_up` | 1 — БД прочитана для этого ответа |

**Служба:**

| Метрика | Что показывает |
|---|---|
| `rdpguard_info{version}` | Версия (всегда 1) |
| `rdpguard_dry_run` | 1 — DryRun |
| `rdpguard_start_time_seconds` | Время запуска процесса (Unix) |
| `rdpguard_queue_length` | Событий в очереди на запись |
| `rdpguard_logon_audit_enabled{type="success"\|"failure"}` | 1 — Windows пишет такие входы в журнал (проверка раз в час) |
| `rdpguard_last_event_timestamp_seconds{channel}` | Время последнего обработанного события входа |
| `rdpguard_firewall_rules`, `rdpguard_firewall_addresses` | Правил и адресов после последней сверки (нет в DryRun) |
| `rdpguard_firewall_last_sync_timestamp_seconds` | Время последней успешной сверки |
| `rdpguard_scrape_timestamp_seconds` | Время формирования ответа |

Адреса атакующих в метки Prometheus не попадают — это раздуло бы число рядов. Для таблиц по адресам
используйте JSON API.
