# Разработка

## Сборка и тесты

```powershell
dotnet build
dotnet test
dotnet publish src/RdpGuard -c Release -r win-x64 -o publish
```

Нужен .NET SDK 8+ на Windows (проект `net8.0-windows`: журнал событий, COM брандмауэра, службы).

Запуск из исходников в консоли с отдельной папкой данных, не трогая установленную службу:

```powershell
$env:RDPGUARD_RdpGuard__DataDirectory = "$env:TEMP\rdpguard-dev"
$env:RDPGUARD_RdpGuard__Api__Urls__0 = "http://127.0.0.1:9646/"
dotnet run --project src/RdpGuard -- run
```

В DryRun (по умолчанию) это безопасно: журналы только читаются, брандмауэр не меняется.

### Системные тесты

Тесты `Category=System` работают с настоящим Windows Firewall: создают **выключенные** правила
`RdpGuard-SystemTest-…` с адресами из документационных диапазонов (192.0.2.0/24, 2001:db8::/32)
и удаляют их. По умолчанию они пропускаются; запуск — из консоли администратора:

```powershell
$env:RDPGUARD_SYSTEM_TESTS = "1"
dotnet test --filter "Category=System"
```

Именно они нашли, что брандмауэр возвращает одиночный IPv6 как диапазон `addr-addr`.

### Аудит зависимостей

```powershell
dotnet list package --vulnerable --include-transitive
dotnet list package --deprecated
dotnet list src/RdpGuard package --outdated --highest-patch --include-transitive
```

`Microsoft.Data.Sqlite` 8.0.x по умолчанию тянет `SQLitePCLRaw` 2.1.6 с уязвимой SQLite
(GHSA-2m69-gcr7-jv3q), поэтому `SQLitePCLRaw.bundle_e_sqlite3` зафиксирован в `RdpGuard.csproj` явно.
При обновлении пакетов не удаляйте эту ссылку, пока транзитивная версия не станет ≥ 2.1.11.

## Структура

```
src/RdpGuard/
  Program.cs          служба (под SCM), "run" (консоль) или CLI
  Api/                StatsApiServer (HttpListener), PrometheusWriter, ApiTokens
  Cli/                команды, sc.exe-установщик, ACL папки данных
  Configuration/      GuardOptions — модель appsettings.json и её проверка
  Data/               GuardDb (SQLite, WAL, миграции), Repository, StatsQueries
  Engine/             GuardEngine (очередь -> БД -> брандмауэр), AdminOperations, GuardMetrics, LogEvents
  Events/             EventParser, EventLogAuthSource (EventLogWatcher), склейка 4625/140
  Firewall/           IFirewall, ComFirewall (INetFwPolicy2), FirewallSync (разбиение и сверка)
  Hosting/            ServiceHost, GuardService
  Logging/            файловый лог с ротацией
  Net/                IP, CIDR, белый список
  Policy/             BanPolicy — чистая логика без ввода-вывода
tests/RdpGuard.Tests/
  BanPolicyTests             окно, порог, нарастание, потолок, навсегда, сброс счётчика, доверие после входа
  WhitelistAndParsingTests   диапазоны, CIDR, нормализация IP, разбор событий по позициям, XPath, склейка
  FirewallSyncTests          пачки по 1000, стабильность правил, сверка, чужие правила не трогаются
  GuardEngineTests           поток событий -> баны в SQLite и в фейковом брандмауэре; метрики
  StatsApiTests              HTTP API на настоящем HttpListener: токены, 401/403, JSON, Prometheus
  ComFirewallSystemTests     настоящий брандмауэр (опционально)
grafana/rdpguard-dashboard.json
```

Внешние зависимости изолированы интерфейсами: `IFirewall` (в тестах `FakeFirewall`),
`IAuthEventSource` (`FakeEventSource`), время — `TimeProvider` (`ManualTime`).

## Ключевые решения

- **Один писатель.** Все изменения из службы идут через `GuardEngine` в одном потоке; пачка — одна
  транзакция вместе с закладками журналов. CLI пишет в БД из своего процесса (WAL + `busy_timeout`)
  и сигналит службе через `state.admin_rev`.
- **Аудит после коммита.** Записи в журнал и метрики копятся в `_afterCommit` и выполняются только
  после успешного коммита — откатившаяся пачка не оставляет ложных «Banned …».
- **Закладка через XPath.** `EventRecordID > N` + `readExistingEvents` вместо `EventBookmark`:
  `EventBookmark` в .NET нельзя сериализовать, а `RecordId` — можно, и нет окна между догрузкой и подпиской.
- **Брандмауэр через `dynamic` COM.** Без interop-сборок (`COMReference` не собирается `dotnet build`).
  Поэтому публикация без тримминга.
- **API без ASP.NET.** `HttpListener` — без лишних ~10 МБ в exe; read-only подключение к SQLite на запрос.

## Миграции схемы

Схема версионируется в `state.schema_version`. Миграции — массив `GuardDb.Migrations`; каждая
применяется в своей транзакции `BEGIN IMMEDIATE` (служба и CLI могут открыть БД одновременно).

Добавить миграцию:

1. Дописать новый элемент в конец `Migrations` (существующие не менять).
2. Увеличить `GuardDb.SchemaVersion`.
3. Использовать `IF NOT EXISTS` / идемпотентные операции.
4. Добавить тест обновления по образцу `SchemaV1_IsMigratedToV2`.

Версия, которая видит схему новее своей, отказывается работать, чтобы не испортить данные.

## Коды событий журнала Application

| ID | Уровень | Событие |
|---|---|---|
| 1000 | Information | Служба запущена |
| 1001 | Warning | Бан |
| 1002 | Information / Warning | Снятие бана |
| 1003 | Warning | Успешный вход с внешнего адреса |
| 1004 / 1005 | Warning | Ручной бан / разбан |
| 1006 | Warning | Изменение белого списка |
| 1007 | Warning | Создание / отзыв API-токена |
| 1008 | Warning / Error | Аудит входов был выключен и включён службой (или включить не удалось) |
| 1009 | Warning | Распределённый подбор пароля к учётке (много адресов) |
| 1010 | Information | Изменение правил брандмауэра (только файл) |
| 1900 | Error | Ошибка обработки / конфигурации |
| 1901 | Error | Ошибка брандмауэра |
