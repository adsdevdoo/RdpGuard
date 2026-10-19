# RdpGuard

Служба Windows, которая находит подбор паролей по сети (RDP, SMB и другие сетевые входы)
и автоматически блокирует атакующие IP-адреса в Windows Firewall. Каждое следующее нарушение
с того же адреса даёт бан в два раза длиннее.

- **Без агентов и зависимостей.** Один self-contained `RdpGuard.exe` (.NET 8): и служба, и утилита управления.
- **Не зависит от языка Windows.** События журнала читаются по позициям полей, а не по тексту сообщений.
- **Не теряет события.** Подписка в реальном времени через `EventLogWatcher`; после перезапуска служба
  дочитывает всё, что пропустила.
- **Нарастающие баны.** 1 сутки, 2, 4, 8… до потолка (по умолчанию 30 суток); опционально — навсегда.
- **Аккуратно с брандмауэром.** Правила `RdpGuard-Block-NN` по 1000 адресов; перезаписываются только
  изменившиеся; чужие правила не трогаются никогда.
- **Безопасный старт.** По умолчанию режим DryRun: всё считается и логируется, брандмауэр не меняется.
- **Статистика для Grafana.** `/metrics` для Prometheus и JSON API с авторизацией по токенам; готовый дашборд.
- **IPv4 и IPv6**, белый список, SQLite, журнал Application и ротируемый файловый лог.

## Быстрый старт

Нужна консоль администратора.

```powershell
# 1. Сборка
dotnet publish src/RdpGuard -c Release -r win-x64 -o publish

# 2. Разместить и установить службу (стартует в DryRun)
New-Item -ItemType Directory -Force "C:\Program Files\RdpGuard" | Out-Null
Copy-Item publish\* "C:\Program Files\RdpGuard\"
& "C:\Program Files\RdpGuard\RdpGuard.exe" install

# 3. Понаблюдать день-два
& "C:\Program Files\RdpGuard\RdpGuard.exe" status
& "C:\Program Files\RdpGuard\RdpGuard.exe" top --hours 24
& "C:\Program Files\RdpGuard\RdpGuard.exe" bans --active
```

Когда убедитесь, что в банах нет ваших адресов (если есть: `RdpGuard allow <ip|cidr>`),
поставьте `"DryRun": false` в `C:\Program Files\RdpGuard\appsettings.json` и перезапустите службу:

```powershell
Restart-Service RdpGuard
```

Подробно — в [руководстве по установке](docs/installation.md).

## Как считается срок бана

```
срок = BaseBanDuration × 2^(n−1), но не больше MaxBanDuration      (n — номер нарушения)
```

| Нарушение | 1 | 2 | 3 | 4 | 5 | 6 и далее |
|---|---|---|---|---|---|---|
| Срок (по умолчанию) | 1 сут | 2 сут | 4 сут | 8 сут | 16 сут | 30 сут |

Нарушение — не меньше 10 неудачных входов с адреса за 10 минут. Счётчик нарушений обнуляется,
если адрес не появлялся 90 дней. Адрес, с которого был успешный вход за последние 30 дней,
не банится. Всё настраивается — см. [как это работает](docs/how-it-works.md) и [конфигурацию](docs/configuration.md).

## Grafana

```powershell
RdpGuard api-token create grafana     # токен показывается один раз
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rdpguard
    authorization:
      credentials_file: /etc/prometheus/rdpguard.token
    static_configs:
      - targets: ["win-server-01:9645"]
```

Импортируйте [`grafana/rdpguard-dashboard.json`](grafana/rdpguard-dashboard.json).
По умолчанию API слушает только `127.0.0.1` — как открыть его для Prometheus, описано в [docs/grafana.md](docs/grafana.md).

## Удаление

```powershell
RdpGuard uninstall           # служба и ВСЕ правила RdpGuard-* удалены, данные сохранены
RdpGuard uninstall --purge   # то же + БД, логи и источник журнала
```

## Документация

| Раздел | О чём |
|---|---|
| [Установка](docs/installation.md) | Требования, установка, переход из DryRun, обновление, удаление |
| [Как это работает](docs/how-it-works.md) | События, политика банов, нарастание срока, брандмауэр, схема БД |
| [Конфигурация](docs/configuration.md) | Все параметры `appsettings.json` |
| [Команды CLI](docs/cli.md) | `status`, `bans`, `top`, `ban`, `unban`, `allow`, `api-token`, `export`… |
| [HTTP API](docs/api.md) | Авторизация, эндпоинты, метрики Prometheus, примеры ответов |
| [Grafana и Prometheus](docs/grafana.md) | Сбор метрик, дашборд, плагин Infinity, алерты |
| [Решение проблем](docs/troubleshooting.md) | Нет событий, заблокировал себя, API не отвечает… |
| [Разработка](docs/development.md) | Сборка, тесты, архитектура, миграции схемы |

## Требования

- Windows Server 2016+ или Windows 10/11, x64.
- Права администратора для установки и CLI; служба работает от LocalSystem.
- Включённый аудит входа (`auditpol /get /subcategory:"Logon"`) и Windows Firewall.
- Для сборки: .NET SDK 8 или новее.
