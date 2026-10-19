# Grafana и Prometheus

Два способа, можно совмещать:

| | Prometheus + Grafana | Grafana + плагин Infinity |
|---|---|---|
| Источник | `/metrics` | `/api/*` (JSON) |
| История | хранит Prometheus, сколько настроено | из БД RdpGuard (попытки — 30 дней) |
| Сильная сторона | графики, тренды, алерты, несколько серверов | таблицы: топ адресов, активные баны |
| Готовый дашборд | [`grafana/rdpguard-dashboard.json`](../grafana/rdpguard-dashboard.json) | собирается из запросов ниже |

## 1. Подготовка на сервере с RdpGuard

1. Токен (отдельный на каждого потребителя):

   ```powershell
   RdpGuard api-token create prometheus
   ```

2. Если Prometheus работает на другом сервере — открыть API для его адреса
   (подробно — [доступ с другого сервера](api.md#доступ-с-другого-сервера)):

   ```json
   "Api": {
     "Urls": [ "http://+:9645/" ],
     "AllowedClients": [ "10.0.5.20/32" ]
   }
   ```

   ```powershell
   New-NetFirewallRule -DisplayName "RdpGuard API" -Direction Inbound -Protocol TCP -LocalPort 9645 `
       -RemoteAddress 10.0.5.20 -Action Allow
   Restart-Service RdpGuard
   ```

3. Проверить с сервера Prometheus:

   ```bash
   curl -s -H "Authorization: Bearer $(cat /etc/prometheus/rdpguard.token)" http://win-server-01:9645/metrics | head
   ```

## 2. Prometheus

Сохраните токен в файл, доступный только Prometheus (`/etc/prometheus/rdpguard.token`, права 600), и добавьте:

```yaml
scrape_configs:
  - job_name: rdpguard
    scrape_interval: 60s
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/rdpguard.token
    static_configs:
      - targets:
          - win-server-01:9645
          - win-server-02:9645
```

Для HTTPS добавьте `scheme: https` (и `tls_config`, если сертификат не от доверенного центра).
Метка `instance` различает серверы — дашборд использует её в фильтре «Server».

## 3. Дашборд

Grafana → **Dashboards → New → Import** → загрузите `grafana/rdpguard-dashboard.json` → выберите
источник Prometheus.

| Ряд | Панели |
|---|---|
| Overview | Режим (ENFORCING / DRY RUN), активные баны, неудачные входы за час, атакующие IP за сутки, успешные входы извне, ошибки |
| Attacks | Неудачные входы в минуту (4625 / 140), число атакующих адресов |
| Bans | Активные баны по номеру нарушения, новые баны в час, снятые баны по причине, успешные входы извне |
| Health | Заблокировано адресов, правил, время с последней сверки брандмауэра, очередь, БД, аптайм, ошибки |

Полезные запросы для своих панелей:

```promql
# неудачных входов в минуту по серверам
sum by (instance) (rate(rdpguard_failed_logons_total[5m])) * 60

# сколько банов выдано за сутки, по номеру нарушения
sum by (offense) (increase(rdpguard_bans_total[24h]))

# доля повторных нарушителей среди активных банов
sum(rdpguard_active_bans_by_offense{offense!="1"}) / sum(rdpguard_active_bans)
```

## 4. Алерты

```yaml
groups:
  - name: rdpguard
    rules:
      - alert: RdpGuardDown
        expr: up{job="rdpguard"} == 0
        for: 5m
        annotations:
          summary: "RdpGuard API on {{ $labels.instance }} is unreachable"

      - alert: RdpGuardExternalLogon
        expr: increase(rdpguard_external_logons_total{whitelisted="false"}[10m]) > 0
        annotations:
          summary: "Successful logon from an external address on {{ $labels.instance }}"
          description: "Check event 1003 in the Application log. If it was not expected, the password may be compromised."

      - alert: RdpGuardFirewallSyncStale
        expr: rdpguard_dry_run == 0 and time() - rdpguard_firewall_last_sync_timestamp_seconds > 600
        annotations:
          summary: "RdpGuard has not synchronized the firewall for 10 minutes on {{ $labels.instance }}"

      - alert: RdpGuardErrors
        expr: increase(rdpguard_errors_total[15m]) > 0
        annotations:
          summary: "RdpGuard processing errors ({{ $labels.stage }}) on {{ $labels.instance }}"

      - alert: RdpGuardDistributedPasswordGuessing
        expr: rdpguard_account_wrong_password_ips_last_24h >= 3 and rdpguard_account_wrong_passwords_last_24h >= 20
        annotations:
          summary: "Account {{ $labels.account }} on {{ $labels.instance }} is being guessed from many addresses"
          description: "Per-IP bans do not stop distributed guessing. Check the password, rename the account, restrict RDP."

      - alert: RdpGuardLogonAuditingOff
        expr: rdpguard_logon_audit_enabled == 0
        for: 2h
        annotations:
          summary: "Logon auditing ({{ $labels.type }}) is off on {{ $labels.instance }}: RdpGuard cannot see attacks"
          description: "RdpGuard re-enables it hourly; if it stays off, a Group Policy disables Audit Logon."

      - alert: RdpGuardDryRun
        expr: rdpguard_dry_run == 1
        for: 7d
        annotations:
          summary: "RdpGuard on {{ $labels.instance }} is still in DryRun mode"

      - alert: RdpGuardAttackSpike
        expr: rate(rdpguard_failed_logons_total[5m]) * 60 > 500
        for: 10m
        annotations:
          summary: "More than 500 failed logons per minute on {{ $labels.instance }}"
```

## 5. Таблицы через Infinity (JSON API)

Плагин [Infinity](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) читает JSON напрямую.

1. **Connections → Data sources → Add → Infinity.**
2. **Authentication → Bearer Token**, вставьте токен (`RdpGuard api-token create grafana-infinity`).
3. **Allowed hosts:** `http://win-server-01:9645`.
4. Адрес сервера Grafana добавьте в `Api:AllowedClients` на сервере с RdpGuard.

Панели (тип запроса **JSON**, источник **URL**, парсер **Backend**):

| Панель | URL | Визуализация |
|---|---|---|
| Топ атакующих | `http://win-server-01:9645/api/top?hours=24&limit=20` | Table |
| Активные баны | `http://win-server-01:9645/api/bans?active=true&limit=200` | Table |
| Подбираемые имена | `http://win-server-01:9645/api/users?hours=24&limit=20` | Bar chart / Table |
| Попытки по времени | `http://win-server-01:9645/api/timeseries/attempts?hours=24&step=300` | Time series |
| Сводка | `http://win-server-01:9645/api/summary` | Stat |

Для временного ряда задайте колонки: `time` — тип *Timestamp*, `count` и `ips` — *Number*.
API принимает период в часах, а не диапазон дашборда, поэтому удобно завести переменную
дашборда `hours` (Custom: `1,6,24,168`) и подставлять её: `.../api/top?hours=$hours`.
