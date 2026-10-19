# Решение проблем

Где смотреть в первую очередь:

```powershell
RdpGuard status
Get-EventLog -LogName Application -Source RdpGuard -Newest 30 | Format-Table TimeGenerated, EntryType, EventID, Message -Wrap
Get-Content "$env:ProgramData\RdpGuard\logs\rdpguard.log" -Tail 50
```

## Я заблокировал себя (или коллегу)

С консоли сервера (локальный вход, iLO/iDRAC, консоль гипервизора):

```powershell
RdpGuard unban 203.0.113.7
RdpGuard allow 203.0.113.7 --note "admin home"
```

Если CLI недоступен — снимите все правила RdpGuard; служба в режиме enforcing создаст их заново
в течение минуты, поэтому сначала остановите её:

```powershell
Stop-Service RdpGuard
Get-NetFirewallRule -DisplayName 'RdpGuard-*' | Remove-NetFirewallRule
```

Чтобы это не повторилось, добавьте рабочие адреса (офис, VPN, мониторинг) в `Whitelist:Cidrs` или через `allow`.

## Попыток нет (`Attempts 24h: 0`), хотя атаки идут

1. Аудит входов: `RdpGuard status` → `Logon auditing` должно быть `Success and Failure`.
   Служба включает его сама; если в журнале Application повторяется событие 1008 — аудит выключает
   групповая политика, настройте её (см. [аудит входов](installation.md#аудит-входов)).
   Проверить, какие GPO применяются: `gpresult /h report.html`.

2. Есть ли события:

   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 | Format-List TimeCreated, Message
   ```

3. В 4625 нет адреса (`Source Network Address: -`). Так бывает с RDP при NLA. Тогда адрес берётся
   из события 140 журнала RdpCoreTS — проверьте, что он включён:

   ```powershell
   wevtutil gl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
   ```

   Включить: `wevtutil sl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" /e:true`.

4. Тип входа не 3 и не 10 — см. `Detection:LogonTypes`.

## Баны есть, но атаки не прекращаются

- `RdpGuard status` → `Mode:` — если `DRY RUN`, брандмауэр не меняется ([включение блокировки](installation.md#режим-dryrun-и-включение-блокировки)).
- `Firewall rules: 0` при активных банах — смотрите ошибки 1901 в журнале Application.
- Брандмауэр выключен для активного профиля — `status` покажет `WARNING`; проверьте `Get-NetFirewallProfile`.
- `Scope: RdpPort`, а атака идёт на другой порт (SMB 445) — используйте `AllPorts`.
- Атака идёт с адресов из белого списка (например, через NAT, где весь трафик приходит с одного частного адреса) —
  это видно в `top`. Отключать `TrustPrivateRanges` стоит только если частные адреса действительно недоверенные.

## Служба не запускается

- Ошибка конфигурации: событие 1900 в журнале Application с перечнем неверных параметров;
  то же покажет любая команда CLI, например `RdpGuard status`.
- `Database schema vN is newer than this build supports` — запущена старая версия exe на БД новой версии.
- Запустите в консоли, чтобы увидеть лог: `Stop-Service RdpGuard; RdpGuard run`.

## API не отвечает

| Симптом | Причина |
|---|---|
| Нет соединения | `Api:Enabled = false`; служба слушает только `127.0.0.1` (см. `Api:Urls`); порт закрыт брандмауэром |
| В логе `Statistics API could not start` | Порт занят другим процессом (`netstat -ano | findstr 9645`) или неверный префикс в `Urls` |
| `403 forbidden` | Адрес клиента не в `Api:AllowedClients` |
| `401 unauthorized` | Нет заголовка `Authorization: Bearer …`, токен опечатан или отозван (`RdpGuard api-token list`) |
| `503` | БД ещё не создана (служба ни разу не запускалась) |
| Правило для порта API пропадает | Его имя начинается с `RdpGuard-` — служба удаляет такие правила; назовите `RdpGuard API` |

## Ложные срабатывания

- Пользователь с неверным сохранённым паролем (скрипт, подключённый диск) делает много попыток и банится.
  Найдите адрес в `RdpGuard top`, исправьте источник, затем `RdpGuard unban <ip> --reset`.
- Поднимите `MaxFailures` или увеличьте `FailureWindow`, если порог слишком строгий для вашей среды.

## После очистки журнала Security

Служба замечает, что закладка «впереди» журнала, сбрасывает её (Warning в логе) и продолжает с новых событий.
Ничего делать не нужно.
