# Установка

## Требования

| | |
|---|---|
| ОС | Windows Server 2016 и новее, Windows 10/11, x64 |
| Права | Администратор (установка, CLI); служба работает от LocalSystem |
| Аудит | Аудит входов (Success и Failure) — `install` включает его сам |
| Брандмауэр | Служба Windows Defender Firewall (MpsSvc) запущена, профили включены |
| Сборка | .NET SDK 8+ (на сервере .NET не нужен — exe self-contained) |

### Аудит входов

Windows пишет события 4625 (неудачный вход) и 4624 (успешный) только при включённом аудите подкатегории
**Logon**. Без 4625 RdpGuard ничего не видит, без 4624 — не отличает своих пользователей от атакующих.

RdpGuard следит за этим сам:

- `install` включает аудит Success и Failure, если он выключен;
- служба проверяет настройку при старте и раз в час и включает её снова, если кто-то её выключил
  (событие 1008 в журнале Application; параметр `Detection:EnsureLogonAuditing`);
- `status` показывает текущее состояние, метрика `rdpguard_logon_audit_enabled` — для алерта.

Проверить вручную:

```powershell
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"
```

> **Групповая политика.** Если аудит задан через GPO (*Computer Configuration → Policies → Windows Settings →
> Security Settings → Advanced Audit Policy Configuration → Logon/Logoff → Audit Logon*), локальная настройка
> откатывается при каждом обновлении политики, и событие 1008 будет повторяться. Тогда включите
> Success и Failure в самой GPO для серверов. Если в GPO задана старая политика категорий
> (*Audit Policy → Audit logon events*), включите и
> *Audit: Force audit policy subcategory settings to override audit policy category settings*.

## Сборка

```powershell
dotnet publish src/RdpGuard -c Release -r win-x64 -o publish
```

В `publish\` появятся:

| Файл | Назначение |
|---|---|
| `RdpGuard.exe` | Служба и CLI, ~35 МБ, всё внутри (включая SQLite) |
| `appsettings.json` | Конфигурация; лежит рядом с exe, чтобы её можно было править |

## Установка службы

1. Скопируйте оба файла в постоянную папку. Служба регистрируется с полным путём к exe.

   ```powershell
   New-Item -ItemType Directory -Force "C:\Program Files\RdpGuard" | Out-Null
   Copy-Item publish\* "C:\Program Files\RdpGuard\"
   ```

2. Установите:

   ```powershell
   & "C:\Program Files\RdpGuard\RdpGuard.exe" install
   ```

   Команда:

   - создаёт БД `%ProgramData%\RdpGuard\rdpguard.db`;
   - оставляет доступ к `%ProgramData%\RdpGuard` только SYSTEM и Administrators (там адреса и имена учётных записей);
   - создаёт источник `RdpGuard` в журнале Application;
   - включает аудит входов (Success и Failure), если он выключен;
   - регистрирует службу `RdpGuard`: LocalSystem, автозапуск, зависимости EventLog и MpsSvc;
   - настраивает перезапуск при сбое: через 5 с, 15 с, 60 с, счётчик сбоев обнуляется через сутки;
   - запускает службу (`--no-start` — не запускать).

   Если служба уже установлена, `install` обновляет её настройки (например, новый путь к exe).

3. Проверьте:

   ```powershell
   RdpGuard status
   ```

## Режим DryRun и включение блокировки

Поставляемый `appsettings.json` содержит `"DryRun": true`. В этом режиме служба читает журналы,
считает попытки и записывает баны в БД, но **не изменяет брандмауэр**. Это время, чтобы убедиться,
что политика не задевает своих.

Что посмотреть за день-два:

```powershell
RdpGuard top --hours 48       # кто атакует, какие имена подбирают
RdpGuard bans --active        # кого бы забанили
```

Если среди банов есть ваши адреса (офис, VPN, мониторинг) — добавьте их в белый список:

```powershell
RdpGuard allow 198.51.100.0/24 --note "office"
```

Частные диапазоны (10/8, 172.16/12, 192.168/16 и т. д.) в белом списке по умолчанию.

Включение блокировки:

1. В `C:\Program Files\RdpGuard\appsettings.json` поставьте `"DryRun": false`.
2. Перезапустите службу:

   ```powershell
   Restart-Service RdpGuard
   ```

При старте служба создаст правила `RdpGuard-Block-NN` для всех активных банов.
`RdpGuard status` покажет `Mode: enforcing` и число заблокированных адресов.

## Обновление

```powershell
Stop-Service RdpGuard
Copy-Item publish\RdpGuard.exe "C:\Program Files\RdpGuard\" -Force
Start-Service RdpGuard
```

`appsettings.json` при обновлении не перезаписывайте — сравните с новым и перенесите добавленные секции.
Схема БД обновляется автоматически при первом запуске новой версии (см. [разработка](development.md#миграции-схемы)).
Откатиться на старую версию после миграции нельзя: старый exe откажется открывать более новую схему.

## Удаление и откат

```powershell
RdpGuard uninstall
```

- останавливает и удаляет службу;
- удаляет **все** правила брандмауэра, имя которых начинается с `RdpGuard-`; прочие правила не затрагиваются;
- оставляет БД и логи в `%ProgramData%\RdpGuard`.

`RdpGuard uninstall --purge` дополнительно удаляет БД, логи и источник журнала событий.

Если exe уже удалён, правила можно снять вручную:

```powershell
Get-NetFirewallRule -DisplayName 'RdpGuard-*' | Remove-NetFirewallRule
```

```powershell
sc.exe delete RdpGuard
```

### Быстро отключить блокировку, не удаляя службу

1. `"DryRun": true` в конфиге, `Restart-Service RdpGuard` — служба перестанет менять брандмауэр.
2. Снимите уже созданные правила:

   ```powershell
   Get-NetFirewallRule -DisplayName 'RdpGuard-*' | Remove-NetFirewallRule
   ```

В DryRun служба не создаёт правила заново.
