using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Events;
using RdpGuard.Firewall;
using RdpGuard.Net;
using RdpGuard.Policy;

namespace RdpGuard.Engine;

/// <summary>
/// Единственный писатель в SQLite: читает очередь (события журнала + тики таймера),
/// обрабатывает пачками в одной транзакции и после коммита синхронизирует брандмауэр.
/// </summary>
public sealed class GuardEngine
{
    public const int MaxBatchSize = 1000;
    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan LogonWarningThrottle = TimeSpan.FromHours(1);

    private readonly GuardOptions _options;
    private readonly Repository _repo;
    private readonly FirewallSync _firewall;
    private readonly TimeProvider _time;
    private readonly ILogger _log;
    private readonly ILogger _audit;
    private readonly BanPolicy _policy;
    private readonly IpWhitelist _whitelist;
    private readonly CrossSourceDeduplicator? _dedup;
    private readonly GuardMetrics _metrics;

    private readonly Dictionary<string, long> _bookmarks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _logonWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _accountAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Action> _afterCommit = new();
    private string? _adminRevision;
    private DateTime _lastPrune = DateTime.MinValue;
    private bool _firewallDirty = true;

    public GuardEngine(GuardOptions options, GuardDb db, IFirewall firewall, int rdpPort, TimeProvider time,
        ILoggerFactory loggers, GuardMetrics? metrics = null)
    {
        _options = options;
        _metrics = metrics ?? new GuardMetrics(time);
        _repo = new Repository(db);
        _time = time;
        _log = loggers.CreateLogger("RdpGuard.Engine");
        _audit = loggers.CreateLogger(LogEvents.AuditCategory);
        _policy = new BanPolicy(options.Policy);
        _whitelist = IpWhitelist.FromOptions(options.Whitelist);
        _firewall = new FirewallSync(firewall, options.Firewall, rdpPort, loggers.CreateLogger("RdpGuard.Firewall"));
        if (options.Detection.EnableRdpCoreTs && options.Detection.RdpCoreTsDedupSeconds > 0)
            _dedup = new CrossSourceDeduplicator(TimeSpan.FromSeconds(options.Detection.RdpCoreTsDedupSeconds));
    }

    private DateTime Now => _time.GetUtcNow().UtcDateTime;
    private string Mode => _options.DryRun ? "[DryRun] " : "";

    public Repository Repository => _repo;
    public GuardMetrics Metrics => _metrics;

    /// <summary>Подготовка при старте: белый список, истёкшие баны, сверка брандмауэра с БД.</summary>
    public void Initialize()
    {
        var now = Now;
        ReloadWhitelist();
        _adminRevision = _repo.GetAdminRevision();

        foreach (var channel in new[] { EventParser.SecurityChannel, EventParser.RdpCoreTsChannel })
        {
            if (_repo.GetBookmark(channel) is long b) _bookmarks[channel] = b;
        }

        using (var tx = _repo.Db.Begin())
        {
            ExpireBans(now);
            LiftWhitelistedBans(now);
            tx.Commit();
        }
        FlushAfterCommit();

        int active = _repo.GetActiveBannedIps(now).Count;
        _audit.LogInformation(LogEvents.Started,
            "RdpGuard started. Mode: {Mode}. Active bans: {Active}. Ban rules: {Rules}. Database: {Db}",
            _options.DryRun ? "DRY RUN (firewall is not modified)" : "enforcing", active,
            BanPolicy.DescribeRules(_options.Policy), _repo.Db.Path);

        _firewallDirty = true;
        SyncFirewall();
    }

    public long? GetBookmark(string channel) => _bookmarks.TryGetValue(channel, out var v) ? v : null;

    public async Task RunAsync(ChannelReader<WorkItem> reader, CancellationToken ct = default)
    {
        var batch = new List<WorkItem>(256);
        while (await reader.WaitToReadAsync(ct).ConfigureAwait(false))
        {
            batch.Clear();
            while (batch.Count < MaxBatchSize && reader.TryRead(out var item)) batch.Add(item);
            try
            {
                ProcessBatch(batch);
            }
            catch (Exception ex)
            {
                _metrics.Errors.Inc("batch");
                _log.LogError(LogEvents.Error, ex, "Failed to process a batch of {Count} item(s)", batch.Count);
            }
        }
    }

    public void ProcessBatch(IReadOnlyList<WorkItem> items)
    {
        var now = Now;
        var ticks = TickKind.None;
        var pendingBookmarks = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var readPerChannel = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        _afterCommit.Clear();

        using (var tx = _repo.Db.Begin())
        {
            foreach (var item in items)
            {
                try
                {
                    switch (item)
                    {
                        case RecordWork r:
                            readPerChannel[r.Channel] = readPerChannel.GetValueOrDefault(r.Channel) + 1;
                            if (r.RecordId > 0)
                            {
                                long prev = pendingBookmarks.TryGetValue(r.Channel, out var p) ? p : GetBookmark(r.Channel) ?? 0;
                                if (r.RecordId > prev) pendingBookmarks[r.Channel] = r.RecordId;
                            }
                            if (r.Event is { } e) HandleEvent(e, now);
                            break;
                        case TickWork t:
                            ticks |= t.Kind;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Ошибка одного события не должна останавливать обработку остальных.
                    _metrics.Errors.Inc("event");
                    _log.LogError(LogEvents.Error, ex, "Failed to process {Item}", item);
                }
            }

            try
            {
                if (ticks.HasFlag(TickKind.Quick) || ticks.HasFlag(TickKind.Maintenance)) CheckAdminChanges();
                if (ticks.HasFlag(TickKind.Maintenance)) RunMaintenance(now);
            }
            catch (Exception ex)
            {
                _metrics.Errors.Inc("maintenance");
                _log.LogError(LogEvents.Error, ex, "Maintenance failed");
            }

            foreach (var (channel, recordId) in pendingBookmarks) _repo.SetBookmark(channel, recordId);
            tx.Commit();
        }

        foreach (var (channel, recordId) in pendingBookmarks) _bookmarks[channel] = recordId;
        foreach (var (channel, count) in readPerChannel) _metrics.EventsRead.Inc(GuardMetrics.ChannelLabel(channel), count);
        FlushAfterCommit();

        if (_firewallDirty) SyncFirewall();
    }

    private void FlushAfterCommit()
    {
        foreach (var action in _afterCommit)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Logging failed");
            }
        }
        _afterCommit.Clear();
    }

    private void HandleEvent(AuthEvent e, DateTime now)
    {
        if (e.Kind == AuthEventKind.Failure) HandleFailure(e, now);
        else HandleSuccess(e, now);
    }

    private void HandleFailure(AuthEvent e, DateTime now)
    {
        var address = IpUtil.Parse(e.Ip);
        bool whitelisted = _whitelist.IsWhitelisted(address);

        if (_dedup?.Match(e) is { } duplicate)
        {
            _afterCommit.Add(() => _metrics.DuplicateFailures.Inc(e.EventId.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            // 140 пришло раньше и записано без имени и кода причины: дополняем его данными из 4625
            // и проверяем правила заново — иначе «несуществующее имя» и «неверный пароль» не увидят попытку.
            if (e.EventId == EventParser.FailedLogonId && duplicate.AttemptId is long attemptId)
            {
                _repo.UpgradeAttempt(attemptId, e);
                EvaluateFailure(e, now, _repo.GetIp(e.Ip), whitelisted);
            }
            else
            {
                _log.LogDebug("Skipping duplicate failure from {Ip} ({Channel} #{RecordId})", e.Ip, e.Channel, e.RecordId);
            }
            return;
        }

        var row = _repo.GetIp(e.Ip);
        long attempt = _repo.InsertAttempt(e);
        _dedup?.Register(e, now, attempt);
        _repo.TouchIpFailure(e.Ip, e.TimeUtc, whitelisted);
        _afterCommit.Add(() =>
        {
            _metrics.FailedLogons.Inc(e.EventId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            _metrics.SawEvent(GuardMetrics.ChannelLabel(e.Channel), e.TimeUtc);
        });

        EvaluateFailure(e, now, row, whitelisted);
    }

    /// <summary>Проверяет правила для адреса после записи (или дополнения) попытки.</summary>
    private void EvaluateFailure(AuthEvent e, DateTime now, IpRow? row, bool whitelisted)
    {
        // Белый список и уже забаненные: попытку записали, считать окна незачем.
        if (whitelisted || _repo.GetActiveBan(e.Ip, now) is not null) return;
        if (_policy.IsTrustedBySuccess(row?.LastSuccessUtc, e.TimeUtc)) return;

        var p = _options.Policy;
        var lastBanEnd = _repo.GetLastBanEnd(e.Ip, now);

        // Окна не заходят раньше конца предыдущего бана: иначе после разбана
        // старые попытки сразу вызвали бы новый бан.
        DateTime Since(TimeSpan window)
        {
            var since = e.TimeUtc - window;
            return lastBanEnd is { } end && end > since ? end : since;
        }

        var stats = _repo.GetFailureStats(e.Ip, e.TimeUtc, Since(p.FailureWindow), Since(p.SlowFailureWindow),
            Since(p.NoSuchUserWindow), Since(p.WrongPasswordWindow), Since(p.BadCredentialsWindow));
        var recent = p.PeriodicMinAttempts >= 3
            ? _repo.GetRecentFailureTimes(e.Ip, Since(p.PeriodicWindow), e.TimeUtc, p.PeriodicMinAttempts)
            : null;

        DateTime? lastActivity = Max(row?.LastSeenUtc, lastBanEnd);
        var decision = _policy.Evaluate(new FailureContext(
            e.TimeUtc, stats.Fast, row?.Offenses ?? 0, lastActivity, row?.LastSuccessUtc, HasActiveBan: false, IsWhitelisted: false,
            stats.Slow, stats.NoSuchUser, stats.WrongPassword, recent, stats.BadCredentials));

        if (!decision.Ban) return;

        DateTime? expires = decision.Duration is { } d ? now + d : null;
        _repo.InsertBan(e.Ip, now, expires, decision.OffenseNo, decision.Reason, decision.Count);
        _repo.SetOffenses(e.Ip, decision.OffenseNo, now);
        _firewallDirty = true;

        string mode = Mode;
        _afterCommit.Add(() =>
        {
            _metrics.Bans.Inc(GuardMetrics.OffenseBucket(decision.OffenseNo));
            _metrics.BanTriggers.Inc(decision.Rule ?? "unknown");
        });
        _afterCommit.Add(() => _audit.LogWarning(LogEvents.Ban,
            "{Mode}Banned {Ip}: offense #{Offense}, duration {Duration}, until {Expires}. {Reason}. Last user: {User}",
            mode, e.Ip, decision.OffenseNo, BanPolicy.FormatSpan(decision.Duration),
            expires is { } x ? DbTime.ToDb(x) + " UTC" : "forever", decision.Reason, e.UserName ?? "-"));
    }

    private void HandleSuccess(AuthEvent e, DateTime now)
    {
        if (!_options.Detection.TrackSuccessfulLogons) return;
        var address = IpUtil.Parse(e.Ip);
        if (IpWhitelist.IsPrivate(address)) return; // интересуют только внешние адреса

        bool whitelisted = _whitelist.IsWhitelisted(address);
        _repo.InsertSuccess(e);
        _repo.TouchIpSuccess(e.Ip, e.TimeUtc, whitelisted);
        _afterCommit.Add(() =>
        {
            _metrics.ExternalLogons.Inc(whitelisted ? "true" : "false");
            _metrics.SawEvent(GuardMetrics.ChannelLabel(e.Channel), e.TimeUtc);
        });

        string key = e.Ip + "|" + e.UserName;
        if (!_logonWarnings.TryGetValue(key, out var last) || now - last >= LogonWarningThrottle)
        {
            _logonWarnings[key] = now;
            var level = whitelisted ? LogLevel.Information : LogLevel.Warning;
            _afterCommit.Add(() => _audit.Log(level, LogEvents.ExternalLogon,
                "Successful logon from external address {Ip}: user {User}, logon type {LogonType}",
                e.Ip, e.UserName ?? "-", e.LogonType));
        }

        if (_options.Policy.SuccessfulLogonLiftsBan && _repo.GetActiveBan(e.Ip, now) is { } ban)
        {
            _repo.Unban(ban.Id, now, "successful logon");
            _firewallDirty = true;
            _afterCommit.Add(() => _metrics.Unbans.Inc("successful_logon"));
            string mode = Mode;
            _afterCommit.Add(() => _audit.LogWarning(LogEvents.Unban,
                "{Mode}Unbanned {Ip}: successful logon by user {User}", mode, e.Ip, e.UserName ?? "-"));
        }
    }

    private void CheckAdminChanges()
    {
        var revision = _repo.GetAdminRevision();
        if (revision == _adminRevision) return;
        _adminRevision = revision;
        ReloadWhitelist();
        _firewallDirty = true;
        _log.LogInformation("Changes made with the CLI detected; reloading whitelist and firewall rules");
    }

    private void RunMaintenance(DateTime now)
    {
        ExpireBans(now);
        LiftWhitelistedBans(now);

        if (now - _lastPrune >= PruneInterval)
        {
            _lastPrune = now;
            var cutoff = now - TimeSpan.FromDays(_options.Storage.AttemptRetentionDays);
            int a = _repo.PruneAttempts(cutoff);
            int s = _repo.PruneSuccesses(cutoff);
            if (a + s > 0) _log.LogInformation("Pruned {Attempts} attempt(s) and {Successes} logon record(s) older than {Cutoff:u}", a, s, cutoff);
            foreach (var key in _logonWarnings.Where(kv => now - kv.Value >= LogonWarningThrottle).Select(kv => kv.Key).ToList())
                _logonWarnings.Remove(key);
        }

        CheckAccountAttacks(now);
        _dedup?.Purge(now);
        // Периодическая сверка: восстанавливает правила, если их удалили или изменили вручную.
        _firewallDirty = true;
    }

    /// <summary>
    /// Распределённый подбор: одну учётку атакуют понемногу со многих адресов, и бан по IP не срабатывает.
    /// Не банит, а предупреждает (событие 1009) не чаще раза в сутки на учётку.
    /// </summary>
    private void CheckAccountAttacks(DateTime now)
    {
        var p = _options.Policy;
        if (p.AccountAlertWrongPasswords <= 0) return;
        foreach (var a in _repo.GetWrongPasswordsByAccount(now.AddDays(-1), 50))
        {
            if (a.WrongPasswords < p.AccountAlertWrongPasswords || a.Ips < p.AccountAlertMinIps) continue;
            if (_accountAlerts.TryGetValue(a.User, out var last) && now - last < TimeSpan.FromDays(1)) continue;
            _accountAlerts[a.User] = now;
            _afterCommit.Add(() => _audit.LogWarning(LogEvents.AccountAttack,
                "Account {User} received {Count} wrong passwords from {Ips} different addresses within 24h: " +
                "possible distributed password guessing. Make sure the password is strong; consider renaming the account " +
                "or allowing RDP only via VPN.", a.User, a.WrongPasswords, a.Ips));
        }
    }

    private void ExpireBans(DateTime now)
    {
        var expired = _repo.ExpireBans(now);
        if (expired.Count == 0) return;
        _firewallDirty = true;
        _afterCommit.Add(() => _metrics.Unbans.Inc("expired", expired.Count));
        string mode = Mode;
        foreach (var b in expired)
        {
            _afterCommit.Add(() => _audit.LogInformation(LogEvents.Unban,
                "{Mode}Unbanned {Ip}: ban #{Offense} expired (banned {BannedAt} UTC)",
                mode, b.Ip, b.OffenseNo, DbTime.ToDb(b.BannedAtUtc)));
        }
    }

    /// <summary>Если адрес попал в белый список уже после бана — бан снимается.</summary>
    private void LiftWhitelistedBans(DateTime now)
    {
        foreach (var ban in _repo.GetActiveBans(now))
        {
            if (!_whitelist.IsWhitelisted(ban.Ip)) continue;
            _repo.Unban(ban.Id, now, "whitelisted");
            _firewallDirty = true;
            _afterCommit.Add(() => _metrics.Unbans.Inc("whitelisted"));
            string mode = Mode;
            _afterCommit.Add(() => _audit.LogWarning(LogEvents.Unban, "{Mode}Unbanned {Ip}: address is whitelisted", mode, ban.Ip));
        }
    }

    private void ReloadWhitelist()
    {
        try
        {
            _whitelist.SetDynamic(_repo.GetWhitelistCidrs());
        }
        catch (Exception ex)
        {
            _log.LogError(LogEvents.Error, ex, "Failed to load the whitelist from the database");
        }
    }

    private void SyncFirewall()
    {
        if (_options.DryRun)
        {
            _firewallDirty = false;
            return;
        }

        try
        {
            var ips = _repo.GetActiveBannedIps(Now).Where(ip => !_whitelist.IsWhitelisted(ip)).ToList();
            var result = _firewall.Sync(ips);
            _firewallDirty = false;
            _metrics.FirewallSynced(result, Now);
            if (result.HasChanges)
                _log.LogInformation(LogEvents.FirewallChanged, "Firewall synchronized: {Result}", result);
        }
        catch (Exception ex)
        {
            // Флаг остаётся — повторим на следующем тике.
            _metrics.FirewallSyncs.Inc("error");
            _metrics.Errors.Inc("firewall");
            _log.LogError(LogEvents.FirewallError, ex, "Firewall synchronization failed; will retry");
        }
    }

    private static DateTime? Max(DateTime? a, DateTime? b) =>
        a is null ? b : b is null ? a : a > b ? a : b;
}
