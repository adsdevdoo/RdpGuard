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

    private readonly Dictionary<string, long> _bookmarks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _logonWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Action> _afterCommit = new();
    private string? _adminRevision;
    private DateTime _lastPrune = DateTime.MinValue;
    private bool _firewallDirty = true;

    public GuardEngine(GuardOptions options, GuardDb db, IFirewall firewall, int rdpPort, TimeProvider time, ILoggerFactory loggers)
    {
        _options = options;
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
            "RdpGuard started. Mode: {Mode}. Active bans: {Active}. Threshold: {Max} failures / {Window}. Database: {Db}",
            _options.DryRun ? "DRY RUN (firewall is not modified)" : "enforcing", active,
            _options.Policy.MaxFailures, BanPolicy.FormatSpan(_options.Policy.FailureWindow), _repo.Db.Path);

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
                _log.LogError(LogEvents.Error, ex, "Failed to process a batch of {Count} item(s)", batch.Count);
            }
        }
    }

    public void ProcessBatch(IReadOnlyList<WorkItem> items)
    {
        var now = Now;
        var ticks = TickKind.None;
        var pendingBookmarks = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
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
                _log.LogError(LogEvents.Error, ex, "Maintenance failed");
            }

            foreach (var (channel, recordId) in pendingBookmarks) _repo.SetBookmark(channel, recordId);
            tx.Commit();
        }

        foreach (var (channel, recordId) in pendingBookmarks) _bookmarks[channel] = recordId;
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
        if (_dedup?.IsDuplicate(e, now) == true)
        {
            _log.LogDebug("Skipping duplicate failure from {Ip} ({Channel} #{RecordId})", e.Ip, e.Channel, e.RecordId);
            return;
        }

        var address = IpUtil.Parse(e.Ip);
        bool whitelisted = _whitelist.IsWhitelisted(address);
        var row = _repo.GetIp(e.Ip);

        _repo.InsertAttempt(e);
        _repo.TouchIpFailure(e.Ip, e.TimeUtc, whitelisted);

        var activeBan = _repo.GetActiveBan(e.Ip, now);
        var lastBanEnd = _repo.GetLastBanEnd(e.Ip, now);

        // Окно не заходит раньше конца предыдущего бана: иначе после ручного разбана
        // старые попытки сразу вызвали бы новый бан.
        var since = e.TimeUtc - _options.Policy.FailureWindow;
        if (lastBanEnd is { } end && end > since) since = end;
        int failures = _repo.CountFailures(e.Ip, since, e.TimeUtc);

        DateTime? lastActivity = Max(row?.LastSeenUtc, lastBanEnd);
        var decision = _policy.Evaluate(new FailureContext(
            e.TimeUtc, failures, row?.Offenses ?? 0, lastActivity, row?.LastSuccessUtc, activeBan is not null, whitelisted));

        if (!decision.Ban)
        {
            if (failures >= _options.Policy.MaxFailures && activeBan is null)
                _log.LogDebug("Not banning {Ip}: {Reason}", e.Ip, decision.Reason);
            return;
        }

        DateTime? expires = decision.Duration is { } d ? now + d : null;
        _repo.InsertBan(e.Ip, now, expires, decision.OffenseNo, decision.Reason, failures);
        _repo.SetOffenses(e.Ip, decision.OffenseNo, now);
        _firewallDirty = true;

        string mode = Mode;
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

        _dedup?.Purge(now);
        // Периодическая сверка: восстанавливает правила, если их удалили или изменили вручную.
        _firewallDirty = true;
    }

    private void ExpireBans(DateTime now)
    {
        var expired = _repo.ExpireBans(now);
        if (expired.Count == 0) return;
        _firewallDirty = true;
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
            if (result.HasChanges)
                _log.LogInformation(LogEvents.FirewallChanged, "Firewall synchronized: {Result}", result);
        }
        catch (Exception ex)
        {
            // Флаг остаётся — повторим на следующем тике.
            _log.LogError(LogEvents.FirewallError, ex, "Firewall synchronization failed; will retry");
        }
    }

    private static DateTime? Max(DateTime? a, DateTime? b) =>
        a is null ? b : b is null ? a : a > b ? a : b;
}
