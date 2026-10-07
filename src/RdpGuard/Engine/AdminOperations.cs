using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Net;
using RdpGuard.Policy;

namespace RdpGuard.Engine;

public sealed class AdminException(string message) : Exception(message);

public sealed record ManualBanResult(string Ip, int OffenseNo, DateTime BannedAtUtc, DateTime? ExpiresAtUtc, bool ReplacedExisting);

/// <summary>Ручные операции (CLI): бан, разбан, белый список. Каждая операция — одна транзакция.</summary>
public sealed class AdminOperations
{
    private readonly GuardOptions _options;
    private readonly Repository _repo;
    private readonly BanPolicy _policy;

    public AdminOperations(GuardOptions options, Repository repo)
    {
        _options = options;
        _repo = repo;
        _policy = new BanPolicy(options.Policy);
    }

    public IpWhitelist LoadWhitelist()
    {
        var wl = IpWhitelist.FromOptions(_options.Whitelist);
        wl.SetDynamic(_repo.GetWhitelistCidrs());
        return wl;
    }

    /// <param name="duration">null — по политике (нарастающий срок); permanent — навсегда.</param>
    public ManualBanResult Ban(string ipText, TimeSpan? duration, bool permanent, string? reason, bool force, DateTime nowUtc)
    {
        if (!IpUtil.TryNormalize(ipText, out var address))
            throw new AdminException($"'{ipText}' is not a valid IP address (use 'allow' for networks).");
        var ip = address.ToString();

        if (LoadWhitelist().IsWhitelisted(address, out var matched))
            throw new AdminException($"{ip} is whitelisted ({matched}); remove it with 'disallow' first.");

        using var tx = _repo.Db.Begin(immediate: true);
        var row = _repo.GetIp(ip);
        if (!force && _policy.IsTrustedBySuccess(row?.LastSuccessUtc, nowUtc))
            throw new AdminException(
                $"{ip} had a successful logon at {row!.LastSuccessUtc:u}; use --force to ban it anyway.");

        bool replaced = false;
        if (_repo.GetActiveBan(ip, nowUtc) is { } existing)
        {
            _repo.Unban(existing.Id, nowUtc, "replaced by manual ban");
            replaced = true;
        }

        var lastActivity = Max(row?.LastSeenUtc, _repo.GetLastBanEnd(ip, nowUtc));
        int offense = _policy.NextOffenseNumber(row?.Offenses ?? 0, lastActivity, nowUtc);
        TimeSpan? effective = permanent ? null : duration ?? _policy.GetBanDuration(offense);
        DateTime? expires = effective is { } d ? nowUtc + d : null;

        _repo.EnsureIp(ip, nowUtc);
        _repo.InsertBan(ip, nowUtc, expires, offense, "manual" + (string.IsNullOrWhiteSpace(reason) ? "" : ": " + reason), 0);
        _repo.SetOffenses(ip, offense, nowUtc);
        _repo.BumpAdminRevision();
        tx.Commit();
        return new ManualBanResult(ip, offense, nowUtc, expires, replaced);
    }

    /// <returns>false, если активного бана не было.</returns>
    public bool Unban(string ipText, bool resetOffenses, DateTime nowUtc)
    {
        var ip = IpUtil.Normalize(ipText) ?? throw new AdminException($"'{ipText}' is not a valid IP address.");
        using var tx = _repo.Db.Begin(immediate: true);
        var ban = _repo.GetActiveBan(ip, nowUtc);
        if (ban is not null) _repo.Unban(ban.Id, nowUtc, "manual");
        if (resetOffenses) _repo.SetOffenses(ip, 0, null);
        _repo.BumpAdminRevision();
        tx.Commit();
        return ban is not null;
    }

    /// <returns>Нормализованная запись CIDR и список адресов, с которых снят бан.</returns>
    public (string Cidr, List<string> Unbanned) Allow(string cidrText, string? note, DateTime nowUtc)
    {
        if (!IpCidr.TryParse(cidrText, out var cidr)) throw new AdminException($"'{cidrText}' is not a valid IP or CIDR.");
        if (cidr.PrefixLength == 0) throw new AdminException("Refusing to whitelist the entire address space.");
        var key = cidr.ToString();

        using var tx = _repo.Db.Begin(immediate: true);
        _repo.AddWhitelist(key, nowUtc, note);
        var unbanned = new List<string>();
        foreach (var ban in _repo.GetActiveBans(nowUtc))
        {
            if (!cidr.Contains(IpUtil.Parse(ban.Ip))) continue;
            _repo.Unban(ban.Id, nowUtc, "whitelisted");
            unbanned.Add(ban.Ip);
        }
        foreach (var row in _repo.GetAllIps())
        {
            if (cidr.Contains(IpUtil.Parse(row.Ip))) _repo.SetWhitelistedFlag(row.Ip, true);
        }
        _repo.BumpAdminRevision();
        tx.Commit();
        return (key, unbanned);
    }

    public (string Cidr, bool Removed) Disallow(string cidrText)
    {
        if (!IpCidr.TryParse(cidrText, out var cidr)) throw new AdminException($"'{cidrText}' is not a valid IP or CIDR.");
        var key = cidr.ToString();
        using var tx = _repo.Db.Begin(immediate: true);
        bool removed = _repo.RemoveWhitelist(key);
        if (removed)
        {
            var wl = LoadWhitelist();
            foreach (var row in _repo.GetAllIps())
            {
                if (cidr.Contains(IpUtil.Parse(row.Ip))) _repo.SetWhitelistedFlag(row.Ip, wl.IsWhitelisted(row.Ip));
            }
            _repo.BumpAdminRevision();
        }
        tx.Commit();
        return (key, removed);
    }

    private static DateTime? Max(DateTime? a, DateTime? b) =>
        a is null ? b : b is null ? a : a > b ? a : b;
}
