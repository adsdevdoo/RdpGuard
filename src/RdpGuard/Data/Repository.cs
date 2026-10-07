using Microsoft.Data.Sqlite;
using RdpGuard.Events;
using RdpGuard.Net;

namespace RdpGuard.Data;

public sealed record IpRow(
    string Ip,
    DateTime FirstSeenUtc,
    DateTime LastSeenUtc,
    long TotalFailures,
    int Offenses,
    DateTime? LastOffenseUtc,
    DateTime? LastSuccessUtc,
    string? Note,
    bool Whitelisted);

public sealed record BanRow(
    long Id,
    string Ip,
    DateTime BannedAtUtc,
    DateTime? ExpiresAtUtc,
    int OffenseNo,
    string? Reason,
    int FailuresInWindow,
    DateTime? UnbannedAtUtc,
    string? UnbanReason)
{
    public bool IsActive(DateTime nowUtc) => UnbannedAtUtc is null && (ExpiresAtUtc is null || ExpiresAtUtc > nowUtc);
}

public sealed record WhitelistRow(string Cidr, DateTime AddedUtc, string? Note);

/// <summary>Все SQL-запросы приложения.</summary>
public sealed class Repository
{
    public const string AdminRevisionKey = "admin_rev";
    public static string BookmarkKey(string channel) => "bookmark:" + channel;

    private const string BanColumns =
        "id, ip, banned_at_utc, expires_at_utc, offense_no, reason, failures_in_window, unbanned_at_utc, unban_reason";

    private const string ActiveBanFilter =
        "unbanned_at_utc IS NULL AND (expires_at_utc IS NULL OR expires_at_utc > $now)";

    public Repository(GuardDb db) => Db = db;

    public GuardDb Db { get; }

    // ---------- ips ----------

    public IpRow? GetIp(string ip) =>
        Db.Query("""
                 SELECT ip, first_seen_utc, last_seen_utc, total_failures, offenses, last_offense_utc,
                        last_success_utc, note, whitelisted
                 FROM ips WHERE ip = $ip
                 """, MapIp, ("$ip", ip)).FirstOrDefault();

    public List<IpRow> GetAllIps() =>
        Db.Query("""
                 SELECT ip, first_seen_utc, last_seen_utc, total_failures, offenses, last_offense_utc,
                        last_success_utc, note, whitelisted
                 FROM ips ORDER BY last_seen_utc DESC
                 """, MapIp);

    private static IpRow MapIp(SqliteDataReader r) => new(
        r.GetString(0),
        DbTime.FromDb(r.GetString(1)),
        DbTime.FromDb(r.GetString(2)),
        r.GetInt64(3),
        r.GetInt32(4),
        DbTime.FromDbNullable(r.GetValue(5)),
        DbTime.FromDbNullable(r.GetValue(6)),
        r.IsDBNull(7) ? null : r.GetString(7),
        r.GetInt64(8) != 0);

    public void TouchIpFailure(string ip, DateTime tsUtc, bool whitelisted) =>
        Db.Exec("""
                INSERT INTO ips(ip, first_seen_utc, last_seen_utc, total_failures, whitelisted)
                VALUES($ip, $ts, $ts, 1, $wl)
                ON CONFLICT(ip) DO UPDATE SET
                    first_seen_utc = MIN(first_seen_utc, excluded.first_seen_utc),
                    last_seen_utc  = MAX(last_seen_utc, excluded.last_seen_utc),
                    total_failures = total_failures + 1,
                    whitelisted    = excluded.whitelisted
                """, ("$ip", ip), ("$ts", DbTime.ToDb(tsUtc)), ("$wl", whitelisted ? 1 : 0));

    public void TouchIpSuccess(string ip, DateTime tsUtc, bool whitelisted) =>
        Db.Exec("""
                INSERT INTO ips(ip, first_seen_utc, last_seen_utc, last_success_utc, whitelisted)
                VALUES($ip, $ts, $ts, $ts, $wl)
                ON CONFLICT(ip) DO UPDATE SET
                    first_seen_utc   = MIN(first_seen_utc, excluded.first_seen_utc),
                    last_seen_utc    = MAX(last_seen_utc, excluded.last_seen_utc),
                    last_success_utc = MAX(COALESCE(last_success_utc, ''), excluded.last_success_utc),
                    whitelisted      = excluded.whitelisted
                """, ("$ip", ip), ("$ts", DbTime.ToDb(tsUtc)), ("$wl", whitelisted ? 1 : 0));

    public void EnsureIp(string ip, DateTime nowUtc) =>
        Db.Exec("""
                INSERT INTO ips(ip, first_seen_utc, last_seen_utc) VALUES($ip, $ts, $ts)
                ON CONFLICT(ip) DO NOTHING
                """, ("$ip", ip), ("$ts", DbTime.ToDb(nowUtc)));

    public void SetOffenses(string ip, int offenses, DateTime? lastOffenseUtc) =>
        Db.Exec("UPDATE ips SET offenses = $n, last_offense_utc = COALESCE($ts, last_offense_utc) WHERE ip = $ip",
            ("$ip", ip), ("$n", offenses), ("$ts", lastOffenseUtc is { } t ? DbTime.ToDb(t) : null));

    public void SetWhitelistedFlag(string ip, bool whitelisted) =>
        Db.Exec("UPDATE ips SET whitelisted = $wl WHERE ip = $ip", ("$ip", ip), ("$wl", whitelisted ? 1 : 0));

    // ---------- attempts / successes ----------

    public void InsertAttempt(AuthEvent e) =>
        Db.Exec("""
                INSERT INTO attempts(ts_utc, ip, user_name, logon_type, event_id, record_id)
                VALUES($ts, $ip, $user, $lt, $eid, $rid)
                """,
            ("$ts", DbTime.ToDb(e.TimeUtc)), ("$ip", e.Ip), ("$user", e.UserName), ("$lt", e.LogonType),
            ("$eid", e.EventId), ("$rid", e.RecordId > 0 ? e.RecordId : null));

    public void InsertSuccess(AuthEvent e) =>
        Db.Exec("""
                INSERT INTO successes(ts_utc, ip, user_name, logon_type, record_id)
                VALUES($ts, $ip, $user, $lt, $rid)
                """,
            ("$ts", DbTime.ToDb(e.TimeUtc)), ("$ip", e.Ip), ("$user", e.UserName), ("$lt", e.LogonType),
            ("$rid", e.RecordId > 0 ? e.RecordId : null));

    /// <summary>Неудачные попытки с IP в интервале (sinceExclusive, untilInclusive].</summary>
    public int CountFailures(string ip, DateTime sinceExclusiveUtc, DateTime untilInclusiveUtc) =>
        (int)Db.ScalarLong("SELECT COUNT(*) FROM attempts WHERE ip = $ip AND ts_utc > $since AND ts_utc <= $until",
            ("$ip", ip), ("$since", DbTime.ToDb(sinceExclusiveUtc)), ("$until", DbTime.ToDb(untilInclusiveUtc)));

    public int PruneAttempts(DateTime cutoffUtc) =>
        Db.Exec("DELETE FROM attempts WHERE ts_utc < $c", ("$c", DbTime.ToDb(cutoffUtc)));

    public int PruneSuccesses(DateTime cutoffUtc) =>
        Db.Exec("DELETE FROM successes WHERE ts_utc < $c", ("$c", DbTime.ToDb(cutoffUtc)));

    // ---------- bans ----------

    private static BanRow MapBan(SqliteDataReader r) => new(
        r.GetInt64(0),
        r.GetString(1),
        DbTime.FromDb(r.GetString(2)),
        DbTime.FromDbNullable(r.GetValue(3)),
        r.GetInt32(4),
        r.IsDBNull(5) ? null : r.GetString(5),
        r.GetInt32(6),
        DbTime.FromDbNullable(r.GetValue(7)),
        r.IsDBNull(8) ? null : r.GetString(8));

    public BanRow? GetActiveBan(string ip, DateTime nowUtc) =>
        Db.Query($"SELECT {BanColumns} FROM bans WHERE ip = $ip AND {ActiveBanFilter} ORDER BY id DESC LIMIT 1",
            MapBan, ("$ip", ip), ("$now", DbTime.ToDb(nowUtc))).FirstOrDefault();

    public List<BanRow> GetActiveBans(DateTime nowUtc) =>
        Db.Query($"SELECT {BanColumns} FROM bans WHERE {ActiveBanFilter} ORDER BY id",
            MapBan, ("$now", DbTime.ToDb(nowUtc)));

    public List<BanRow> GetBans(bool activeOnly, DateTime nowUtc, int limit, string? ip = null)
    {
        var where = new List<string>();
        if (activeOnly) where.Add(ActiveBanFilter);
        if (ip is not null) where.Add("ip = $ip");
        var sql = $"SELECT {BanColumns} FROM bans"
                  + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "")
                  + " ORDER BY id DESC LIMIT $limit";
        return Db.Query(sql, MapBan, ("$now", DbTime.ToDb(nowUtc)), ("$ip", ip), ("$limit", limit));
    }

    public List<BanRow> GetAllBans() => Db.Query($"SELECT {BanColumns} FROM bans ORDER BY id", MapBan);

    public List<string> GetActiveBannedIps(DateTime nowUtc) =>
        Db.Query($"SELECT DISTINCT ip FROM bans WHERE {ActiveBanFilter}", r => r.GetString(0),
            ("$now", DbTime.ToDb(nowUtc)));

    /// <summary>Когда закончился последний бан IP (снят вручную или истёк). Активные баны в будущем отсекаются по nowUtc.</summary>
    public DateTime? GetLastBanEnd(string ip, DateTime nowUtc)
    {
        var v = Db.Scalar("""
                          SELECT MAX(COALESCE(unbanned_at_utc, expires_at_utc)) FROM bans
                          WHERE ip = $ip AND COALESCE(unbanned_at_utc, expires_at_utc) IS NOT NULL
                                AND COALESCE(unbanned_at_utc, expires_at_utc) <= $now
                          """, ("$ip", ip), ("$now", DbTime.ToDb(nowUtc)));
        return DbTime.FromDbNullable(v);
    }

    public long InsertBan(string ip, DateTime bannedAtUtc, DateTime? expiresAtUtc, int offenseNo, string reason, int failuresInWindow) =>
        Db.ScalarLong("""
                      INSERT INTO bans(ip, banned_at_utc, expires_at_utc, offense_no, reason, failures_in_window)
                      VALUES($ip, $at, $exp, $n, $reason, $f);
                      SELECT last_insert_rowid();
                      """,
            ("$ip", ip), ("$at", DbTime.ToDb(bannedAtUtc)), ("$exp", expiresAtUtc is { } e ? DbTime.ToDb(e) : null),
            ("$n", offenseNo), ("$reason", reason), ("$f", failuresInWindow));

    public void Unban(long banId, DateTime unbannedAtUtc, string reason) =>
        Db.Exec("UPDATE bans SET unbanned_at_utc = $t, unban_reason = $r WHERE id = $id AND unbanned_at_utc IS NULL",
            ("$id", banId), ("$t", DbTime.ToDb(unbannedAtUtc)), ("$r", reason));

    /// <summary>Помечает истёкшие баны снятыми (время снятия = время истечения) и возвращает их.</summary>
    public List<BanRow> ExpireBans(DateTime nowUtc)
    {
        var expired = Db.Query($"""
                                SELECT {BanColumns} FROM bans
                                WHERE unbanned_at_utc IS NULL AND expires_at_utc IS NOT NULL AND expires_at_utc <= $now
                                """, MapBan, ("$now", DbTime.ToDb(nowUtc)));
        foreach (var b in expired)
            Db.Exec("UPDATE bans SET unbanned_at_utc = expires_at_utc, unban_reason = 'expired' WHERE id = $id",
                ("$id", b.Id));
        return expired;
    }

    // ---------- whitelist ----------

    public List<WhitelistRow> GetWhitelist() =>
        Db.Query("SELECT cidr, added_utc, note FROM whitelist ORDER BY cidr",
            r => new WhitelistRow(r.GetString(0), DbTime.FromDb(r.GetString(1)), r.IsDBNull(2) ? null : r.GetString(2)));

    public List<IpCidr> GetWhitelistCidrs() =>
        GetWhitelist().Select(w => IpCidr.TryParse(w.Cidr, out var c) ? c : null).OfType<IpCidr>().ToList();

    public void AddWhitelist(string cidr, DateTime nowUtc, string? note) =>
        Db.Exec("""
                INSERT INTO whitelist(cidr, added_utc, note) VALUES($c, $t, $n)
                ON CONFLICT(cidr) DO UPDATE SET note = COALESCE(excluded.note, note)
                """, ("$c", cidr), ("$t", DbTime.ToDb(nowUtc)), ("$n", note));

    public bool RemoveWhitelist(string cidr) => Db.Exec("DELETE FROM whitelist WHERE cidr = $c", ("$c", cidr)) > 0;

    // ---------- state ----------

    public long? GetBookmark(string channel) =>
        long.TryParse(Db.GetState(BookmarkKey(channel)), out var v) ? v : null;

    public void SetBookmark(string channel, long recordId) => Db.SetState(BookmarkKey(channel), recordId.ToString());

    public string? GetAdminRevision() => Db.GetState(AdminRevisionKey);

    /// <summary>CLI увеличивает ревизию — служба замечает изменение и перечитывает белый список / пересобирает правила.</summary>
    public void BumpAdminRevision() =>
        Db.Exec("""
                INSERT INTO state(key, value) VALUES($k, '1')
                ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
                """, ("$k", AdminRevisionKey));
}
