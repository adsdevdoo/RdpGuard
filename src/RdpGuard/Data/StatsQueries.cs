namespace RdpGuard.Data;

public sealed record StatsSummary(
    DateTime GeneratedUtc,
    int ActiveBans,
    int PermanentBans,
    long FailedLogons1h,
    long AttackingIps1h,
    long FailedLogons24h,
    long AttackingIps24h,
    long Bans24h,
    long ExternalLogons24h,
    long TrackedIps,
    long WhitelistEntries,
    long TotalBans,
    IReadOnlyDictionary<string, int> ActiveBansByOffense,
    DateTime? LastFailureUtc);

public sealed record TopIpRow(
    string Ip,
    long Attempts,
    long Users,
    DateTime FirstUtc,
    DateTime LastUtc,
    int Offenses,
    bool Banned,
    DateTime? BanExpiresUtc,
    bool BanPermanent,
    IReadOnlyList<UserCount> TopUsers);

public sealed record UserCount(string User, long Attempts, long Ips = 0);

public sealed record TimePoint(DateTime TimeUtc, long Count, long Ips);

/// <summary>Агрегаты для CLI (status/top) и HTTP API.</summary>
public sealed class StatsQueries
{
    private readonly GuardDb _db;
    private readonly Repository _repo;

    public StatsQueries(GuardDb db)
    {
        _db = db;
        _repo = new Repository(db);
    }

    public StatsSummary Summary(DateTime nowUtc)
    {
        var active = _repo.GetActiveBans(nowUtc);
        var byOffense = active
            .GroupBy(b => b.ExpiresAtUtc is null ? "permanent" : b.OffenseNo >= 5 ? "5+" : b.OffenseNo.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .ToDictionary(g => g.Key, g => g.Count());
        foreach (var k in new[] { "1", "2", "3", "4", "5+", "permanent" }) byOffense.TryAdd(k, 0);

        var h1 = DbTime.ToDb(nowUtc.AddHours(-1));
        var h24 = DbTime.ToDb(nowUtc.AddDays(-1));
        return new StatsSummary(
            nowUtc,
            active.Count,
            active.Count(b => b.ExpiresAtUtc is null),
            _db.ScalarLong("SELECT COUNT(*) FROM attempts WHERE ts_utc >= $s", ("$s", h1)),
            _db.ScalarLong("SELECT COUNT(DISTINCT ip) FROM attempts WHERE ts_utc >= $s", ("$s", h1)),
            _db.ScalarLong("SELECT COUNT(*) FROM attempts WHERE ts_utc >= $s", ("$s", h24)),
            _db.ScalarLong("SELECT COUNT(DISTINCT ip) FROM attempts WHERE ts_utc >= $s", ("$s", h24)),
            _db.ScalarLong("SELECT COUNT(*) FROM bans WHERE banned_at_utc >= $s", ("$s", h24)),
            _db.ScalarLong("SELECT COUNT(*) FROM successes WHERE ts_utc >= $s", ("$s", h24)),
            _db.ScalarLong("SELECT COUNT(*) FROM ips"),
            _db.ScalarLong("SELECT COUNT(*) FROM whitelist"),
            _db.ScalarLong("SELECT COUNT(*) FROM bans"),
            byOffense,
            DbTime.FromDbNullable(_db.Scalar("SELECT MAX(ts_utc) FROM attempts")));
    }

    public List<TopIpRow> TopIps(DateTime sinceUtc, int limit, DateTime nowUtc, int usersPerIp = 3)
    {
        var since = DbTime.ToDb(sinceUtc);
        var rows = _db.Query("""
                             SELECT a.ip, COUNT(*) AS n, COUNT(DISTINCT a.user_name), MIN(a.ts_utc), MAX(a.ts_utc), COALESCE(i.offenses, 0)
                             FROM attempts a LEFT JOIN ips i ON i.ip = a.ip
                             WHERE a.ts_utc >= $s
                             GROUP BY a.ip ORDER BY n DESC, a.ip LIMIT $l
                             """,
            r => (Ip: r.GetString(0), N: r.GetInt64(1), Users: r.GetInt64(2), First: DbTime.FromDb(r.GetString(3)),
                Last: DbTime.FromDb(r.GetString(4)), Offenses: r.GetInt32(5)),
            ("$s", since), ("$l", limit));

        var result = new List<TopIpRow>(rows.Count);
        foreach (var row in rows)
        {
            var users = _db.Query("""
                                  SELECT COALESCE(user_name, '?'), COUNT(*) AS n FROM attempts
                                  WHERE ip = $ip AND ts_utc >= $s GROUP BY user_name ORDER BY n DESC LIMIT $l
                                  """, r => new UserCount(r.GetString(0), r.GetInt64(1)),
                ("$ip", row.Ip), ("$s", since), ("$l", usersPerIp));
            var ban = _repo.GetActiveBan(row.Ip, nowUtc);
            result.Add(new TopIpRow(row.Ip, row.N, row.Users, row.First, row.Last, row.Offenses,
                ban is not null, ban?.ExpiresAtUtc, ban is not null && ban.ExpiresAtUtc is null, users));
        }
        return result;
    }

    public List<UserCount> TopUsers(DateTime sinceUtc, int limit) =>
        _db.Query("""
                  SELECT COALESCE(user_name, '?'), COUNT(*) AS n, COUNT(DISTINCT ip) FROM attempts
                  WHERE ts_utc >= $s GROUP BY user_name ORDER BY n DESC LIMIT $l
                  """, r => new UserCount(r.GetString(0), r.GetInt64(1), r.GetInt64(2)),
            ("$s", DbTime.ToDb(sinceUtc)), ("$l", limit));

    /// <summary>Неудачные попытки по интервалам (пустые интервалы заполнены нулями).</summary>
    public List<TimePoint> AttemptsSeries(DateTime sinceUtc, DateTime untilUtc, int stepSeconds) =>
        Series("""
               SELECT (CAST(strftime('%s', ts_utc) AS INTEGER) / $step) * $step AS b, COUNT(*), COUNT(DISTINCT ip)
               FROM attempts WHERE ts_utc >= $s AND ts_utc < $u GROUP BY b
               """, sinceUtc, untilUtc, stepSeconds);

    /// <summary>Новые баны по интервалам.</summary>
    public List<TimePoint> BansSeries(DateTime sinceUtc, DateTime untilUtc, int stepSeconds) =>
        Series("""
               SELECT (CAST(strftime('%s', banned_at_utc) AS INTEGER) / $step) * $step AS b, COUNT(*), COUNT(DISTINCT ip)
               FROM bans WHERE banned_at_utc >= $s AND banned_at_utc < $u GROUP BY b
               """, sinceUtc, untilUtc, stepSeconds);

    private List<TimePoint> Series(string sql, DateTime sinceUtc, DateTime untilUtc, int step)
    {
        var data = _db.Query(sql, r => (Bucket: r.GetInt64(0), N: r.GetInt64(1), Ips: r.GetInt64(2)),
                ("$step", step), ("$s", DbTime.ToDb(sinceUtc)), ("$u", DbTime.ToDb(untilUtc)))
            .ToDictionary(x => x.Bucket);

        long start = new DateTimeOffset(sinceUtc).ToUnixTimeSeconds() / step * step;
        long end = new DateTimeOffset(untilUtc).ToUnixTimeSeconds();
        var points = new List<TimePoint>();
        for (long b = start; b < end; b += step)
        {
            data.TryGetValue(b, out var v);
            points.Add(new TimePoint(DateTimeOffset.FromUnixTimeSeconds(b).UtcDateTime, v.N, v.Ips));
        }
        return points;
    }
}
