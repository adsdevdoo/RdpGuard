using RdpGuard.Configuration;

namespace RdpGuard.Policy;

/// <summary>Всё, что известно об IP в момент очередной неудачной попытки.</summary>
/// <param name="FailuresInWindow">Неудач в быстром окне FailureWindow (включая текущую).</param>
/// <param name="PreviousOffenses">Сколько раз IP уже банили (ips.offenses).</param>
/// <param name="LastActivityUtc">Когда IP последний раз появлялся или когда закончился его последний бан.</param>
/// <param name="LastSuccessUtc">Последний успешный вход с IP.</param>
/// <param name="SlowFailures">Неудач в длинном окне SlowFailureWindow.</param>
/// <param name="NoSuchUserFailures">Попыток с несуществующим именем в окне NoSuchUserWindow.</param>
/// <param name="WrongPasswordFailures">Неверных паролей к существующим учёткам в окне WrongPasswordWindow.</param>
/// <param name="RecentFailureTimes">Время последних неудач по возрастанию (для детектора «по таймеру»).</param>
/// <param name="BadCredentialFailures">Несуществующее имя или неверный пароль вместе, в окне BadCredentialsWindow.</param>
public sealed record FailureContext(
    DateTime NowUtc,
    int FailuresInWindow,
    int PreviousOffenses,
    DateTime? LastActivityUtc,
    DateTime? LastSuccessUtc,
    bool HasActiveBan,
    bool IsWhitelisted,
    int SlowFailures = 0,
    int NoSuchUserFailures = 0,
    int WrongPasswordFailures = 0,
    IReadOnlyList<DateTime>? RecentFailureTimes = null,
    int BadCredentialFailures = 0);

/// <summary>Какое правило сработало — для причины бана и метрик.</summary>
public static class BanRules
{
    public const string Fast = "fast";
    public const string Slow = "slow";
    public const string NoSuchUser = "no_such_user";
    public const string BadCredentials = "bad_credentials";
    public const string WrongPassword = "wrong_password";
    public const string Periodic = "periodic";
    public const string Manual = "manual";

    public static readonly string[] All = { Fast, Slow, NoSuchUser, WrongPassword, BadCredentials, Periodic };
}

/// <param name="Duration">null — бан навсегда.</param>
/// <param name="Rule">Сработавшее правило (BanRules).</param>
/// <param name="Count">Сколько попыток насчитало сработавшее правило.</param>
public sealed record BanDecision(bool Ban, int OffenseNo, TimeSpan? Duration, string Reason, string? Rule = null, int Count = 0)
{
    public static BanDecision None(string reason) => new(false, 0, null, reason);
}

public sealed class BanPolicy
{
    private readonly PolicyOptions _o;

    public BanPolicy(PolicyOptions options) => _o = options;

    public PolicyOptions Options => _o;

    /// <summary>base * 2^(n-1), не больше потолка; null — навсегда.</summary>
    public TimeSpan? GetBanDuration(int offenseNo)
    {
        if (offenseNo < 1) throw new ArgumentOutOfRangeException(nameof(offenseNo));
        if (_o.PermanentAfterOffenses > 0 && offenseNo > _o.PermanentAfterOffenses) return null;

        // Сдвиг ограничен, чтобы не переполнить long: 2^40 суток уже далеко за любым потолком.
        int shift = Math.Min(offenseNo - 1, 40);
        double ticks = _o.BaseBanDuration.Ticks * Math.Pow(2, shift);
        if (ticks >= _o.MaxBanDuration.Ticks) return _o.MaxBanDuration;
        return TimeSpan.FromTicks((long)ticks);
    }

    /// <summary>Номер нарушения сбрасывается, если IP не появлялся OffenseResetDays дней.</summary>
    public int EffectivePreviousOffenses(int previousOffenses, DateTime? lastActivityUtc, DateTime nowUtc)
    {
        if (_o.OffenseResetDays > 0
            && lastActivityUtc is { } last
            && nowUtc - last >= TimeSpan.FromDays(_o.OffenseResetDays))
        {
            return 0;
        }
        return Math.Max(0, previousOffenses);
    }

    public bool IsTrustedBySuccess(DateTime? lastSuccessUtc, DateTime nowUtc) =>
        _o.SuccessTrustDays > 0
        && lastSuccessUtc is { } s
        && nowUtc - s <= TimeSpan.FromDays(_o.SuccessTrustDays);

    public int NextOffenseNumber(int previousOffenses, DateTime? lastActivityUtc, DateTime nowUtc) =>
        EffectivePreviousOffenses(previousOffenses, lastActivityUtc, nowUtc) + 1;

    public BanDecision Evaluate(FailureContext c)
    {
        if (c.IsWhitelisted) return BanDecision.None("whitelisted");
        if (IsTrustedBySuccess(c.LastSuccessUtc, c.NowUtc)) return BanDecision.None("recent successful logon");
        if (c.HasActiveBan) return BanDecision.None("already banned");

        // Порядок — от самого опасного: причина бана называет первое сработавшее правило.
        (string Rule, int Count, string Reason)? hit = null;
        if (Reached(c.WrongPasswordFailures, _o.WrongPasswordMaxFailures))
            hit = (BanRules.WrongPassword, c.WrongPasswordFailures,
                $"{c.WrongPasswordFailures} wrong passwords for existing accounts within {FormatSpan(_o.WrongPasswordWindow)}");
        else if (Reached(c.NoSuchUserFailures, _o.NoSuchUserMaxFailures))
            hit = (BanRules.NoSuchUser, c.NoSuchUserFailures,
                $"{c.NoSuchUserFailures} logons with non-existent user names within {FormatSpan(_o.NoSuchUserWindow)}");
        else if (Reached(c.BadCredentialFailures, _o.BadCredentialsMaxFailures))
            hit = (BanRules.BadCredentials, c.BadCredentialFailures,
                $"{c.BadCredentialFailures} logons with non-existent users or wrong passwords within {FormatSpan(_o.BadCredentialsWindow)}");
        else if (IsPeriodic(c.RecentFailureTimes, out var interval))
            hit = (BanRules.Periodic, _o.PeriodicMinAttempts,
                $"{_o.PeriodicMinAttempts} failed logons at regular ~{FormatInterval(interval)} intervals (automated)");
        else if (Reached(c.FailuresInWindow, _o.MaxFailures))
            hit = (BanRules.Fast, c.FailuresInWindow,
                $"{c.FailuresInWindow} failed logons within {FormatSpan(_o.FailureWindow)}");
        else if (Reached(c.SlowFailures, _o.SlowMaxFailures))
            hit = (BanRules.Slow, c.SlowFailures,
                $"{c.SlowFailures} failed logons within {FormatSpan(_o.SlowFailureWindow)}");

        if (hit is not { } h) return BanDecision.None("below thresholds");

        int offense = NextOffenseNumber(c.PreviousOffenses, c.LastActivityUtc, c.NowUtc);
        return new BanDecision(true, offense, GetBanDuration(offense), h.Reason, h.Rule, h.Count);
    }

    private static bool Reached(int count, int threshold) => threshold > 0 && count >= threshold;

    /// <summary>
    /// Последние PeriodicMinAttempts попыток идут с почти равными интервалами:
    /// каждый интервал отличается от среднего не больше чем на PeriodicMaxDeviation.
    /// Человек ошибается вразнобой, а скрипт с паузой — по таймеру, даже очень медленно.
    /// </summary>
    public bool IsPeriodic(IReadOnlyList<DateTime>? times, out TimeSpan interval)
    {
        interval = TimeSpan.Zero;
        int n = _o.PeriodicMinAttempts;
        if (n < 3 || times is null || times.Count < n) return false;

        var last = times.Skip(times.Count - n).ToArray();
        var gaps = new double[n - 1];
        for (int i = 1; i < n; i++) gaps[i - 1] = (last[i] - last[i - 1]).TotalSeconds;
        double mean = gaps.Average();
        // Пачки быстрее секунды ловит быстрое окно; здесь интересны паузы.
        if (mean < 1) return false;
        if (gaps.Any(g => Math.Abs(g - mean) / mean > _o.PeriodicMaxDeviation)) return false;
        interval = TimeSpan.FromSeconds(mean);
        return true;
    }

    private static string FormatInterval(TimeSpan t) =>
        t.TotalMinutes >= 1 ? $"{Math.Round(t.TotalMinutes)}m" : $"{Math.Round(t.TotalSeconds)}s";

    /// <summary>Включённые правила одной строкой — для журнала и status.</summary>
    public static string DescribeRules(PolicyOptions p)
    {
        var rules = new List<string>();
        if (p.WrongPasswordMaxFailures > 0) rules.Add($"{p.WrongPasswordMaxFailures} wrong passwords/{FormatSpan(p.WrongPasswordWindow)}");
        if (p.NoSuchUserMaxFailures > 0) rules.Add($"{p.NoSuchUserMaxFailures} unknown users/{FormatSpan(p.NoSuchUserWindow)}");
        if (p.BadCredentialsMaxFailures > 0) rules.Add($"{p.BadCredentialsMaxFailures} bad credentials/{FormatSpan(p.BadCredentialsWindow)}");
        if (p.PeriodicMinAttempts > 0) rules.Add($"{p.PeriodicMinAttempts} at regular intervals");
        if (p.MaxFailures > 0) rules.Add($"{p.MaxFailures}/{FormatSpan(p.FailureWindow)}");
        if (p.SlowMaxFailures > 0) rules.Add($"{p.SlowMaxFailures}/{FormatSpan(p.SlowFailureWindow)}");
        return string.Join(", ", rules);
    }

    public static string FormatSpan(TimeSpan? span)
    {
        if (span is not { } s) return "permanent";
        if (s.TotalDays >= 1 && s.Ticks % TimeSpan.TicksPerDay == 0) return $"{(long)s.TotalDays}d";
        if (s.TotalHours >= 1 && s.Ticks % TimeSpan.TicksPerHour == 0) return $"{(long)s.TotalHours}h";
        if (s.TotalMinutes >= 1 && s.Ticks % TimeSpan.TicksPerMinute == 0) return $"{(long)s.TotalMinutes}m";
        if (s.TotalDays >= 1) return $"{(int)s.TotalDays}d{s.Hours}h{s.Minutes}m";
        if (s.TotalHours >= 1) return $"{(int)s.TotalHours}h{s.Minutes}m";
        return $"{(int)s.TotalMinutes}m{s.Seconds}s";
    }
}
