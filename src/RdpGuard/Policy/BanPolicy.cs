using RdpGuard.Configuration;

namespace RdpGuard.Policy;

/// <summary>Всё, что известно об IP в момент очередной неудачной попытки.</summary>
/// <param name="FailuresInWindow">Неудачных попыток в текущем окне (включая текущую).</param>
/// <param name="PreviousOffenses">Сколько раз IP уже банили (ips.offenses).</param>
/// <param name="LastActivityUtc">Когда IP последний раз появлялся или когда закончился его последний бан.</param>
/// <param name="LastSuccessUtc">Последний успешный вход с IP.</param>
public sealed record FailureContext(
    DateTime NowUtc,
    int FailuresInWindow,
    int PreviousOffenses,
    DateTime? LastActivityUtc,
    DateTime? LastSuccessUtc,
    bool HasActiveBan,
    bool IsWhitelisted);

/// <param name="Duration">null — бан навсегда.</param>
public sealed record BanDecision(bool Ban, int OffenseNo, TimeSpan? Duration, string Reason)
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
        if (c.FailuresInWindow < _o.MaxFailures) return BanDecision.None("below threshold");

        int offense = NextOffenseNumber(c.PreviousOffenses, c.LastActivityUtc, c.NowUtc);
        var duration = GetBanDuration(offense);
        return new BanDecision(true, offense, duration,
            $"{c.FailuresInWindow} failed logons within {FormatSpan(_o.FailureWindow)}");
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
