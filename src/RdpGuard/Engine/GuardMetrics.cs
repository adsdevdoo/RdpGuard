using System.Collections.Concurrent;
using RdpGuard.Firewall;

namespace RdpGuard.Engine;

/// <summary>Счётчик с одной меткой; значения живут в памяти с момента запуска процесса.</summary>
public sealed class CounterFamily(string name, string help, string label)
{
    private readonly ConcurrentDictionary<string, long> _values = new(StringComparer.Ordinal);

    public string Name { get; } = name;
    public string Help { get; } = help;
    public string Label { get; } = label;

    public void Inc(string labelValue, long by = 1) => _values.AddOrUpdate(labelValue, by, (_, v) => v + by);

    public long Get(string labelValue) => _values.TryGetValue(labelValue, out var v) ? v : 0;

    public IReadOnlyList<KeyValuePair<string, long>> Snapshot() =>
        _values.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToList();

    /// <summary>Чтобы ряд был в Prometheus с нулём ещё до первого события.</summary>
    public CounterFamily WithZero(params string[] labelValues)
    {
        foreach (var v in labelValues) _values.TryAdd(v, 0);
        return this;
    }
}

/// <summary>
/// Метрики работы службы. Движок обновляет их после коммита транзакции,
/// чтобы откатившаяся пачка не попадала в счётчики.
/// </summary>
public sealed class GuardMetrics
{
    public GuardMetrics(TimeProvider? time = null)
    {
        StartedUtc = (time ?? TimeProvider.System).GetUtcNow().UtcDateTime;
    }

    public DateTime StartedUtc { get; }

    public CounterFamily EventsRead { get; } =
        new("rdpguard_events_read_total", "Event log records read, per channel.", "channel");

    public CounterFamily FailedLogons { get; } =
        new CounterFamily("rdpguard_failed_logons_total", "Failed logons recorded (after 4625/140 de-duplication), per event id.", "event_id")
            .WithZero("4625", "140");

    public CounterFamily DuplicateFailures { get; } =
        new CounterFamily("rdpguard_failed_logons_duplicate_total", "Failed logons skipped as 4625/140 duplicates.", "event_id")
            .WithZero("4625", "140");

    public CounterFamily ExternalLogons { get; } =
        new CounterFamily("rdpguard_external_logons_total", "Successful logons from external addresses.", "whitelisted")
            .WithZero("true", "false");

    public CounterFamily Bans { get; } =
        new CounterFamily("rdpguard_bans_total", "Automatic bans issued by this process, per offense number.", "offense")
            .WithZero("1", "2", "3", "4", "5+");

    public CounterFamily Unbans { get; } =
        new CounterFamily("rdpguard_unbans_total", "Bans lifted by this process, per reason.", "reason")
            .WithZero("expired", "successful_logon", "whitelisted");

    public CounterFamily Errors { get; } =
        new CounterFamily("rdpguard_errors_total", "Processing errors, per stage.", "stage")
            .WithZero("event", "batch", "maintenance", "firewall");

    public CounterFamily FirewallSyncs { get; } =
        new CounterFamily("rdpguard_firewall_syncs_total", "Firewall reconciliations, per result.", "result")
            .WithZero("ok", "error");

    private readonly ConcurrentDictionary<string, DateTime> _lastEvent = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, DateTime> LastEventUtc => _lastEvent;

    public void SawEvent(string channel, DateTime eventTimeUtc) =>
        _lastEvent.AddOrUpdate(channel, eventTimeUtc, (_, old) => eventTimeUtc > old ? eventTimeUtc : old);

    public FirewallSyncResult? LastFirewallSync { get; private set; }
    public DateTime? LastFirewallSyncUtc { get; private set; }

    public void FirewallSynced(FirewallSyncResult result, DateTime nowUtc)
    {
        LastFirewallSync = result;
        LastFirewallSyncUtc = nowUtc;
        FirewallSyncs.Inc("ok");
    }

    /// <summary>Последнее известное состояние аудита входов (null — не проверялось или не удалось).</summary>
    public Events.LogonAuditState? LogonAudit { get; set; }

    /// <summary>Длина очереди событий (задаётся службой).</summary>
    public Func<int>? QueueLength { get; set; }

    public IEnumerable<CounterFamily> Counters()
    {
        yield return EventsRead;
        yield return FailedLogons;
        yield return DuplicateFailures;
        yield return ExternalLogons;
        yield return Bans;
        yield return Unbans;
        yield return Errors;
        yield return FirewallSyncs;
    }

    public static string OffenseBucket(int offense) => offense >= 5 ? "5+" : offense.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static string ChannelLabel(string channel) =>
        channel.StartsWith("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", StringComparison.OrdinalIgnoreCase) ? "RdpCoreTS" : channel;
}
