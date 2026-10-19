using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using RdpGuard.Configuration;

namespace RdpGuard.Events;

/// <summary>
/// Чтение журналов: новые события — подпиской EventLogWatcher, пропущенные за время простоя —
/// EventLogReader с условием "EventRecordID &gt; закладка".
/// <para>
/// Условие по EventRecordID в подписке Windows применяет только к уже записанным событиям:
/// живые события под него не попадают никогда (проверено на Windows Server 2025). Поэтому подписка
/// строится без него, а догрузка идёт отдельно. Подписка запускается первой; пока идёт догрузка,
/// живые события копятся в буфере и выдаются после неё, без тех, что догрузка уже прочитала.
/// Так нет ни окна, ни дублей, а номера записей в очереди идут по возрастанию — это важно,
/// потому что закладка в БД — максимальный обработанный номер.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogAuthSource : IAuthEventSource
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    /// <param name="BuildQuery">(после записи N или null, глубина первого запуска в минутах) → structured XML query.</param>
    internal sealed record ChannelSpec(string Name, Func<long?, int, string> BuildQuery, Func<string, int, long, DateTime, IReadOnlyList<object?>, AuthEvent?> Parse);

    private sealed class Subscription(string channel)
    {
        public string Channel { get; } = channel;
        public EventLogWatcher? Watcher { get; set; }
        public object Lock { get; } = new();
        public bool CatchingUp { get; set; }
        public List<RecordWork> Buffer { get; } = new();
        public long CatchUpUpper { get; set; }
        public volatile bool Stopped;
    }

    private readonly GuardOptions _options;
    private readonly ILogger _log;
    private readonly Dictionary<string, ChannelSpec> _specs;
    private readonly object _gate = new();
    private readonly Dictionary<string, Subscription> _subscriptions = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reportedUnavailable = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private ChannelWriter<WorkItem>? _writer;
    private Timer? _retryTimer;
    private bool _disposed;

    public EventLogAuthSource(GuardOptions options, ILogger<EventLogAuthSource> log)
        : this(options, log, DefaultChannels(options))
    {
    }

    internal EventLogAuthSource(GuardOptions options, ILogger log, IEnumerable<ChannelSpec> channels)
    {
        _options = options;
        _log = log;
        _specs = channels.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<ChannelSpec> DefaultChannels(GuardOptions options)
    {
        var logonTypes = options.Detection.EffectiveLogonTypes;
        bool success = options.Detection.TrackSuccessfulLogons;
        AuthEvent? Parse(string channel, int id, long recordId, DateTime timeUtc, IReadOnlyList<object?> props) =>
            EventParser.Parse(channel, id, recordId, timeUtc, props, logonTypes);

        yield return new ChannelSpec(EventParser.SecurityChannel,
            (after, lookback) => BuildQueryXml(EventParser.SecurityChannel, after, lookback, logonTypes, success), Parse);
        if (options.Detection.EnableRdpCoreTs)
            yield return new ChannelSpec(EventParser.RdpCoreTsChannel,
                (after, lookback) => BuildQueryXml(EventParser.RdpCoreTsChannel, after, lookback, logonTypes, success), Parse);
    }

    public void Start(ChannelWriter<WorkItem> writer, Func<string, long?> getBookmark)
    {
        _writer = writer;
        foreach (var channel in _specs.Keys)
        {
            if (getBookmark(channel) is long bookmark) _lastSeen[channel] = bookmark;
            TryStart(channel);
        }
        _retryTimer = new Timer(_ => RetryPending(), null, RetryInterval, RetryInterval);
    }

    private void RetryPending()
    {
        string[] channels;
        lock (_gate)
        {
            if (_disposed) return;
            channels = _pending.ToArray();
        }
        foreach (var channel in channels) TryStart(channel);
    }

    private void TryStart(string channel)
    {
        var spec = _specs[channel];
        lock (_gate)
        {
            if (_disposed || _subscriptions.ContainsKey(channel)) return;
            _pending.Add(channel);
            try
            {
                if (!IsChannelAvailable(channel, out var reason))
                {
                    if (_reportedUnavailable.Add(channel))
                    {
                        if (channel == EventParser.SecurityChannel)
                            _log.LogError("Event log {Channel} is not available: {Reason}", channel, reason);
                        else
                            _log.LogInformation("Event log {Channel} is not available ({Reason}); it will be used once enabled", channel, reason);
                    }
                    return;
                }

                long? from = _lastSeen.TryGetValue(channel, out var v) ? v : null;
                from = ValidateBookmark(channel, from);
                int lookback = _options.Detection.InitialLookbackMinutes;
                bool catchUp = from is not null || lookback > 0;

                var subscription = new Subscription(channel) { CatchingUp = catchUp };
                var live = new EventLogQuery(null, PathType.LogName, spec.BuildQuery(null, 0));
                var watcher = new EventLogWatcher(live, null, readExistingEvents: false);
                watcher.EventRecordWritten += (_, e) => OnEvent(subscription, e);
                subscription.Watcher = watcher;
                watcher.Enabled = true;

                _subscriptions[channel] = subscription;
                _pending.Remove(channel);
                _reportedUnavailable.Remove(channel);

                if (!catchUp)
                {
                    _log.LogInformation("Subscribed to {Channel} (new events only)", channel);
                    return;
                }

                if (from is long f)
                    _log.LogInformation("Subscribed to {Channel}, catching up after record {RecordId}", channel, f);
                else
                    _log.LogInformation("Subscribed to {Channel}, first run: reading the last {Minutes} minutes", channel, lookback);
                _ = Task.Run(() => CatchUp(subscription, spec, from, lookback));
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Cannot subscribe to {Channel}; retrying in {Seconds}s", channel, RetryInterval.TotalSeconds);
            }
        }
    }

    /// <summary>Читает пропущенное, затем выдаёт накопленные живые события и переключает подписку в обычный режим.</summary>
    private void CatchUp(Subscription subscription, ChannelSpec spec, long? from, int lookbackMinutes)
    {
        long upper = from ?? 0;
        int count = 0;
        try
        {
            var query = new EventLogQuery(null, PathType.LogName, spec.BuildQuery(from, from is null ? lookbackMinutes : 0));
            using var reader = new EventLogReader(query);
            while (!subscription.Stopped)
            {
                using var record = reader.ReadEvent();
                if (record is null) break;
                var work = ToWork(spec, subscription.Channel, record);
                if (work.RecordId > 0) upper = Math.Max(upper, work.RecordId);
                Write(work);
                count++;
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Catch-up of {Channel} failed after {Count} record(s); continuing with new events", subscription.Channel, count);
        }
        finally
        {
            int buffered;
            lock (subscription.Lock)
            {
                buffered = 0;
                foreach (var work in subscription.Buffer)
                {
                    if (work.RecordId > upper)
                    {
                        Write(work);
                        buffered++;
                    }
                }
                subscription.Buffer.Clear();
                subscription.CatchUpUpper = upper;
                subscription.CatchingUp = false;
            }
            _log.LogInformation("Caught up {Channel}: {Count} missed record(s), {Buffered} new during catch-up; now live",
                subscription.Channel, count, buffered);
        }
    }

    private void OnEvent(Subscription subscription, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventException is { } error)
            {
                _log.LogWarning(error, "Subscription to {Channel} failed; it will be restarted", subscription.Channel);
                ScheduleRestart(subscription);
                return;
            }

            using var record = e.EventRecord;
            if (record is null) return;
            var work = ToWork(_specs[subscription.Channel], subscription.Channel, record);

            lock (subscription.Lock)
            {
                if (subscription.CatchingUp)
                {
                    subscription.Buffer.Add(work);
                    return;
                }
                // Записанное между запуском подписки и концом догрузки догрузка уже прочитала.
                if (work.RecordId > 0 && work.RecordId <= subscription.CatchUpUpper) return;
                Write(work);
            }
        }
        catch (Exception ex)
        {
            // Ни одно исключение из колбэка не должно уронить процесс.
            _log.LogError(ex, "Failed to read an event from {Channel}", subscription.Channel);
        }
    }

    private static RecordWork ToWork(ChannelSpec spec, string channel, EventRecord record)
    {
        long recordId = record.RecordId ?? 0;
        var props = record.Properties;
        var values = new object?[props.Count];
        for (int i = 0; i < props.Count; i++) values[i] = props[i].Value;
        var time = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
        return new RecordWork(channel, recordId, spec.Parse(channel, record.Id, recordId, time, values));
    }

    private void Write(RecordWork work)
    {
        if (work.RecordId > 0) _lastSeen.AddOrUpdate(work.Channel, work.RecordId, (_, old) => Math.Max(old, work.RecordId));
        _writer?.TryWrite(work);
    }

    private void ScheduleRestart(Subscription subscription)
    {
        lock (_gate)
        {
            if (_disposed || !_subscriptions.TryGetValue(subscription.Channel, out var current) || current != subscription) return;
            _subscriptions.Remove(subscription.Channel);
            _pending.Add(subscription.Channel);
        }
        subscription.Stopped = true;
        // Dispose из колбэка этого же watcher-а может зависнуть — освобождаем в другом потоке.
        _ = Task.Run(() => StopWatcher(subscription));
    }

    private void StopWatcher(Subscription subscription)
    {
        try
        {
            if (subscription.Watcher is { } w)
            {
                w.Enabled = false;
                w.Dispose();
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Error disposing watcher for {Channel}", subscription.Channel);
        }
    }

    private static bool IsChannelAvailable(string channel, out string reason)
    {
        try
        {
            using var config = new EventLogConfiguration(channel);
            if (!config.IsEnabled)
            {
                reason = "the log is disabled";
                return false;
            }
            reason = "";
            return true;
        }
        catch (EventLogNotFoundException)
        {
            reason = "the log does not exist";
            return false;
        }
    }

    /// <summary>Если журнал очищен и номера записей начались заново — закладка недействительна.</summary>
    private long? ValidateBookmark(string channel, long? bookmark)
    {
        if (bookmark is null) return null;
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true });
            using var newest = reader.ReadEvent();
            long? newestId = newest?.RecordId;
            if (newestId is null || newestId < bookmark)
            {
                _log.LogWarning(
                    "Bookmark {Bookmark} for {Channel} is ahead of the newest record {Newest} (log cleared?); starting from scratch",
                    bookmark, channel, newestId);
                return null;
            }
        }
        catch (EventLogException ex)
        {
            _log.LogDebug(ex, "Cannot validate bookmark for {Channel}", channel);
        }
        return bookmark;
    }

    /// <summary>
    /// XML-запрос к журналу. С afterRecordId — для догрузки через EventLogReader;
    /// без него и с lookbackMinutes = 0 — для живой подписки (в подписке условие по EventRecordID не работает).
    /// </summary>
    public static string BuildQueryXml(
        string channel, long? afterRecordId, int lookbackMinutes, IReadOnlySet<int> logonTypes, bool includeSuccess)
    {
        string range = afterRecordId is long r
            ? $" and EventRecordID &gt; {r.ToString(CultureInfo.InvariantCulture)}"
            : lookbackMinutes > 0
                ? $" and TimeCreated[timediff(@SystemTime) &lt;= {((long)lookbackMinutes * 60_000).ToString(CultureInfo.InvariantCulture)}]"
                : "";

        string path = SecurityElement.Escape(channel);
        var sb = new StringBuilder();
        sb.Append("<QueryList><Query Id=\"0\" Path=\"").Append(path).Append("\">");

        if (string.Equals(channel, EventParser.SecurityChannel, StringComparison.OrdinalIgnoreCase))
        {
            string types = string.Join(" or ", logonTypes.OrderBy(t => t)
                .Select(t => $"Data[@Name='LogonType']='{t.ToString(CultureInfo.InvariantCulture)}'"));
            AppendSelect(sb, path, $"*[System[(EventID={EventParser.FailedLogonId}){range}]] and *[EventData[{types}]]");
            if (includeSuccess)
                AppendSelect(sb, path, $"*[System[(EventID={EventParser.SuccessfulLogonId}){range}]] and *[EventData[{types}]]");
        }
        else
        {
            AppendSelect(sb, path, $"*[System[(EventID={EventParser.RdpAuthFailedId}){range}]]");
        }

        sb.Append("</Query></QueryList>");
        return sb.ToString();

        static void AppendSelect(StringBuilder sb, string path, string xpath) =>
            sb.Append("<Select Path=\"").Append(path).Append("\">").Append(xpath).Append("</Select>");
    }

    public void Dispose()
    {
        Subscription[] subscriptions;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            subscriptions = _subscriptions.Values.ToArray();
            _subscriptions.Clear();
        }
        _retryTimer?.Dispose();
        foreach (var s in subscriptions)
        {
            s.Stopped = true;
            StopWatcher(s);
        }
    }
}
