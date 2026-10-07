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
/// Подписка на журналы через EventLogWatcher. Запрос строится как "EventRecordID > закладка" и
/// readExistingEvents = true: watcher сначала отдаёт пропущенные за время простоя события,
/// затем новые — без окна между догрузкой и подпиской.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogAuthSource : IAuthEventSource
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    private readonly GuardOptions _options;
    private readonly ILogger _log;
    private readonly IReadOnlySet<int> _logonTypes;
    private readonly object _gate = new();
    private readonly Dictionary<string, EventLogWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reportedUnavailable = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private ChannelWriter<WorkItem>? _writer;
    private Timer? _retryTimer;
    private bool _disposed;

    public EventLogAuthSource(GuardOptions options, ILogger<EventLogAuthSource> log)
    {
        _options = options;
        _log = log;
        _logonTypes = options.Detection.EffectiveLogonTypes;
    }

    private IEnumerable<string> Channels()
    {
        yield return EventParser.SecurityChannel;
        if (_options.Detection.EnableRdpCoreTs) yield return EventParser.RdpCoreTsChannel;
    }

    public void Start(ChannelWriter<WorkItem> writer, Func<string, long?> getBookmark)
    {
        _writer = writer;
        foreach (var channel in Channels())
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
        lock (_gate)
        {
            if (_disposed || _watchers.ContainsKey(channel)) return;
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
                var xml = BuildQueryXml(channel, from, lookback, _logonTypes, _options.Detection.TrackSuccessfulLogons);
                bool readExisting = from is not null || lookback > 0;

                var query = new EventLogQuery(null, PathType.LogName, xml);
                var watcher = new EventLogWatcher(query, null, readExisting);
                watcher.EventRecordWritten += (_, e) => OnEvent(channel, e);
                watcher.Enabled = true;

                _watchers[channel] = watcher;
                _pending.Remove(channel);
                _reportedUnavailable.Remove(channel);

                if (from is long f)
                    _log.LogInformation("Subscribed to {Channel}, catching up after record {RecordId}", channel, f);
                else if (readExisting)
                    _log.LogInformation("Subscribed to {Channel}, first run: reading the last {Minutes} minutes", channel, lookback);
                else
                    _log.LogInformation("Subscribed to {Channel} (new events only)", channel);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Cannot subscribe to {Channel}; retrying in {Seconds}s", channel, RetryInterval.TotalSeconds);
            }
        }
    }

    private void OnEvent(string channel, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventException is { } error)
            {
                _log.LogWarning(error, "Subscription to {Channel} failed; it will be restarted", channel);
                ScheduleRestart(channel);
                return;
            }

            using var record = e.EventRecord;
            if (record is null) return;

            long recordId = record.RecordId ?? 0;
            var props = record.Properties;
            var values = new object?[props.Count];
            for (int i = 0; i < props.Count; i++) values[i] = props[i].Value;

            var time = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
            var evt = EventParser.Parse(channel, record.Id, recordId, time, values, _logonTypes);

            if (recordId > 0) _lastSeen.AddOrUpdate(channel, recordId, (_, old) => Math.Max(old, recordId));
            _writer?.TryWrite(new RecordWork(channel, recordId, evt));
        }
        catch (Exception ex)
        {
            // Ни одно исключение из колбэка не должно уронить процесс.
            _log.LogError(ex, "Failed to read an event from {Channel}", channel);
        }
    }

    private void ScheduleRestart(string channel)
    {
        EventLogWatcher? watcher;
        lock (_gate)
        {
            if (_disposed || !_watchers.Remove(channel, out watcher)) return;
            _pending.Add(channel);
        }
        // Dispose из колбэка этого же watcher-а может зависнуть — освобождаем в другом потоке.
        _ = Task.Run(() =>
        {
            try
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Error disposing watcher for {Channel}", channel);
            }
        });
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
        EventLogWatcher[] watchers;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            watchers = _watchers.Values.ToArray();
            _watchers.Clear();
        }
        _retryTimer?.Dispose();
        foreach (var w in watchers)
        {
            try
            {
                w.Enabled = false;
                w.Dispose();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Error disposing event log watcher");
            }
        }
    }
}
