using System.Threading.Channels;
using RdpGuard.Events;
using RdpGuard.Firewall;

namespace RdpGuard.Tests;

public sealed class ManualTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public DateTime UtcNow => Now.UtcDateTime;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>Брандмауэр в памяти. Хранит адреса так, как их возвращает настоящий (с маской).</summary>
public sealed class FakeFirewall : IFirewall
{
    public List<FirewallRuleInfo> Rules { get; } = new();
    public int Adds { get; private set; }
    public int Updates { get; private set; }
    public int Removes { get; private set; }
    public List<string> Touched { get; } = new();

    public void ResetCounters()
    {
        Adds = Updates = Removes = 0;
        Touched.Clear();
    }

    public IReadOnlyList<FirewallRuleInfo> GetRules(string namePrefix) =>
        Rules.Where(r => r.Name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)).ToList();

    public void AddRule(FirewallRuleInfo rule)
    {
        if (rule.RemoteAddresses.Count == 0) throw new InvalidOperationException("empty rule would block everything");
        Rules.Add(rule with { RemoteAddresses = rule.RemoteAddresses.Select(AsFirewallReturns).ToList() });
        Adds++;
        Touched.Add(rule.Name);
    }

    public void SetRemoteAddresses(string name, IReadOnlyCollection<string> addresses)
    {
        if (addresses.Count == 0) throw new InvalidOperationException("empty rule would block everything");
        int i = Rules.FindIndex(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (i < 0) throw new InvalidOperationException("no such rule " + name);
        Rules[i] = Rules[i] with { RemoteAddresses = addresses.Select(AsFirewallReturns).ToList() };
        Updates++;
        Touched.Add(name);
    }

    public void RemoveRule(string name)
    {
        Rules.RemoveAll(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        Removes++;
        Touched.Add(name);
    }

    public HashSet<string> BlockedAddresses() =>
        Rules.Where(r => r.Name.StartsWith("RdpGuard-", StringComparison.OrdinalIgnoreCase))
            .SelectMany(r => r.RemoteAddresses)
            .Select(a => FirewallAddress.TryNormalizeHost(a, out var ip) ? ip : a)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    // Так адреса возвращает настоящий брандмауэр (проверено системными тестами).
    private static string AsFirewallReturns(string ip) => ip.Contains(':') ? ip + "-" + ip : ip + "/255.255.255.255";
}

/// <summary>Источник событий для интеграционных тестов: отдаёт заранее заданный поток и закрывает канал.</summary>
public sealed class FakeEventSource(IEnumerable<WorkItem> items, bool complete = true) : IAuthEventSource
{
    public Func<string, long?>? BookmarkProvider { get; private set; }

    public void Start(ChannelWriter<WorkItem> writer, Func<string, long?> getBookmark)
    {
        BookmarkProvider = getBookmark;
        foreach (var item in items) writer.TryWrite(item);
        if (complete) writer.TryComplete();
    }

    public void Dispose()
    {
    }

    private static long _record = 1000;

    public static RecordWork Failure(string ip, DateTime timeUtc, string user = "admin", int eventId = 4625,
        string channel = EventParser.SecurityChannel)
    {
        long id = Interlocked.Increment(ref _record);
        return new RecordWork(channel, id, new AuthEvent(AuthEventKind.Failure, channel, eventId, id, timeUtc, ip, user, 3));
    }

    public static RecordWork Success(string ip, DateTime timeUtc, string user = "alice")
    {
        long id = Interlocked.Increment(ref _record);
        return new RecordWork(EventParser.SecurityChannel, id,
            new AuthEvent(AuthEventKind.Success, EventParser.SecurityChannel, 4624, id, timeUtc, ip, user, 10));
    }
}
