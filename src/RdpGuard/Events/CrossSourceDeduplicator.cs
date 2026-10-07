namespace RdpGuard.Events;

/// <summary>
/// Одна неудачная RDP-попытка может дать и 4625 (Security), и 140 (RdpCoreTS).
/// Событие считается дубликатом, если из другого канала уже пришло ещё не сопоставленное
/// событие с того же IP с разницей во времени не больше окна. Сопоставление 1:1.
/// </summary>
public sealed class CrossSourceDeduplicator
{
    private const int MaxEntriesPerIp = 256;
    private static readonly TimeSpan Retention = TimeSpan.FromMinutes(5);

    private readonly TimeSpan _window;
    private readonly Dictionary<string, LinkedList<Entry>> _byIp = new(StringComparer.OrdinalIgnoreCase);

    private sealed class Entry
    {
        public required string Channel;
        public required DateTime EventTimeUtc;
        public required DateTime SeenAtUtc;
        public bool Matched;
    }

    public CrossSourceDeduplicator(TimeSpan window) => _window = window;

    public bool IsDuplicate(AuthEvent e, DateTime nowUtc)
    {
        if (e.Kind != AuthEventKind.Failure || _window <= TimeSpan.Zero) return false;

        if (!_byIp.TryGetValue(e.Ip, out var list))
        {
            list = new LinkedList<Entry>();
            _byIp[e.Ip] = list;
        }

        for (var node = list.First; node != null; node = node.Next)
        {
            var x = node.Value;
            if (!x.Matched
                && !string.Equals(x.Channel, e.Channel, StringComparison.OrdinalIgnoreCase)
                && (x.EventTimeUtc - e.TimeUtc).Duration() <= _window)
            {
                x.Matched = true;
                return true;
            }
        }

        list.AddLast(new Entry { Channel = e.Channel, EventTimeUtc = e.TimeUtc, SeenAtUtc = nowUtc });
        if (list.Count > MaxEntriesPerIp) list.RemoveFirst();
        return false;
    }

    public void Purge(DateTime nowUtc)
    {
        var cutoff = nowUtc - Retention;
        foreach (var ip in _byIp.Keys.ToList())
        {
            var list = _byIp[ip];
            while (list.First is { } first && first.Value.SeenAtUtc < cutoff) list.RemoveFirst();
            if (list.Count == 0) _byIp.Remove(ip);
        }
    }
}
