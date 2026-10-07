using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RdpGuard.Configuration;

namespace RdpGuard.Firewall;

public sealed record FirewallSyncResult(int Added, int Updated, int Removed, int Unchanged, int Rules, int Addresses)
{
    public bool HasChanges => Added + Updated + Removed > 0;
    public override string ToString() =>
        $"{Rules} rule(s), {Addresses} address(es): +{Added} ~{Updated} -{Removed} ={Unchanged}";
}

/// <summary>
/// Приводит правила "RdpGuard-Block-NN" к нужному набору адресов.
/// Адреса, уже стоящие в правиле, остаются в нём; новые занимают свободные места в существующих
/// правилах, затем создаются новые правила. Поэтому изменение одного адреса трогает одно правило.
/// Правила с префиксом "RdpGuard-", которые не нужны, удаляются; прочие правила не трогаются никогда.
/// </summary>
public sealed partial class FirewallSync
{
    public const string ManagedPrefix = "RdpGuard-";
    public const string Grouping = "RdpGuard";
    public const int MaxAddressesPerRuleLimit = 1000;

    [GeneratedRegex(@"^RdpGuard-Block-(\d{1,6})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BlockRuleRegex();

    private readonly IFirewall _firewall;
    private readonly FirewallScope _scope;
    private readonly int _rdpPort;
    private readonly int _capacity;
    private readonly ILogger _log;

    public FirewallSync(IFirewall firewall, FirewallOptions options, int rdpPort, ILogger? log = null)
    {
        _firewall = firewall;
        _scope = options.Scope;
        _rdpPort = rdpPort;
        _capacity = Math.Clamp(options.MaxAddressesPerRule, 1, MaxAddressesPerRuleLimit);
        _log = log ?? NullLogger.Instance;
    }

    public static string BlockRuleName(int index) =>
        "RdpGuard-Block-" + index.ToString("D2", CultureInfo.InvariantCulture);

    private (int Protocol, string? Ports) DesiredShape() => _scope == FirewallScope.RdpPort
        ? (FirewallConstants.ProtocolTcp, _rdpPort.ToString(CultureInfo.InvariantCulture))
        : (FirewallConstants.ProtocolAny, null);

    public FirewallSyncResult Sync(IEnumerable<string> bannedIps)
    {
        var desired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in bannedIps)
        {
            if (FirewallAddress.TryNormalizeHost(ip, out var n)) desired.Add(n);
        }

        var shape = DesiredShape();
        var existing = _firewall.GetRules(ManagedPrefix);

        var chunks = new SortedDictionary<int, List<string>>();
        var existingByIndex = new Dictionary<int, FirewallRuleInfo>();
        var toDelete = new List<string>();
        var assigned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var group in existing.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            var m = BlockRuleRegex().Match(group.Key);
            if (!m.Success
                || group.Count() > 1
                || !int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var index)
                || index < 1
                || existingByIndex.ContainsKey(index))
            {
                // Посторонние правила с нашим префиксом и дубли имён — удалить (дубли пересоздадутся).
                toDelete.Add(group.Key);
                continue;
            }

            var rule = group.First();
            existingByIndex[index] = rule;
            var keep = new List<string>();
            foreach (var token in rule.RemoteAddresses)
            {
                if (keep.Count >= _capacity) break;
                if (FirewallAddress.TryNormalizeHost(token, out var ip) && desired.Contains(ip) && assigned.Add(ip))
                    keep.Add(ip);
            }
            chunks[index] = keep;
        }

        var remaining = new Queue<string>(desired.Where(ip => !assigned.Contains(ip)).OrderBy(ip => ip, StringComparer.Ordinal));
        foreach (var list in chunks.Values)
        {
            while (list.Count < _capacity && remaining.Count > 0) list.Add(remaining.Dequeue());
        }
        int next = 1;
        while (remaining.Count > 0)
        {
            while (chunks.ContainsKey(next)) next++;
            var list = new List<string>(Math.Min(_capacity, remaining.Count));
            while (list.Count < _capacity && remaining.Count > 0) list.Add(remaining.Dequeue());
            chunks[next] = list;
        }

        int added = 0, updated = 0, removed = 0, unchanged = 0, rules = 0;
        var errors = new List<Exception>();

        void Try(string name, Action action)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Firewall operation on rule {Rule} failed", name);
                errors.Add(ex);
            }
        }

        // Сначала удаления: имя удалённого дубля может быть занято заново ниже.
        foreach (var name in toDelete)
        {
            Try(name, () =>
            {
                _firewall.RemoveRule(name);
                removed++;
                _log.LogInformation("Removed firewall rule {Rule} (not managed by the current state)", name);
            });
        }

        foreach (var (index, list) in chunks)
        {
            existingByIndex.TryGetValue(index, out var current);
            if (list.Count == 0)
            {
                if (current is not null) Try(current.Name, () => { _firewall.RemoveRule(current.Name); removed++; });
                continue;
            }

            rules++;
            var name = current?.Name ?? BlockRuleName(index);
            var spec = new FirewallRuleInfo
            {
                Name = name,
                RemoteAddresses = list,
                Protocol = shape.Protocol,
                LocalPorts = shape.Ports,
                Description = "Managed by RdpGuard: blocked brute-force sources. Do not edit.",
                Grouping = Grouping,
            };

            if (current is null)
            {
                Try(name, () => { _firewall.AddRule(spec); added++; });
            }
            else if (!ShapeMatches(current, shape.Protocol, shape.Ports))
            {
                Try(name, () =>
                {
                    _firewall.RemoveRule(current.Name);
                    _firewall.AddRule(spec);
                    updated++;
                });
            }
            else if (!SameAddresses(current.RemoteAddresses, list))
            {
                Try(name, () => { _firewall.SetRemoteAddresses(current.Name, list); updated++; });
            }
            else
            {
                unchanged++;
            }
        }

        if (errors.Count > 0)
            throw new AggregateException("Firewall synchronization finished with errors", errors);

        return new FirewallSyncResult(added, updated, removed, unchanged, rules, desired.Count);
    }

    /// <summary>Удаляет все правила с префиксом RdpGuard- (uninstall).</summary>
    public int RemoveAll()
    {
        int removed = 0;
        foreach (var name in _firewall.GetRules(ManagedPrefix).Select(r => r.Name).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            _firewall.RemoveRule(name);
            removed++;
        }
        return removed;
    }

    private static bool ShapeMatches(FirewallRuleInfo rule, int protocol, string? ports) =>
        rule.Inbound && rule.Block && rule.Enabled
        && rule.Protocol == protocol
        && string.Equals(NormalizePorts(rule.LocalPorts), NormalizePorts(ports), StringComparison.OrdinalIgnoreCase);

    private static string? NormalizePorts(string? ports) =>
        string.IsNullOrWhiteSpace(ports) || ports.Trim() == "*" ? null : ports.Replace(" ", "", StringComparison.Ordinal);

    private static bool SameAddresses(IReadOnlyList<string> current, List<string> wanted)
    {
        if (current.Count != wanted.Count) return false;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in current)
        {
            if (!FirewallAddress.TryNormalizeHost(token, out var ip) || !set.Add(ip)) return false;
        }
        return wanted.All(set.Contains);
    }
}
