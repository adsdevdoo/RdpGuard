using System.Security.Principal;
using RdpGuard.Firewall;

namespace RdpGuard.Tests;

/// <summary>
/// Запускается только от администратора и только при RDPGUARD_SYSTEM_TESTS=1:
/// тест меняет настоящий брандмауэр (создаёт и удаляет выключенные правила).
/// </summary>
public sealed class SystemFactAttribute : FactAttribute
{
    public SystemFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("RDPGUARD_SYSTEM_TESTS") != "1")
        {
            Skip = "Set RDPGUARD_SYSTEM_TESTS=1 to run tests against the real Windows Firewall.";
            return;
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "Requires an elevated (Administrator) process.";
    }
}

[Trait("Category", "System")]
public class ComFirewallSystemTests
{
    // 192.0.2.0/24 и 2001:db8::/32 — диапазоны для документации, в интернете не маршрутизируются.
    // Правила создаются выключенными и в любом случае удаляются в finally.
    private static string NewName() => "RdpGuard-SystemTest-" + Guid.NewGuid().ToString("N")[..8];

    private static HashSet<string> Addresses(FirewallRuleInfo rule) =>
        rule.RemoteAddresses
            .Select(a => FirewallAddress.TryNormalizeHost(a, out var ip) ? ip : a)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    [SystemFact]
    public void AddUpdateRemove_AllPortsRule()
    {
        var fw = new ComFirewall();
        var name = NewName();
        try
        {
            fw.AddRule(new FirewallRuleInfo
            {
                Name = name,
                RemoteAddresses = new[] { "192.0.2.1" },
                Enabled = false,
                Description = "RdpGuard system test",
                Grouping = FirewallSync.Grouping,
            });

            var rule = Assert.Single(fw.GetRules(name));
            Assert.Equal(name, rule.Name);
            Assert.False(rule.Enabled);
            Assert.True(rule.Inbound);
            Assert.True(rule.Block);
            Assert.Equal(FirewallConstants.ProtocolAny, rule.Protocol);
            Assert.Equal(FirewallSync.Grouping, rule.Grouping);
            Assert.Equal(new HashSet<string> { "192.0.2.1" }, Addresses(rule));

            fw.SetRemoteAddresses(name, new[] { "192.0.2.1", "192.0.2.2", "2001:db8::1" });
            rule = Assert.Single(fw.GetRules(name));
            Assert.Equal(new HashSet<string> { "192.0.2.1", "192.0.2.2", "2001:db8::1" }, Addresses(rule));
            Assert.False(rule.Enabled);

            fw.RemoveRule(name);
            Assert.Empty(fw.GetRules(name));
        }
        finally
        {
            fw.RemoveRule(name);
        }
    }

    [SystemFact]
    public void AddRule_RdpPortShape_IsReadBack()
    {
        var fw = new ComFirewall();
        var name = NewName();
        try
        {
            fw.AddRule(new FirewallRuleInfo
            {
                Name = name,
                RemoteAddresses = new[] { "192.0.2.10" },
                Protocol = FirewallConstants.ProtocolTcp,
                LocalPorts = "3389",
                Enabled = false,
            });

            var rule = Assert.Single(fw.GetRules(name));
            Assert.Equal(FirewallConstants.ProtocolTcp, rule.Protocol);
            Assert.Equal("3389", rule.LocalPorts);
        }
        finally
        {
            fw.RemoveRule(name);
        }
    }

    [SystemFact]
    public void RemoveRule_DeletesDuplicatesAndIgnoresMissing()
    {
        var fw = new ComFirewall();
        var name = NewName();
        try
        {
            var spec = new FirewallRuleInfo { Name = name, RemoteAddresses = new[] { "192.0.2.20" }, Enabled = false };
            fw.AddRule(spec);
            fw.AddRule(spec);
            Assert.Equal(2, fw.GetRules(name).Count);

            fw.RemoveRule(name);
            Assert.Empty(fw.GetRules(name));
            fw.RemoveRule(name); // повторное удаление не падает
        }
        finally
        {
            fw.RemoveRule(name);
        }
    }

    [SystemFact]
    public void RefusesEmptyAddressList()
    {
        var fw = new ComFirewall();
        var name = NewName();
        Assert.Throws<ArgumentException>(() =>
            fw.AddRule(new FirewallRuleInfo { Name = name, RemoteAddresses = Array.Empty<string>(), Enabled = false }));
        Assert.Empty(fw.GetRules(name));
    }
}

[Trait("Category", "System")]
public class LogonAuditPolicySystemTests
{
    [SystemFact]
    public void Query_ReadsAuditPolicy()
    {
        // Только чтение; включение (EnsureEnabled) не тестируется, чтобы не менять политику машины.
        var state = Events.LogonAuditPolicy.Query();
        Assert.False(string.IsNullOrEmpty(state.ToString()));
    }
}

/// <summary>
/// Источник событий на настоящем журнале: пишем свои события в Application и проверяем,
/// что догрузка и живая подписка вместе отдают каждую запись ровно один раз и по порядку.
/// Регрессия: подписка с условием EventRecordID не получала живых событий вовсе.
/// </summary>
[Trait("Category", "System")]
public class EventLogAuthSourceSystemTests
{
    private const string Source = "RdpGuardSystemTest";

    private static Events.EventLogAuthSource.ChannelSpec Spec() => new(
        "Application",
        (after, lookback) =>
        {
            string range = after is long r ? $" and EventRecordID &gt; {r}" : "";
            return "<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">" +
                   $"*[System[Provider[@Name='{Source}']{range}]]</Select></Query></QueryList>";
        },
        (_, _, _, _, _) => null);

    private static long Write(string message)
    {
        System.Diagnostics.EventLog.WriteEntry(Source, message, System.Diagnostics.EventLogEntryType.Information, 4242);
        var q = new System.Diagnostics.Eventing.Reader.EventLogQuery("Application",
            System.Diagnostics.Eventing.Reader.PathType.LogName, $"*[System[Provider[@Name='{Source}']]]") { ReverseDirection = true };
        using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(q);
        using var newest = reader.ReadEvent();
        return newest!.RecordId!.Value;
    }

    private static async Task<List<long>> Collect(System.Threading.Channels.ChannelReader<Events.WorkItem> reader, int expected)
    {
        var ids = new List<long>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (ids.Count < expected)
        {
            var item = await reader.ReadAsync(cts.Token);
            if (item is Events.RecordWork w) ids.Add(w.RecordId);
        }
        // небольшая пауза: убедиться, что дублей не приходит
        await Task.Delay(1500);
        while (reader.TryRead(out var extra)) if (extra is Events.RecordWork w) ids.Add(w.RecordId);
        return ids;
    }

    [SystemFact]
    public async Task CatchUpThenLive_DeliversEveryRecordOnceInOrder()
    {
        bool created = false;
        if (!System.Diagnostics.EventLog.SourceExists(Source))
        {
            System.Diagnostics.EventLog.CreateEventSource(Source, "Application");
            created = true;
        }
        try
        {
            long before = Write("before start (bookmark)");
            long missed1 = Write("missed while service was down #1");
            long missed2 = Write("missed while service was down #2");

            var options = new Configuration.GuardOptions();
            options.Detection.InitialLookbackMinutes = 0;
            var channel = System.Threading.Channels.Channel.CreateUnbounded<Events.WorkItem>();
            using var source = new Events.EventLogAuthSource(options, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, new[] { Spec() });
            source.Start(channel.Writer, ch => ch == "Application" ? before : null);

            long live1 = Write("live #1");
            await Task.Delay(2000);
            long live2 = Write("live #2 (after catch-up)");

            var ids = await Collect(channel.Reader, 4);
            Assert.Equal(new[] { missed1, missed2, live1, live2 }, ids);
        }
        finally
        {
            if (created) System.Diagnostics.EventLog.DeleteEventSource(Source);
        }
    }
}
