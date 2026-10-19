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
