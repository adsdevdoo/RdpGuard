using RdpGuard.Configuration;
using RdpGuard.Firewall;

namespace RdpGuard.Tests;

public class FirewallSyncTests
{
    private static FirewallSync Sync(FakeFirewall fw, int perRule = 1000, FirewallScope scope = FirewallScope.AllPorts) =>
        new(fw, new FirewallOptions { MaxAddressesPerRule = perRule, Scope = scope }, 3389);

    private static List<string> Ips(int count, int offset = 0) =>
        Enumerable.Range(offset, count).Select(i => $"203.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}").ToList();

    [Fact]
    public void SplitsIntoRulesOfAtMostThousand()
    {
        var fw = new FakeFirewall();
        var r = Sync(fw).Sync(Ips(2500));

        Assert.Equal(3, r.Added);
        Assert.Equal(new[] { "RdpGuard-Block-01", "RdpGuard-Block-02", "RdpGuard-Block-03" },
            fw.Rules.Select(x => x.Name).OrderBy(x => x));
        Assert.Equal(new[] { 1000, 1000, 500 }, fw.Rules.OrderBy(x => x.Name).Select(x => x.RemoteAddresses.Count));
        Assert.All(fw.Rules, rule =>
        {
            Assert.True(rule.Inbound);
            Assert.True(rule.Block);
            Assert.Equal(FirewallConstants.ProtocolAny, rule.Protocol);
            Assert.Null(rule.LocalPorts);
        });
        Assert.Equal(Ips(2500).ToHashSet(), fw.BlockedAddresses());
    }

    [Fact]
    public void SecondSyncWithSameSet_ChangesNothing()
    {
        var fw = new FakeFirewall();
        var sync = Sync(fw);
        sync.Sync(Ips(2500));
        fw.ResetCounters();

        var r = sync.Sync(Ips(2500));
        Assert.False(r.HasChanges);
        Assert.Equal(3, r.Unchanged);
        Assert.Empty(fw.Touched);
    }

    [Fact]
    public void RemovingOneAddress_RebuildsOnlyItsRule()
    {
        var fw = new FakeFirewall();
        var sync = Sync(fw);
        var ips = Ips(2500);
        sync.Sync(ips);
        var victim = fw.Rules.Single(r => r.Name == "RdpGuard-Block-01").RemoteAddresses[10];
        Assert.True(FirewallAddress.TryNormalizeHost(victim, out var victimIp));
        fw.ResetCounters();

        ips.Remove(victimIp);
        var r = sync.Sync(ips);

        Assert.Equal(1, r.Updated);
        Assert.Equal(new[] { "RdpGuard-Block-01" }, fw.Touched);
        Assert.DoesNotContain(victimIp, fw.BlockedAddresses());
        Assert.Equal(2499, fw.BlockedAddresses().Count);
    }

    [Fact]
    public void NewAddresses_FillFreeSlotsBeforeCreatingRules()
    {
        var fw = new FakeFirewall();
        var sync = Sync(fw);
        var ips = Ips(2500);
        sync.Sync(ips);
        fw.ResetCounters();

        ips.AddRange(Ips(10, offset: 5000));
        var r = sync.Sync(ips);
        Assert.Equal(1, r.Updated);
        Assert.Equal(0, r.Added);
        Assert.Equal(new[] { "RdpGuard-Block-03" }, fw.Touched);
        Assert.Equal(510, fw.Rules.Single(x => x.Name == "RdpGuard-Block-03").RemoteAddresses.Count);
    }

    [Fact]
    public void EmptiedRule_IsDeleted_NeverLeftEmpty()
    {
        var fw = new FakeFirewall();
        var sync = Sync(fw, perRule: 2);
        sync.Sync(new[] { "1.1.1.1", "1.1.1.2", "1.1.1.3" });
        Assert.Equal(2, fw.Rules.Count);

        sync.Sync(new[] { "1.1.1.1", "1.1.1.2" });
        Assert.Single(fw.Rules);
        Assert.All(fw.Rules, r => Assert.NotEmpty(r.RemoteAddresses));

        var r = sync.Sync(Array.Empty<string>());
        Assert.Equal(1, r.Removed);
        Assert.Empty(fw.Rules);
    }

    [Fact]
    public void Reconcile_DeletesUnknownRdpGuardRules_AndNeverTouchesOthers()
    {
        var fw = new FakeFirewall();
        fw.Rules.Add(new FirewallRuleInfo { Name = "Remote Desktop - User Mode (TCP-In)", RemoteAddresses = new[] { "*" }, Block = false });
        fw.Rules.Add(new FirewallRuleInfo { Name = "My custom block", RemoteAddresses = new[] { "9.9.9.9/255.255.255.255" } });
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Old-Style", RemoteAddresses = new[] { "5.5.5.5/255.255.255.255" } });
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Block-07", RemoteAddresses = new[] { "6.6.6.6/255.255.255.255" } });

        var r = Sync(fw).Sync(new[] { "1.2.3.4" });

        // Посторонний RdpGuard-* удалён; RdpGuard-Block-07 переиспользован (адрес не из БД выкинут).
        Assert.Equal(1, r.Removed);
        Assert.Equal(1, r.Updated);
        Assert.Contains(fw.Rules, x => x.Name == "Remote Desktop - User Mode (TCP-In)");
        Assert.Contains(fw.Rules, x => x.Name == "My custom block");
        Assert.DoesNotContain(fw.Rules, x => x.Name == "RdpGuard-Old-Style");
        Assert.Equal(new[] { "1.2.3.4" }, fw.BlockedAddresses());

        // Если адресов нет вовсе — удаляются все правила RdpGuard-*, чужие остаются.
        Sync(fw).Sync(Array.Empty<string>());
        Assert.Equal(new[] { "Remote Desktop - User Mode (TCP-In)", "My custom block" }, fw.Rules.Select(x => x.Name));
    }

    [Fact]
    public void ExistingRuleKeepsItsIndex_WhenItStillHasBannedAddresses()
    {
        var fw = new FakeFirewall();
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Block-05", RemoteAddresses = new[] { "6.6.6.6/255.255.255.255", "7.7.7.7/255.255.255.255" } });

        var r = Sync(fw).Sync(new[] { "6.6.6.6", "8.8.4.4" });

        Assert.Equal(1, r.Updated);
        var rule = Assert.Single(fw.Rules);
        Assert.Equal("RdpGuard-Block-05", rule.Name);
        Assert.Equal(new HashSet<string> { "6.6.6.6", "8.8.4.4" }, fw.BlockedAddresses());
    }

    [Fact]
    public void DuplicateRuleNames_AreRecreated()
    {
        var fw = new FakeFirewall();
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Block-01", RemoteAddresses = new[] { "1.1.1.1" } });
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Block-01", RemoteAddresses = new[] { "2.2.2.2" } });

        Sync(fw).Sync(new[] { "1.1.1.1", "2.2.2.2" });

        var rule = Assert.Single(fw.Rules);
        Assert.Equal(2, rule.RemoteAddresses.Count);
    }

    [Fact]
    public void ScopeChange_RecreatesRulesForRdpPortOnly()
    {
        var fw = new FakeFirewall();
        Sync(fw).Sync(new[] { "1.1.1.1" });
        fw.ResetCounters();

        var r = Sync(fw, scope: FirewallScope.RdpPort).Sync(new[] { "1.1.1.1" });

        Assert.Equal(1, r.Updated);
        var rule = Assert.Single(fw.Rules);
        Assert.Equal(FirewallConstants.ProtocolTcp, rule.Protocol);
        Assert.Equal("3389", rule.LocalPorts);
    }

    [Fact]
    public void ManuallyEditedRule_IsRepaired()
    {
        var fw = new FakeFirewall();
        var sync = Sync(fw);
        sync.Sync(new[] { "1.1.1.1", "2.2.2.2" });
        fw.Rules[0] = fw.Rules[0] with { RemoteAddresses = new[] { "1.1.1.0/255.255.255.0" } };

        sync.Sync(new[] { "1.1.1.1", "2.2.2.2" });
        Assert.Equal(new HashSet<string> { "1.1.1.1", "2.2.2.2" }, fw.BlockedAddresses());
    }

    [Fact]
    public void Ipv6AndIpv4_AreMixedInRules()
    {
        var fw = new FakeFirewall();
        Sync(fw).Sync(new[] { "2001:db8::1", "1.2.3.4", "2001:DB8::1" });
        Assert.Equal(new HashSet<string> { "2001:db8::1", "1.2.3.4" }, fw.BlockedAddresses());
    }

    [Fact]
    public void RemoveAll_DeletesOnlyRdpGuardRules()
    {
        var fw = new FakeFirewall();
        fw.Rules.Add(new FirewallRuleInfo { Name = "Other", RemoteAddresses = new[] { "1.1.1.1" } });
        var sync = Sync(fw);
        sync.Sync(Ips(1500));
        fw.Rules.Add(new FirewallRuleInfo { Name = "RdpGuard-Leftover", RemoteAddresses = new[] { "1.1.1.1" } });

        Assert.Equal(3, sync.RemoveAll());
        Assert.Equal(new[] { "Other" }, fw.Rules.Select(r => r.Name));
    }
}
