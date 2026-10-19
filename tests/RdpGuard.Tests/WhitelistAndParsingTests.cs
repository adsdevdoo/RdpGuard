using RdpGuard.Configuration;
using RdpGuard.Events;
using RdpGuard.Firewall;
using RdpGuard.Net;

namespace RdpGuard.Tests;

public class WhitelistTests
{
    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.10.20", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("100.127.255.255", true)]
    [InlineData("100.128.0.1", false)]
    [InlineData("::1", true)]
    [InlineData("fe80::1234", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("fc00::1", true)]
    [InlineData("::ffff:10.0.0.1", true)] // IPv4-mapped
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:db8::1", false)]
    public void PrivateRanges(string ip, bool expected)
    {
        var wl = new IpWhitelist(trustPrivateRanges: true, Array.Empty<string>());
        Assert.Equal(expected, wl.IsWhitelisted(IpUtil.Parse(ip)));
    }

    [Fact]
    public void PrivateRanges_CanBeDisabled()
    {
        var wl = new IpWhitelist(trustPrivateRanges: false, Array.Empty<string>());
        Assert.False(wl.IsWhitelisted(IpUtil.Parse("10.0.0.1")));
    }

    [Fact]
    public void ConfigCidrs_AndDynamicEntries()
    {
        var wl = new IpWhitelist(false, new[] { "203.0.113.0/24", "2001:db8:abcd::/48" });
        Assert.True(wl.IsWhitelisted(IpUtil.Parse("203.0.113.77")));
        Assert.False(wl.IsWhitelisted(IpUtil.Parse("203.0.114.1")));
        Assert.True(wl.IsWhitelisted(IpUtil.Parse("2001:db8:abcd:1::5")));
        Assert.False(wl.IsWhitelisted(IpUtil.Parse("2001:db8:abce::5")));

        Assert.False(wl.IsWhitelisted(IpUtil.Parse("198.51.100.9")));
        wl.SetDynamic(new[] { IpCidr.Parse("198.51.100.9") });
        Assert.True(wl.IsWhitelisted(IpUtil.Parse("198.51.100.9")));
    }

    [Theory]
    [InlineData("10.1.2.3/8", "10.0.0.0/8")]
    [InlineData("192.168.1.77/24", "192.168.1.0/24")]
    [InlineData("1.2.3.4", "1.2.3.4/32")]
    [InlineData("2001:db8::1/32", "2001:db8::/32")]
    [InlineData("100.64.0.0/10", "100.64.0.0/10")]
    public void Cidr_MasksHostBits(string input, string expected)
    {
        Assert.Equal(expected, IpCidr.Parse(input).ToString());
    }

    [Theory]
    [InlineData("1.2.3.4/33")]
    [InlineData("1.2.3/24")]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("::1/129")]
    public void Cidr_RejectsInvalid(string input)
    {
        Assert.False(IpCidr.TryParse(input, out _));
    }

    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4")]
    [InlineData(" 1.2.3.4 ", "1.2.3.4")]
    [InlineData("::ffff:1.2.3.4", "1.2.3.4")]
    [InlineData("fe80::1%12", "fe80::1")]
    [InlineData("2001:DB8::1", "2001:db8::1")]
    [InlineData("-", null)]
    [InlineData("", null)]
    [InlineData("0.0.0.0", null)]
    [InlineData("::", null)]
    [InlineData("1.2", null)]
    public void IpNormalization(string input, string? expected)
    {
        Assert.Equal(expected, IpUtil.Normalize(input));
    }

    [Theory]
    [InlineData("1.2.3.4/255.255.255.255", "1.2.3.4")]
    [InlineData("1.2.3.4/32", "1.2.3.4")]
    [InlineData("2001:db8::1/128", "2001:db8::1")]
    [InlineData("1.2.3.4", "1.2.3.4")]
    [InlineData("1.2.3.0/255.255.255.0", null)]
    [InlineData("2001:db8::1-2001:db8::1", "2001:db8::1")] // так брандмауэр возвращает одиночный IPv6
    [InlineData("1.2.3.4-1.2.3.4", "1.2.3.4")]
    [InlineData("1.2.3.4-1.2.3.9", null)]
    [InlineData("*", null)]
    public void FirewallAddressNormalization(string token, string? expected)
    {
        bool ok = FirewallAddress.TryNormalizeHost(token, out var ip);
        Assert.Equal(expected is not null, ok);
        if (expected is not null) Assert.Equal(expected, ip);
    }
}

public class EventParserTests
{
    private static readonly IReadOnlySet<int> Types = new DetectionOptions().EffectiveLogonTypes;
    private static readonly DateTime T = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static object?[] Props4625(string ip, object logonType, string user = "administrator")
    {
        var p = new object?[21];
        for (int i = 0; i < p.Length; i++) p[i] = "-";
        p[5] = user;
        p[10] = logonType;
        p[19] = ip;
        p[20] = "0";
        return p;
    }

    private static object?[] Props4624(string ip, object logonType, string user = "alice")
    {
        var p = new object?[27];
        for (int i = 0; i < p.Length; i++) p[i] = "-";
        p[5] = user;
        p[8] = logonType;
        p[18] = ip;
        return p;
    }

    [Fact]
    public void Parses4625_ByPosition()
    {
        var e = EventParser.Parse("Security", 4625, 42, T, Props4625("203.0.113.5", 3u), Types);
        Assert.NotNull(e);
        Assert.Equal(AuthEventKind.Failure, e!.Kind);
        Assert.Equal("203.0.113.5", e.Ip);
        Assert.Equal("administrator", e.UserName);
        Assert.Equal(3, e.LogonType);
        Assert.Equal(42, e.RecordId);
    }

    [Theory]
    [InlineData(2)]   // интерактивный вход с консоли
    [InlineData(5)]   // служба
    public void Ignores4625_WithOtherLogonTypes(int logonType)
    {
        Assert.Null(EventParser.Parse("Security", 4625, 1, T, Props4625("203.0.113.5", (uint)logonType), Types));
    }

    [Fact]
    public void Ignores4625_WithoutIp()
    {
        Assert.Null(EventParser.Parse("Security", 4625, 1, T, Props4625("-", 10u), Types));
    }

    [Fact]
    public void Ignores4625_TooFewProperties()
    {
        Assert.Null(EventParser.Parse("Security", 4625, 1, T, new object?[] { "a", "b" }, Types));
    }

    [Fact]
    public void Parses4624_ByPosition()
    {
        var e = EventParser.Parse("Security", 4624, 7, T, Props4624("2001:db8::7", "10"), Types);
        Assert.NotNull(e);
        Assert.Equal(AuthEventKind.Success, e!.Kind);
        Assert.Equal("2001:db8::7", e.Ip);
        Assert.Equal("alice", e.UserName);
        Assert.Equal(10, e.LogonType);
    }

    [Fact]
    public void Parses140_FromRdpCoreTs()
    {
        var e = EventParser.Parse(EventParser.RdpCoreTsChannel, 140, 9, T, new object?[] { "198.51.100.3" }, Types);
        Assert.NotNull(e);
        Assert.Equal(AuthEventKind.Failure, e!.Kind);
        Assert.Equal("198.51.100.3", e.Ip);
        Assert.Null(e.UserName);
    }

    [Fact]
    public void Ignores140_FromOtherChannel()
    {
        Assert.Null(EventParser.Parse("Security", 140, 9, T, new object?[] { "198.51.100.3" }, Types));
    }

    [Fact]
    public void QueryXml_UsesRecordIdBookmark()
    {
        var xml = EventLogAuthSource.BuildQueryXml("Security", 12345, 60, Types, includeSuccess: true);
        Assert.Contains("EventRecordID &gt; 12345", xml);
        Assert.Contains("EventID=4625", xml);
        Assert.Contains("EventID=4624", xml);
        Assert.Contains("Data[@Name='LogonType']='10'", xml);
        Assert.DoesNotContain("timediff", xml);
    }

    [Fact]
    public void QueryXml_FirstRunUsesLookback()
    {
        var xml = EventLogAuthSource.BuildQueryXml(EventParser.RdpCoreTsChannel, null, 60, Types, includeSuccess: true);
        Assert.Contains("timediff(@SystemTime) &lt;= 3600000", xml);
        Assert.Contains("EventID=140", xml);
    }
}

public class DeduplicatorTests
{
    private static readonly DateTime T = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static AuthEvent Ev(string channel, string ip, DateTime t) =>
        new(AuthEventKind.Failure, channel, channel == "Security" ? 4625 : 140, 1, t, ip, null, 3);

    [Fact]
    public void SameAttemptFromTwoChannels_CountsOnce()
    {
        var d = new CrossSourceDeduplicator(TimeSpan.FromSeconds(5));
        Assert.False(d.IsDuplicate(Ev("Security", "1.1.1.1", T), T));
        Assert.True(d.IsDuplicate(Ev(EventParser.RdpCoreTsChannel, "1.1.1.1", T.AddSeconds(2)), T));
        // Сопоставление 1:1 — следующее событие 140 уже не дубль.
        Assert.False(d.IsDuplicate(Ev(EventParser.RdpCoreTsChannel, "1.1.1.1", T.AddSeconds(3)), T));
    }

    [Fact]
    public void SameChannel_OrDifferentIp_OrFarInTime_IsNotDuplicate()
    {
        var d = new CrossSourceDeduplicator(TimeSpan.FromSeconds(5));
        Assert.False(d.IsDuplicate(Ev("Security", "1.1.1.1", T), T));
        Assert.False(d.IsDuplicate(Ev("Security", "1.1.1.1", T), T));
        Assert.False(d.IsDuplicate(Ev(EventParser.RdpCoreTsChannel, "2.2.2.2", T), T));
        Assert.False(d.IsDuplicate(Ev(EventParser.RdpCoreTsChannel, "1.1.1.1", T.AddSeconds(30)), T));
    }
}

public class SubStatusParsingTests
{
    private static readonly IReadOnlySet<int> Types = new RdpGuard.Configuration.DetectionOptions().EffectiveLogonTypes;

    private static object?[] Props(object subStatus)
    {
        var p = new object?[21];
        for (int i = 0; i < p.Length; i++) p[i] = "-";
        p[5] = "admin";
        p[9] = subStatus;
        p[10] = 3u;
        p[19] = "203.0.113.5";
        return p;
    }

    [Theory]
    [InlineData(-1073741724, FailureReason.NoSuchUser)]    // 0xC0000064 как отрицательный int
    [InlineData(-1073741718, FailureReason.WrongPassword)] // 0xC000006A
    [InlineData(-1073741714, FailureReason.Other)]         // 0xC000006E (ограничение учётки)
    public void SubStatus_IsParsedFromSignedInt(int raw, FailureReason expected)
    {
        var e = EventParser.Parse("Security", 4625, 1, DateTime.UtcNow, Props(raw), Types)!;
        Assert.Equal(expected, e.Reason);
    }

    [Fact]
    public void SubStatus_IsParsedFromUInt_AndHexString()
    {
        Assert.Equal(FailureReason.WrongPassword, EventParser.Parse("Security", 4625, 1, DateTime.UtcNow, Props(0xC000006Au), Types)!.Reason);
        Assert.Equal(FailureReason.NoSuchUser, EventParser.Parse("Security", 4625, 1, DateTime.UtcNow, Props("0xC0000064"), Types)!.Reason);
    }

    [Fact]
    public void Rdp140_HasUnknownReason()
    {
        var e = EventParser.Parse(EventParser.RdpCoreTsChannel, 140, 1, DateTime.UtcNow, new object?[] { "203.0.113.5" }, Types)!;
        Assert.Equal(FailureReason.Unknown, e.Reason);
    }
}
