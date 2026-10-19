using RdpGuard.Configuration;
using RdpGuard.Policy;

namespace RdpGuard.Tests;

public class BanPolicyTests
{
    private static readonly DateTime Now = new(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);

    private static BanPolicy Policy(Action<PolicyOptions>? configure = null)
    {
        var o = new PolicyOptions();
        configure?.Invoke(o);
        return new BanPolicy(o);
    }

    private static FailureContext Ctx(int failures = 10, int offenses = 0, DateTime? lastActivity = null,
        DateTime? lastSuccess = null, bool activeBan = false, bool whitelisted = false) =>
        new(Now, failures, offenses, lastActivity, lastSuccess, activeBan, whitelisted);

    [Fact]
    public void BelowThreshold_DoesNotBan()
    {
        var d = Policy().Evaluate(Ctx(failures: 4));
        Assert.False(d.Ban);
        Assert.Equal("below thresholds", d.Reason);
    }

    [Fact]
    public void AtThreshold_BansFirstOffenseForBaseDuration()
    {
        var d = Policy().Evaluate(Ctx(failures: 5));
        Assert.True(d.Ban);
        Assert.Equal(BanRules.Fast, d.Rule);
        Assert.Equal(1, d.OffenseNo);
        Assert.Equal(TimeSpan.FromDays(1), d.Duration);
    }

    [Fact]
    public void CustomThreshold_IsRespected()
    {
        var p = Policy(o => o.MaxFailures = 3);
        Assert.False(p.Evaluate(Ctx(failures: 2)).Ban);
        Assert.True(p.Evaluate(Ctx(failures: 3)).Ban);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 4)]
    [InlineData(4, 8)]
    [InlineData(5, 16)]
    [InlineData(6, 30)] // 32 суток упираются в потолок
    [InlineData(7, 30)]
    [InlineData(500, 30)] // без переполнения
    public void Duration_DoublesPerOffense_WithCeiling(int offense, int expectedDays)
    {
        Assert.Equal(TimeSpan.FromDays(expectedDays), Policy().GetBanDuration(offense));
    }

    [Fact]
    public void Duration_UsesConfiguredBaseAndCeiling()
    {
        var p = Policy(o =>
        {
            o.BaseBanDuration = TimeSpan.FromHours(6);
            o.MaxBanDuration = TimeSpan.FromDays(2);
        });
        Assert.Equal(TimeSpan.FromHours(6), p.GetBanDuration(1));
        Assert.Equal(TimeSpan.FromHours(12), p.GetBanDuration(2));
        Assert.Equal(TimeSpan.FromHours(24), p.GetBanDuration(3));
        Assert.Equal(TimeSpan.FromHours(48), p.GetBanDuration(4));
        Assert.Equal(TimeSpan.FromHours(48), p.GetBanDuration(5));
    }

    [Fact]
    public void PermanentAfterK_MakesOffenseKPlusOnePermanent()
    {
        var p = Policy(o => o.PermanentAfterOffenses = 3);
        Assert.Equal(TimeSpan.FromDays(4), p.GetBanDuration(3));
        Assert.Null(p.GetBanDuration(4));
        Assert.Null(p.GetBanDuration(10));

        var d = p.Evaluate(Ctx(offenses: 3, lastActivity: Now.AddDays(-1)));
        Assert.True(d.Ban);
        Assert.Equal(4, d.OffenseNo);
        Assert.Null(d.Duration);
    }

    [Fact]
    public void PermanentDisabledByDefault()
    {
        Assert.NotNull(Policy().GetBanDuration(1000));
    }

    [Fact]
    public void RepeatOffender_GetsNextOffenseNumber()
    {
        var d = Policy().Evaluate(Ctx(offenses: 2, lastActivity: Now.AddDays(-10)));
        Assert.Equal(3, d.OffenseNo);
        Assert.Equal(TimeSpan.FromDays(4), d.Duration);
    }

    [Fact]
    public void OffenseCounter_ResetsAfterInactivity()
    {
        var p = Policy(); // 90 дней
        Assert.Equal(1, p.Evaluate(Ctx(offenses: 4, lastActivity: Now.AddDays(-90))).OffenseNo);
        Assert.Equal(1, p.Evaluate(Ctx(offenses: 4, lastActivity: Now.AddDays(-200))).OffenseNo);
        Assert.Equal(5, p.Evaluate(Ctx(offenses: 4, lastActivity: Now.AddDays(-89))).OffenseNo);
    }

    [Fact]
    public void OffenseReset_CanBeDisabled()
    {
        var p = Policy(o => o.OffenseResetDays = 0);
        Assert.Equal(5, p.Evaluate(Ctx(offenses: 4, lastActivity: Now.AddYears(-5))).OffenseNo);
    }

    [Fact]
    public void Whitelisted_NeverBanned()
    {
        var d = Policy().Evaluate(Ctx(failures: 1000, whitelisted: true));
        Assert.False(d.Ban);
        Assert.Equal("whitelisted", d.Reason);
    }

    [Fact]
    public void RecentSuccessfulLogon_PreventsBan()
    {
        var d = Policy().Evaluate(Ctx(failures: 100, lastSuccess: Now.AddDays(-29)));
        Assert.False(d.Ban);
        Assert.Equal("recent successful logon", d.Reason);
    }

    [Fact]
    public void OldSuccessfulLogon_DoesNotPreventBan()
    {
        Assert.True(Policy().Evaluate(Ctx(failures: 100, lastSuccess: Now.AddDays(-31))).Ban);
        Assert.True(Policy(o => o.SuccessTrustDays = 0).Evaluate(Ctx(failures: 100, lastSuccess: Now)).Ban);
    }

    [Fact]
    public void AlreadyBanned_IsNotBannedAgain()
    {
        Assert.False(Policy().Evaluate(Ctx(failures: 50, activeBan: true)).Ban);
    }

    [Theory]
    [InlineData(0, "permanent")]
    [InlineData(24, "1d")]
    [InlineData(6, "6h")]
    public void FormatSpan(int hours, string expected)
    {
        TimeSpan? span = hours == 0 ? null : TimeSpan.FromHours(hours);
        Assert.Equal(expected, BanPolicy.FormatSpan(span));
    }
}
