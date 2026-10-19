using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;
using RdpGuard.Events;
using RdpGuard.Policy;

namespace RdpGuard.Tests;

/// <summary>Правила политики по отдельности.</summary>
public class PolicyRulesTests
{
    private static readonly DateTime Now = new(2026, 10, 19, 12, 0, 0, DateTimeKind.Utc);
    private static readonly BanPolicy Policy = new(new PolicyOptions());

    private static FailureContext Ctx(int fast = 1, int slow = 1, int noSuchUser = 0, int wrongPassword = 0,
        IReadOnlyList<DateTime>? times = null, DateTime? lastSuccess = null) =>
        new(Now, fast, 0, null, lastSuccess, false, false, slow, noSuchUser, wrongPassword, times);

    private static List<DateTime> Every(TimeSpan step, int count, params int[] jitterSeconds) =>
        Enumerable.Range(0, count)
            .Select(i => Now.AddMinutes(-600) + step * i + TimeSpan.FromSeconds(i < jitterSeconds.Length ? jitterSeconds[i] : 0))
            .ToList();

    [Fact]
    public void WrongPasswordForExistingAccount_BansAtFive()
    {
        Assert.False(Policy.Evaluate(Ctx(wrongPassword: 4)).Ban);
        var d = Policy.Evaluate(Ctx(wrongPassword: 5));
        Assert.True(d.Ban);
        Assert.Equal(BanRules.WrongPassword, d.Rule);
        Assert.Equal(5, d.Count);
        Assert.Contains("wrong passwords", d.Reason);
    }

    [Fact]
    public void NonExistentUserNames_BanAtThree()
    {
        Assert.False(Policy.Evaluate(Ctx(noSuchUser: 2)).Ban);
        var d = Policy.Evaluate(Ctx(noSuchUser: 3));
        Assert.True(d.Ban);
        Assert.Equal(BanRules.NoSuchUser, d.Rule);
    }

    [Fact]
    public void SlowWindow_BansAtFifteenPerDay()
    {
        Assert.False(Policy.Evaluate(Ctx(fast: 1, slow: 14)).Ban);
        var d = Policy.Evaluate(Ctx(fast: 1, slow: 15));
        Assert.True(d.Ban);
        Assert.Equal(BanRules.Slow, d.Rule);
    }

    [Fact]
    public void WrongPasswordRule_TakesPriorityInReason()
    {
        var d = Policy.Evaluate(Ctx(fast: 7, slow: 20, wrongPassword: 5));
        Assert.Equal(BanRules.WrongPassword, d.Rule);
    }

    [Fact]
    public void Periodic_SspBotEvery38Minutes_IsDetected()
    {
        // Реальные интервалы бота 109.206.146.139: 37,5–38,2 минуты.
        var times = Every(TimeSpan.FromMinutes(38), 5, 0, -29, 2, 38, -3);
        Assert.True(Policy.IsPeriodic(times, out var interval));
        Assert.InRange(interval.TotalMinutes, 37, 39);

        var d = Policy.Evaluate(Ctx(times: times));
        Assert.True(d.Ban);
        Assert.Equal(BanRules.Periodic, d.Rule);
        Assert.Contains("regular ~38m", d.Reason);
    }

    [Fact]
    public void Periodic_NeedsEnoughAttempts()
    {
        Assert.False(Policy.IsPeriodic(Every(TimeSpan.FromMinutes(38), 4), out _));
    }

    [Fact]
    public void Periodic_IrregularHumanTypos_AreNotDetected()
    {
        var human = new[] { 0, 40, 95, 400, 410 }.Select(s => Now.AddSeconds(s)).ToList();
        Assert.False(Policy.IsPeriodic(human, out _));
    }

    [Fact]
    public void Periodic_SubSecondBurst_IsLeftToFastWindow()
    {
        var burst = Enumerable.Range(0, 5).Select(i => Now.AddMilliseconds(i * 200)).ToList();
        Assert.False(Policy.IsPeriodic(burst, out _));
    }

    [Fact]
    public void Periodic_UsesOnlyTheLastAttempts()
    {
        // Старые нерегулярные попытки не мешают узнать регулярную серию в конце.
        var times = new List<DateTime> { Now.AddHours(-20), Now.AddHours(-19.3) };
        times.AddRange(Every(TimeSpan.FromMinutes(10), 5));
        Assert.True(Policy.IsPeriodic(times, out _));
    }

    [Fact]
    public void DisabledRules_DoNotFire()
    {
        var off = new BanPolicy(new PolicyOptions
        {
            WrongPasswordMaxFailures = 0, NoSuchUserMaxFailures = 0, PeriodicMinAttempts = 0, SlowMaxFailures = 0,
        });
        var d = off.Evaluate(Ctx(fast: 1, slow: 100, noSuchUser: 100, wrongPassword: 100, times: Every(TimeSpan.FromMinutes(5), 10)));
        Assert.False(d.Ban);
    }

    [Fact]
    public void RecentSuccessfulLogon_ExemptsFromAllRules()
    {
        var d = Policy.Evaluate(Ctx(fast: 50, slow: 50, noSuchUser: 50, wrongPassword: 50, lastSuccess: Now.AddDays(-1)));
        Assert.False(d.Ban);
    }
}

/// <summary>Новые правила сквозь движок и SQLite (с настройками по умолчанию).</summary>
public sealed class PolicyRulesEngineTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rdpguard-rules-" + Guid.NewGuid().ToString("N"));
    private readonly ManualTime _time = new(new DateTimeOffset(2026, 10, 19, 18, 0, 0, TimeSpan.Zero));
    private readonly FakeFirewall _firewall = new();
    private readonly CapturingLoggerFactory _loggers = new();
    private readonly GuardOptions _options;
    private readonly GuardDb _db;
    private readonly GuardEngine _engine;

    public PolicyRulesEngineTests()
    {
        _options = new GuardOptions { DryRun = false, DataDirectory = _dir };
        _db = GuardDb.Open(_options.DatabasePath);
        _engine = new GuardEngine(_options, _db, _firewall, 3389, _time, _loggers);
        _engine.Initialize();
    }

    public void Dispose()
    {
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
        }
    }

    private DateTime Now => _time.UtcNow;

    private async Task Feed(IEnumerable<WorkItem> items)
    {
        var channel = Channel.CreateUnbounded<WorkItem>();
        new FakeEventSource(items.ToList()).Start(channel.Writer, _engine.GetBookmark);
        await _engine.RunAsync(channel.Reader).WaitAsync(TimeSpan.FromSeconds(30));
    }

    /// <summary>Подаёт события по одному, как они приходили бы в реальном времени.</summary>
    private async Task<int?> FeedUntilBanned(string ip, IReadOnlyList<RecordWork> items)
    {
        for (int i = 0; i < items.Count; i++)
        {
            await Feed(new WorkItem[] { items[i] });
            if (_engine.Repository.GetActiveBan(ip, Now) is not null) return i + 1;
        }
        return null;
    }

    // Время попыток бота 109.206.146.139 (AS47914) из журнала Security, 19.10.2026, UTC.
    private static readonly string[] SspBot =
    {
        "01:30:11", "02:07:42", "02:45:13", "03:22:49", "04:00:49", "04:38:56", "05:17:13", "05:55:22", "06:33:32",
        "07:11:21", "07:48:58", "10:20:36", "10:58:13", "11:36:14", "12:13:59", "12:51:51", "13:30:09", "14:08:29", "14:46:59",
    };

    private static DateTime At(string hms) => DateTime.SpecifyKind(DateTime.Parse("2026-10-19 " + hms), DateTimeKind.Utc);

    [Fact]
    public async Task SspBot_WrongPasswordEvery38Min_IsBannedOnFifthAttempt()
    {
        const string ip = "203.0.113.39"; // вместо реального адреса
        var items = SspBot.Select(t => FakeEventSource.Failure(ip, At(t), "Администратор",
            subStatus: FailureCodes.WrongPassword)).ToList();

        var bannedAfter = await FeedUntilBanned(ip, items);

        Assert.Equal(5, bannedAfter);
        var ban = _engine.Repository.GetActiveBan(ip, Now)!;
        Assert.Contains("wrong passwords", ban.Reason);
        Assert.Equal(5, ban.FailuresInWindow);
        Assert.Contains(ip, _firewall.BlockedAddresses());
        Assert.Equal(1, _engine.Metrics.BanTriggers.Get(BanRules.WrongPassword));
    }

    [Fact]
    public async Task SspBot_WithoutReasonCode_IsCaughtByTimerDetector()
    {
        // Например, только событие 140 (без SubStatus): ловит детектор «по таймеру».
        const string ip = "203.0.113.40";
        var items = SspBot.Select(t => FakeEventSource.Failure(ip, At(t), "x")).ToList();

        Assert.Equal(5, await FeedUntilBanned(ip, items));
        Assert.Contains("regular ~38m", _engine.Repository.GetActiveBan(ip, Now)!.Reason);
    }

    [Fact]
    public async Task UserNameScanner_IsBannedOnThirdAttempt()
    {
        const string ip = "198.51.100.77";
        var rnd = new Random(1);
        var t = Now.AddHours(-3);
        var items = new[] { "admin", "Administrator", "user", "backup", "test" }
            .Select(u => FakeEventSource.Failure(ip, t = t.AddSeconds(rnd.Next(30, 900)), u, subStatus: FailureCodes.NoSuchUser))
            .ToList();

        Assert.Equal(3, await FeedUntilBanned(ip, items));
    }

    [Fact]
    public async Task LegitUserTypos_ThenSuccess_AreNotBanned()
    {
        const string ip = "198.51.100.88";
        await Feed(new WorkItem[]
        {
            FakeEventSource.Failure(ip, Now.AddMinutes(-10), "alcie", subStatus: FailureCodes.NoSuchUser),
            FakeEventSource.Failure(ip, Now.AddMinutes(-9), "alice", subStatus: FailureCodes.WrongPassword),
            FakeEventSource.Success(ip, Now.AddMinutes(-8), "alice"),
        });
        // После успешного входа даже серия опечаток не банит (SuccessTrustDays).
        await Feed(Enumerable.Range(0, 6).Select(i =>
            (WorkItem)FakeEventSource.Failure(ip, Now.AddMinutes(-5 + i * 0.5), "alice", subStatus: FailureCodes.WrongPassword)));

        Assert.Null(_engine.Repository.GetActiveBan(ip, Now));
    }

    [Fact]
    public async Task DistributedGuessing_RaisesAccountAlertOnce()
    {
        // 5 адресов по 4 неверных пароля к одной учётке: ни один адрес не дошёл до бана, но учётку атакуют.
        var items = new List<WorkItem>();
        for (int ip = 1; ip <= 5; ip++)
        for (int i = 0; i < 4; i++)
            items.Add(FakeEventSource.Failure($"203.0.113.{100 + ip}", Now.AddMinutes(-300 + ip * 7 + i * 41 + ip), "Администратор",
                subStatus: FailureCodes.WrongPassword));
        await Feed(items);
        Assert.Empty(_engine.Repository.GetActiveBans(Now));

        await Feed(new WorkItem[] { new TickWork(TickKind.Maintenance) });
        await Feed(new WorkItem[] { new TickWork(TickKind.Maintenance) });

        var alert = Assert.Single(_loggers.Entries, e => e.EventId == LogEvents.AccountAttack.Id);
        Assert.Contains("Администратор", alert.Message);
        Assert.Contains("20 wrong passwords from 5", alert.Message);
    }
}

/// <summary>Логгер, запоминающий сообщения (для проверки событий аудита).</summary>
public sealed class CapturingLoggerFactory : ILoggerFactory
{
    public sealed record Entry(string Category, LogLevel Level, int EventId, string Message);

    private readonly List<Entry> _entries = new();

    public IReadOnlyList<Entry> Entries
    {
        get
        {
            lock (_entries) return _entries.ToList();
        }
    }

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }

    private sealed class Logger(CapturingLoggerFactory owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (owner._entries) owner._entries.Add(new Entry(category, logLevel, eventId.Id, formatter(state, exception)));
        }
    }
}
