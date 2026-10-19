using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;
using RdpGuard.Events;

namespace RdpGuard.Tests;

/// <summary>Интеграция: фейковый источник событий -> очередь -> движок -> SQLite -> фейковый брандмауэр.</summary>
public sealed class GuardEngineTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rdpguard-tests-" + Guid.NewGuid().ToString("N"));
    private readonly ManualTime _time = new(Start);
    private readonly FakeFirewall _firewall = new();
    private readonly GuardOptions _options;
    private readonly GuardDb _db;
    private readonly GuardEngine _engine;

    public GuardEngineTests()
    {
        _options = new GuardOptions { DryRun = false, DataDirectory = _dir };
        // Эти тесты проверяют механику (окно, эскалация, БД, брандмауэр) на классическом правиле
        // «10 за 10 минут»; новые правила проверяются в PolicyRulesEngineTests.
        _options.Policy.MaxFailures = 10;
        _options.Policy.PeriodicMinAttempts = 0;
        _db = GuardDb.Open(_options.DatabasePath);
        _engine = new GuardEngine(_options, _db, _firewall, 3389, _time, NullLoggerFactory.Instance);
        _engine.Initialize();
    }

    public void Dispose()
    {
        _db.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
        }
    }

    private Repository Repo => _engine.Repository;
    private DateTime Now => _time.UtcNow;

    /// <summary>Прогоняет поток событий через канал так же, как это делает служба.</summary>
    private async Task Feed(IEnumerable<WorkItem> items)
    {
        var channel = Channel.CreateUnbounded<WorkItem>();
        using var source = new FakeEventSource(items.ToList());
        source.Start(channel.Writer, _engine.GetBookmark);
        await _engine.RunAsync(channel.Reader).WaitAsync(TimeSpan.FromSeconds(30));
    }

    private static IEnumerable<WorkItem> Burst(string ip, int count, DateTime from, TimeSpan step, string user = "admin") =>
        Enumerable.Range(0, count).Select(i => (WorkItem)FakeEventSource.Failure(ip, from + step * i, user));

    [Fact]
    public async Task StreamFromSeveralIps_ProducesExpectedBans()
    {
        var t0 = Now.AddMinutes(-30);
        var items = new List<WorkItem>();
        items.AddRange(Burst("203.0.113.10", 12, t0, TimeSpan.FromSeconds(20)));        // 12 за 4 минуты -> бан
        items.AddRange(Burst("198.51.100.20", 5, t0, TimeSpan.FromSeconds(10)));        // мало -> нет
        items.AddRange(Burst("10.0.0.5", 50, t0, TimeSpan.FromSeconds(1)));            // частный -> нет
        items.AddRange(Burst("2001:db8::66", 10, t0, TimeSpan.FromSeconds(55)));        // ровно порог за 8.25 мин -> бан
        items.AddRange(Burst("192.0.2.30", 10, t0, TimeSpan.FromMinutes(3)));           // 10 за 27 минут -> нет
        // Перемешиваем источники, как в реальном потоке.
        items = items.OrderBy(i => ((RecordWork)i).Event!.TimeUtc).ToList();

        await Feed(items);

        var active = Repo.GetActiveBans(Now).OrderBy(b => b.Ip).ToList();
        Assert.Equal(new[] { "2001:db8::66", "203.0.113.10" }, active.Select(b => b.Ip));
        Assert.All(active, b =>
        {
            Assert.Equal(1, b.OffenseNo);
            Assert.Equal(Now.AddDays(1), b.ExpiresAtUtc);
            Assert.Equal(10, b.FailuresInWindow);
        });
        Assert.Equal(new HashSet<string> { "2001:db8::66", "203.0.113.10" }, _firewall.BlockedAddresses());

        // Все попытки записаны, включая частные и не приведшие к бану.
        Assert.Equal(12 + 5 + 50 + 10 + 10, _db.ScalarLong("SELECT COUNT(*) FROM attempts"));
        var ip = Repo.GetIp("203.0.113.10")!;
        Assert.Equal(12, ip.TotalFailures);
        Assert.Equal(1, ip.Offenses);
        Assert.True(Repo.GetIp("10.0.0.5")!.Whitelisted);

        var m = _engine.Metrics;
        Assert.Equal(87, m.FailedLogons.Get("4625"));
        Assert.Equal(87, m.EventsRead.Get("Security"));
        Assert.Equal(2, m.Bans.Get("1"));
        Assert.Equal(2, m.LastFirewallSync!.Addresses);
    }

    [Fact]
    public async Task RepeatOffense_EscalatesAfterExpiry()
    {
        const string ip = "203.0.113.50";
        await Feed(Burst(ip, 10, Now.AddMinutes(-2), TimeSpan.FromSeconds(5)));
        Assert.Equal(Now.AddDays(1), Repo.GetActiveBan(ip, Now)!.ExpiresAtUtc);

        // Через сутки с минутой фоновая задача снимает бан.
        _time.Advance(TimeSpan.FromDays(1) + TimeSpan.FromMinutes(1));
        await Feed(new WorkItem[] { new TickWork(TickKind.Maintenance) });
        Assert.Null(Repo.GetActiveBan(ip, Now));
        Assert.Empty(_firewall.BlockedAddresses());
        Assert.Equal("expired", Repo.GetBans(false, Now, 10, ip).Single().UnbanReason);

        // Новая атака: нарушение №2, двое суток. Старые попытки до конца бана не учитываются.
        await Feed(Burst(ip, 9, Now.AddSeconds(-50), TimeSpan.FromSeconds(5)));
        Assert.Null(Repo.GetActiveBan(ip, Now));
        await Feed(Burst(ip, 1, Now, TimeSpan.Zero));
        var ban = Repo.GetActiveBan(ip, Now)!;
        Assert.Equal(2, ban.OffenseNo);
        Assert.Equal(Now.AddDays(2), ban.ExpiresAtUtc);
        Assert.Contains(ip, _firewall.BlockedAddresses());
    }

    [Fact]
    public async Task SuccessfulLogon_LiftsBan_AndPreventsNewBans()
    {
        const string ip = "198.51.100.77";
        await Feed(Burst(ip, 10, Now.AddMinutes(-1), TimeSpan.FromSeconds(3)));
        Assert.NotNull(Repo.GetActiveBan(ip, Now));

        await Feed(new WorkItem[] { FakeEventSource.Success(ip, Now) });

        Assert.Null(Repo.GetActiveBan(ip, Now));
        Assert.Equal("successful logon", Repo.GetBans(false, Now, 10, ip).Single().UnbanReason);
        Assert.Empty(_firewall.BlockedAddresses());
        Assert.Equal(1, _db.ScalarLong("SELECT COUNT(*) FROM successes WHERE ip = $ip", ("$ip", ip)));
        Assert.NotNull(Repo.GetIp(ip)!.LastSuccessUtc);

        _time.Advance(TimeSpan.FromMinutes(5));
        await Feed(Burst(ip, 30, Now.AddMinutes(-2), TimeSpan.FromSeconds(2)));
        Assert.Null(Repo.GetActiveBan(ip, Now));
    }

    [Fact]
    public async Task SuccessfulLogonFromPrivateAddress_IsNotRecorded()
    {
        await Feed(new WorkItem[] { FakeEventSource.Success("192.168.1.10", Now) });
        Assert.Equal(0, _db.ScalarLong("SELECT COUNT(*) FROM successes"));
    }

    [Fact]
    public async Task DuplicateFrom140And4625_CountsOnce()
    {
        const string ip = "203.0.113.99";
        var items = new List<WorkItem>();
        for (int i = 0; i < 9; i++)
        {
            var t = Now.AddMinutes(-5).AddSeconds(i * 10);
            items.Add(FakeEventSource.Failure(ip, t));
            items.Add(FakeEventSource.Failure(ip, t.AddSeconds(1), eventId: 140, channel: EventParser.RdpCoreTsChannel));
        }
        await Feed(items);

        Assert.Equal(9, _db.ScalarLong("SELECT COUNT(*) FROM attempts WHERE ip = $ip", ("$ip", ip)));
        Assert.Null(Repo.GetActiveBan(ip, Now));
    }

    [Fact]
    public async Task DryRun_RecordsBans_ButDoesNotTouchFirewall()
    {
        var options = new GuardOptions { DryRun = true, DataDirectory = _dir };
        var firewall = new FakeFirewall();
        firewall.Rules.Add(new() { Name = "RdpGuard-Block-01", RemoteAddresses = new[] { "9.9.9.9/255.255.255.255" } });
        var engine = new GuardEngine(options, _db, firewall, 3389, _time, NullLoggerFactory.Instance);
        engine.Initialize();

        var channel = Channel.CreateUnbounded<WorkItem>();
        new FakeEventSource(Burst("203.0.113.1", 10, Now.AddMinutes(-1), TimeSpan.FromSeconds(1)).ToList())
            .Start(channel.Writer, engine.GetBookmark);
        await engine.RunAsync(channel.Reader);

        Assert.NotNull(engine.Repository.GetActiveBan("203.0.113.1", Now));
        Assert.Equal(0, firewall.Adds + firewall.Updates + firewall.Removes);
        Assert.Equal("RdpGuard-Block-01", Assert.Single(firewall.Rules).Name);
    }

    [Fact]
    public async Task Startup_ReconcilesFirewallWithDatabase()
    {
        // В брандмауэре — мусор от прошлых запусков; в БД — один активный бан.
        _firewall.Rules.Add(new() { Name = "RdpGuard-Block-01", RemoteAddresses = new[] { "9.9.9.9/255.255.255.255" } });
        _firewall.Rules.Add(new() { Name = "RdpGuard-Stale", RemoteAddresses = new[] { "8.8.8.8/255.255.255.255" } });
        _firewall.Rules.Add(new() { Name = "Unrelated", RemoteAddresses = new[] { "7.7.7.7/255.255.255.255" } });
        Repo.InsertBan("203.0.113.5", Now, Now.AddDays(1), 1, "test", 10);
        Repo.InsertBan("203.0.113.6", Now.AddDays(-3), Now.AddDays(-2), 1, "expired", 10);

        new GuardEngine(_options, _db, _firewall, 3389, _time, NullLoggerFactory.Instance).Initialize();

        Assert.Equal(new HashSet<string> { "203.0.113.5" }, _firewall.BlockedAddresses());
        Assert.Contains(_firewall.Rules, r => r.Name == "Unrelated");
        Assert.DoesNotContain(_firewall.Rules, r => r.Name == "RdpGuard-Stale");
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Bookmarks_ArePersistedPerChannel()
    {
        await Feed(new WorkItem[]
        {
            new RecordWork(EventParser.SecurityChannel, 500, null),
            new RecordWork(EventParser.SecurityChannel, 510, null),
            new RecordWork(EventParser.RdpCoreTsChannel, 77, null),
        });

        Assert.Equal(510, _engine.GetBookmark(EventParser.SecurityChannel));
        Assert.Equal(510, Repo.GetBookmark(EventParser.SecurityChannel));
        Assert.Equal(77, Repo.GetBookmark(EventParser.RdpCoreTsChannel));

        // Новый движок (перезапуск службы) получает закладку из БД — с неё источник догрузит пропущенное.
        var restarted = new GuardEngine(_options, _db, _firewall, 3389, _time, NullLoggerFactory.Instance);
        restarted.Initialize();
        var source = new FakeEventSource(Array.Empty<WorkItem>());
        source.Start(Channel.CreateUnbounded<WorkItem>().Writer, restarted.GetBookmark);
        Assert.Equal(510, source.BookmarkProvider!(EventParser.SecurityChannel));
    }

    [Fact]
    public async Task CliChanges_ArePickedUpOnQuickTick()
    {
        const string ip = "203.0.113.70";
        await Feed(Burst(ip, 10, Now.AddMinutes(-1), TimeSpan.FromSeconds(1)));
        Assert.Contains(ip, _firewall.BlockedAddresses());

        // CLI в другом процессе: allow снимает бан и увеличивает ревизию.
        var admin = new AdminOperations(_options, Repo);
        var (_, unbanned) = admin.Allow("203.0.113.0/24", "office", Now);
        Assert.Equal(new[] { ip }, unbanned);

        await Feed(new WorkItem[] { new TickWork(TickKind.Quick) });
        Assert.Empty(_firewall.BlockedAddresses());

        // Теперь адрес в белом списке: атака не приводит к бану.
        await Feed(Burst(ip, 20, Now, TimeSpan.FromSeconds(1)));
        Assert.Null(Repo.GetActiveBan(ip, Now));
    }

    [Fact]
    public async Task ManualBan_UsesEscalationAndRefusesWhitelisted()
    {
        var admin = new AdminOperations(_options, Repo);
        var r = admin.Ban("198.51.100.1", null, false, "test", false, Now);
        Assert.Equal(1, r.OffenseNo);
        Assert.Equal(Now.AddDays(1), r.ExpiresAtUtc);

        var p = admin.Ban("198.51.100.2", null, true, null, false, Now);
        Assert.Null(p.ExpiresAtUtc);

        Assert.Throws<AdminException>(() => admin.Ban("10.1.1.1", null, false, null, false, Now));

        await Feed(new WorkItem[] { new TickWork(TickKind.Quick) });
        Assert.Equal(new HashSet<string> { "198.51.100.1", "198.51.100.2" }, _firewall.BlockedAddresses());

        Assert.True(admin.Unban("198.51.100.1", resetOffenses: true, Now));
        await Feed(new WorkItem[] { new TickWork(TickKind.Quick) });
        Assert.Equal(new HashSet<string> { "198.51.100.2" }, _firewall.BlockedAddresses());
        Assert.Equal(0, Repo.GetIp("198.51.100.1")!.Offenses);
    }

    [Fact]
    public async Task OldAttempts_ArePrunedByMaintenance()
    {
        await Feed(Burst("203.0.113.88", 3, Now.AddDays(-40), TimeSpan.FromSeconds(1)));
        await Feed(Burst("203.0.113.89", 3, Now.AddDays(-1), TimeSpan.FromSeconds(1)));
        await Feed(new WorkItem[] { new TickWork(TickKind.Maintenance) });
        Assert.Equal(3, _db.ScalarLong("SELECT COUNT(*) FROM attempts"));
    }

    [Fact]
    public async Task BrokenEvent_DoesNotStopProcessing()
    {
        var bad = new RecordWork(EventParser.SecurityChannel, 1,
            new AuthEvent(AuthEventKind.Failure, EventParser.SecurityChannel, 4625, 1, Now, "not-an-ip", "x", 3));
        var items = new List<WorkItem> { bad };
        items.AddRange(Burst("203.0.113.111", 10, Now.AddMinutes(-1), TimeSpan.FromSeconds(1)));

        await Feed(items);
        Assert.NotNull(Repo.GetActiveBan("203.0.113.111", Now));
    }
}
