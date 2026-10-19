using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using RdpGuard.Api;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;

namespace RdpGuard.Tests;

/// <summary>HTTP API: поднимается настоящий HttpListener на свободном порту localhost.</summary>
public sealed class StatsApiTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rdpguard-api-" + Guid.NewGuid().ToString("N"));
    private readonly ManualTime _time = new(new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly GuardMetrics _metrics = new();
    private StatsApiServer? _server;
    private string _baseUrl = "";
    private string _token = "";

    private GuardOptions Options(Action<ApiOptions>? configure = null)
    {
        int port = FreePort();
        _baseUrl = $"http://localhost:{port}/";
        var o = new GuardOptions { DataDirectory = _dir };
        o.Api.Urls.Add(_baseUrl);
        configure?.Invoke(o.Api);
        return o;
    }

    public async Task InitializeAsync()
    {
        var options = Options();
        Seed(options);
        await StartServer(options);
    }

    private void Seed(GuardOptions options)
    {
        using var db = GuardDb.Open(options.DatabasePath);
        var repo = new Repository(db);
        var now = _time.UtcNow;
        for (int i = 0; i < 12; i++)
        {
            repo.InsertAttempt(new Events.AuthEvent(Events.AuthEventKind.Failure, "Security", 4625, i + 1,
                now.AddMinutes(-30).AddSeconds(i * 10), "203.0.113.10", i % 2 == 0 ? "admin" : "administrator", 3));
            repo.TouchIpFailure("203.0.113.10", now.AddMinutes(-30).AddSeconds(i * 10), false);
        }
        repo.InsertAttempt(new Events.AuthEvent(Events.AuthEventKind.Failure, "Security", 4625, 100,
            now.AddHours(-3), "198.51.100.5", "backup", 3));
        repo.InsertBan("203.0.113.10", now.AddMinutes(-28), now.AddDays(1), 1, "test", 10);
        repo.InsertBan("198.51.100.9", now.AddDays(-2), null, 6, "test", 10);
        _token = ApiTokens.Create(repo, "grafana", now);
        ApiTokens.Create(repo, "old", now);
        ApiTokens.Revoke(db, "old", now);
    }

    private async Task StartServer(GuardOptions options)
    {
        if (_server is not null)
        {
            await _server.StopAsync(CancellationToken.None);
            _server.Dispose();
        }
        _metrics.FailedLogons.Inc("4625", 13);
        _server = new StatsApiServer(options, _metrics, _time, NullLogger<StatsApiServer>.Instance);
        await _server.StartAsync(CancellationToken.None);
        Assert.True(_server.IsListening, "HttpListener did not start");
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.StopAsync(CancellationToken.None);
            _server.Dispose();
        }
        _http.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
        }
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private async Task<HttpResponseMessage> Get(string path, string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, _baseUrl + path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _http.SendAsync(request);
    }

    private async Task<JsonElement> GetJson(string path)
    {
        var response = await Get(path, _token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("application/json", response.Content.Headers.ContentType?.ToString());
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }

    [Fact]
    public async Task Health_IsAvailableWithoutToken()
    {
        var r = await Get("health");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("rg_wrong")]
    [InlineData("not-a-token")]
    public async Task Metrics_RequireValidToken(string? token)
    {
        var r = await Get("metrics", token);
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Contains(r.Headers.WwwAuthenticate, h => h.Scheme == "Bearer");
    }

    [Fact]
    public async Task RevokedToken_IsRejected()
    {
        using var db = GuardDb.Open(Path.Combine(_dir, "rdpguard.db"));
        var token = ApiTokens.Create(new Repository(db), "temp", _time.UtcNow);
        Assert.Equal(HttpStatusCode.OK, (await Get("api/summary", token)).StatusCode);

        ApiTokens.Revoke(db, "temp", _time.UtcNow);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Get("api/summary", token)).StatusCode);
    }

    [Fact]
    public async Task Metrics_ArePrometheusText()
    {
        var r = await Get("metrics", _token);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.StartsWith("text/plain", r.Content.Headers.ContentType?.ToString());
        var text = await r.Content.ReadAsStringAsync();

        Assert.Contains("# TYPE rdpguard_active_bans gauge", text);
        Assert.Contains("\nrdpguard_active_bans 2\n", text);
        Assert.Contains("rdpguard_active_bans_by_offense{offense=\"1\"} 1", text);
        Assert.Contains("rdpguard_active_bans_by_offense{offense=\"permanent\"} 1", text);
        Assert.Contains("rdpguard_failed_logons_last_1h 12", text);
        Assert.Contains("rdpguard_attacking_ips_last_24h 2", text);
        Assert.Contains("# TYPE rdpguard_failed_logons_total counter", text);
        Assert.Contains("rdpguard_failed_logons_total{event_id=\"4625\"} 13", text);
        Assert.Contains("rdpguard_database_up 1", text);
        Assert.Contains("rdpguard_dry_run 1", text);
        // Адреса атакующих в метки Prometheus не попадают (кардинальность).
        Assert.DoesNotContain("203.0.113.10", text);
    }

    [Fact]
    public async Task Summary_ReturnsCounts()
    {
        var j = await GetJson("api/summary");
        Assert.Equal(2, j.GetProperty("activeBans").GetInt32());
        Assert.Equal(1, j.GetProperty("permanentBans").GetInt32());
        Assert.Equal(13, j.GetProperty("failedLogons24h").GetInt64());
        Assert.True(j.GetProperty("dryRun").GetBoolean());
        Assert.EndsWith("Z", j.GetProperty("generatedUtc").GetString());
    }

    [Fact]
    public async Task Top_ListsAttackers()
    {
        var j = await GetJson("api/top?hours=24&limit=5");
        Assert.Equal(2, j.GetArrayLength());
        var first = j[0];
        Assert.Equal("203.0.113.10", first.GetProperty("ip").GetString());
        Assert.Equal(12, first.GetProperty("attempts").GetInt64());
        Assert.True(first.GetProperty("banned").GetBoolean());
        Assert.Contains("admin(6)", first.GetProperty("topUsers").GetString());
    }

    [Fact]
    public async Task Users_AndBans()
    {
        var users = await GetJson("api/users?hours=24");
        Assert.Equal(3, users.GetArrayLength());

        var bans = await GetJson("api/bans?active=true");
        Assert.Equal(2, bans.GetArrayLength());
        Assert.Contains(bans.EnumerateArray(), b => b.GetProperty("permanent").GetBoolean());
    }

    [Fact]
    public async Task Timeseries_FillsEmptyBuckets()
    {
        var j = await GetJson("api/timeseries/attempts?hours=2&step=600");
        Assert.Equal(12, j.GetArrayLength()); // 2 часа / 10 минут
        Assert.Equal(12, j.EnumerateArray().Sum(p => p.GetProperty("count").GetInt64()));
        Assert.All(j.EnumerateArray(), p => Assert.True(p.GetProperty("timeMs").GetInt64() > 0));

        var bans = await GetJson("api/timeseries/bans?hours=72&step=3600");
        Assert.Equal(2, bans.EnumerateArray().Sum(p => p.GetProperty("count").GetInt64()));
    }

    [Fact]
    public async Task BadParameters_Return400_UnknownPath404()
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await Get("api/top?hours=abc", _token)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Get("api/nothing", _token)).StatusCode);
    }

    [Fact]
    public async Task ClientNotInAllowList_IsForbidden()
    {
        await StartServer(Options(api => api.AllowedClients.Add("192.0.2.0/24")));
        Assert.Equal(HttpStatusCode.Forbidden, (await Get("metrics", _token)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Get("health")).StatusCode);
    }

    [Fact]
    public async Task TokenCanBeDisabled_ForLocalPrometheus()
    {
        await StartServer(Options(api => api.RequireToken = false));
        Assert.Equal(HttpStatusCode.OK, (await Get("metrics")).StatusCode);
    }
}

public class ApiTokenAndSchemaTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "rdpguard-schema-" + Guid.NewGuid().ToString("N") + ".db");

    public void Dispose()
    {
        foreach (var f in new[] { _path, _path + "-wal", _path + "-shm" })
        {
            try
            {
                File.Delete(f);
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public void Tokens_AreRandom_AndOnlyHashIsStored()
    {
        using var db = GuardDb.Open(_path);
        var now = DateTime.UtcNow;
        var a = ApiTokens.Create(new Repository(db), "a", now);
        var b = ApiTokens.Create(new Repository(db), "b", now);
        Assert.NotEqual(a, b);
        Assert.StartsWith("rg_", a);
        Assert.True(a.Length >= 40);

        Assert.Equal(0, db.ScalarLong("SELECT COUNT(*) FROM api_tokens WHERE token_hash = $t OR prefix = $t", ("$t", a)));
        Assert.Equal("a", ApiTokens.Validate(db, a));
        Assert.Throws<ArgumentException>(() => ApiTokens.Create(new Repository(db), "a", now));
    }

    [Fact]
    public void SchemaV1_IsMigratedToV2()
    {
        using (var db = GuardDb.Open(_path))
        {
            db.Exec("DROP TABLE api_tokens");
            db.SetState("schema_version", "1");
        }

        using var upgraded = GuardDb.Open(_path);
        Assert.Equal(GuardDb.SchemaVersion, upgraded.CurrentSchemaVersion);
        Assert.Equal(0, upgraded.ScalarLong("SELECT COUNT(*) FROM api_tokens"));
    }
}

public class PrometheusWriterTests
{
    [Fact]
    public void QueueLength_FromServiceChannel_IsReported()
    {
        // Канал создаётся так же, как в GuardService.
        var channel = System.Threading.Channels.Channel.CreateUnbounded<Events.WorkItem>(
            new System.Threading.Channels.UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
        channel.Writer.TryWrite(new Events.TickWork(Events.TickKind.Quick));
        Assert.True(channel.Reader.CanCount);

        var metrics = new GuardMetrics { QueueLength = () => channel.Reader.Count };
        var text = PrometheusWriter.Render(metrics, null, false, "1.0", DateTime.UtcNow);
        Assert.Contains("\nrdpguard_queue_length 1\n", text);
    }

    [Fact]
    public void FailingOptionalMetric_DoesNotBreakResponse()
    {
        var metrics = new GuardMetrics { QueueLength = () => throw new NotSupportedException() };
        var text = PrometheusWriter.Render(metrics, null, false, "1.0", DateTime.UtcNow);
        Assert.DoesNotContain("rdpguard_queue_length", text);
        Assert.Contains("rdpguard_database_up 0", text);
    }

    [Fact]
    public void LabelValues_AreEscaped()
    {
        var metrics = new GuardMetrics();
        metrics.EventsRead.Inc(@"we""ird\chan");
        var text = PrometheusWriter.Render(metrics, null, false, "1.0", DateTime.UtcNow);
        Assert.Contains(@"rdpguard_events_read_total{channel=""we\""ird\\chan""} 1", text);
    }
}
