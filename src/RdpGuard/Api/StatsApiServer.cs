using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;
using RdpGuard.Net;

namespace RdpGuard.Api;

/// <summary>
/// HTTP API статистики для Grafana: /metrics (Prometheus) и /api/* (JSON, например для плагина Infinity).
/// Только чтение: каждый запрос открывает собственное read-only подключение к SQLite и не мешает писателю.
/// </summary>
public sealed class StatsApiServer : BackgroundService
{
    private const int MaxConcurrentRequests = 4;
    private const int MaxLimit = 1000;
    private const int MaxHours = 24 * 90;
    private const int MaxPoints = 5000;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false,
        Converters = { new UtcDateTimeConverter() },
    };

    private readonly GuardOptions _options;
    private readonly GuardMetrics _metrics;
    private readonly TimeProvider _time;
    private readonly ILogger _log;
    private readonly IpCidr[] _allowed;
    private readonly bool _requireToken;
    private readonly Dictionary<string, DateTime> _authFailureLog = new();
    private readonly SemaphoreSlim _gate = new(MaxConcurrentRequests);
    private readonly string _version;
    private HttpListener? _listener;

    public StatsApiServer(GuardOptions options, GuardMetrics metrics, TimeProvider time, ILogger<StatsApiServer> log)
    {
        _options = options;
        _metrics = metrics;
        _time = time;
        _log = log;
        _allowed = options.Api.EffectiveAllowedClients.Select(IpCidr.Parse).ToArray();
        _requireToken = options.Api.RequireToken;
        _version = typeof(StatsApiServer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                   ?? typeof(StatsApiServer).Assembly.GetName().Version?.ToString() ?? "0";
        int plus = _version.IndexOf('+');
        if (plus > 0) _version = _version[..plus];
    }

    /// <summary>Адреса, на которых реально запущен сервер (для тестов).</summary>
    public IReadOnlyCollection<string> Prefixes => _listener?.Prefixes.ToList() ?? new List<string>();

    public bool IsListening => _listener?.IsListening == true;

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Api.Enabled) return Task.CompletedTask;
        var listener = new HttpListener { IgnoreWriteExceptions = true };
        foreach (var url in _options.Api.EffectiveUrls) listener.Prefixes.Add(url);
        try
        {
            listener.Start();
            _listener = listener;
            _log.LogInformation("Statistics API listening on {Urls}", string.Join(", ", _options.Api.EffectiveUrls));
        }
        catch (Exception ex)
        {
            // API не главное: без него служба продолжает банить.
            _log.LogError(LogEvents.Error, ex, "Statistics API could not start on {Urls}", string.Join(", ", _options.Api.EffectiveUrls));
            listener.Close();
            return Task.CompletedTask;
        }
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listener = _listener;
        if (listener is null) return;
        using var stopRegistration = stoppingToken.Register(() => listener.Stop());

        while (!stoppingToken.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception) when (stoppingToken.IsCancellationRequested || !listener.IsListening)
            {
                break;
            }
            catch (HttpListenerException ex)
            {
                _log.LogWarning(ex, "Statistics API accept failed");
                continue;
            }

            if (!await _gate.WaitAsync(TimeSpan.FromSeconds(10), stoppingToken).ConfigureAwait(false))
            {
                TryRespond(context, 503, "text/plain", "busy");
                continue;
            }
            _ = Task.Run(() =>
            {
                try
                {
                    Handle(context);
                }
                finally
                {
                    _gate.Release();
                }
            }, CancellationToken.None);
        }
    }

    public override void Dispose()
    {
        _listener?.Close();
        base.Dispose();
    }

    private void Handle(HttpListenerContext context)
    {
        var request = context.Request;
        try
        {
            var remote = request.RemoteEndPoint?.Address;
            if (remote is null || !IsAllowed(remote))
            {
                TryRespond(context, 403, "text/plain", "forbidden");
                return;
            }
            if (request.HttpMethod != "GET" && request.HttpMethod != "HEAD")
            {
                TryRespond(context, 405, "text/plain", "method not allowed");
                return;
            }

            var path = (request.Url?.AbsolutePath ?? "/").TrimEnd('/').ToLowerInvariant();

            // /health без токена — для проверок доступности; остальное только с действующим токеном.
            if (_requireToken && path != "/health" && !IsAuthorized(request.Headers["Authorization"], remote))
            {
                context.Response.AddHeader("WWW-Authenticate", "Bearer realm=\"RdpGuard\"");
                TryRespond(context, 401, "text/plain", "unauthorized: send 'Authorization: Bearer <token>' (create one with 'RdpGuard api-token create <name>')");
                return;
            }
            var q = request.QueryString;
            var now = _time.GetUtcNow().UtcDateTime;

            switch (path)
            {
                case "" or "/api":
                    WriteJson(context, new
                    {
                        name = "RdpGuard statistics API",
                        version = _version,
                        endpoints = new[]
                        {
                            "/metrics", "/health", "/api/summary", "/api/bans?active=true&limit=100",
                            "/api/top?hours=24&limit=20", "/api/users?hours=24&limit=20",
                            "/api/timeseries/attempts?hours=24&step=300", "/api/timeseries/bans?hours=168&step=3600",
                        },
                    });
                    break;

                case "/health":
                    TryRespond(context, 200, "text/plain", "ok");
                    break;

                case "/metrics":
                    StatsSummary? summary = null;
                    try
                    {
                        summary = WithDb(db => new StatsQueries(db).Summary(now));
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Metrics: database is not readable");
                    }
                    TryRespond(context, 200, PrometheusWriter.ContentType,
                        PrometheusWriter.Render(_metrics, summary, _options.DryRun, _version, now));
                    break;

                case "/api/summary":
                    WriteJson(context, WithDb(db =>
                    {
                        var s = new StatsQueries(db).Summary(now);
                        return new
                        {
                            s.GeneratedUtc,
                            dryRun = _options.DryRun,
                            s.ActiveBans,
                            s.PermanentBans,
                            s.FailedLogons1h,
                            s.AttackingIps1h,
                            s.FailedLogons24h,
                            s.AttackingIps24h,
                            s.Bans24h,
                            s.ExternalLogons24h,
                            s.TrackedIps,
                            s.WhitelistEntries,
                            s.TotalBans,
                            s.ActiveBansByOffense,
                            s.LastFailureUtc,
                            accountAttacks = s.AccountAttacks,
                            firewallRules = _metrics.LastFirewallSync?.Rules,
                            firewallAddresses = _metrics.LastFirewallSync?.Addresses,
                            lastFirewallSyncUtc = _metrics.LastFirewallSyncUtc,
                            startedUtc = _metrics.StartedUtc,
                        };
                    }));
                    break;

                case "/api/bans":
                    bool activeOnly = Bool(q["active"], false);
                    int banLimit = Int(q["limit"], 100, 1, MaxLimit);
                    string? ip = q["ip"] is { Length: > 0 } t ? IpUtil.Normalize(t) ?? throw new ArgumentException("invalid ip") : null;
                    WriteJson(context, WithDb(db => new Repository(db).GetBans(activeOnly, now, banLimit, ip).Select(b => new
                    {
                        b.Id,
                        b.Ip,
                        b.OffenseNo,
                        b.BannedAtUtc,
                        b.ExpiresAtUtc,
                        permanent = b.ExpiresAtUtc is null,
                        active = b.IsActive(now),
                        remainingSeconds = b.IsActive(now) && b.ExpiresAtUtc is { } e ? (long?)(e - now).TotalSeconds : null,
                        b.FailuresInWindow,
                        b.Reason,
                        b.UnbannedAtUtc,
                        b.UnbanReason,
                    }).ToList()));
                    break;

                case "/api/top":
                    int topHours = Int(q["hours"], 24, 1, MaxHours);
                    int topLimit = Int(q["limit"], 20, 1, MaxLimit);
                    WriteJson(context, WithDb(db => new StatsQueries(db).TopIps(now.AddHours(-topHours), topLimit, now).Select(r => new
                    {
                        r.Ip,
                        r.Attempts,
                        r.Users,
                        r.FirstUtc,
                        r.LastUtc,
                        r.Offenses,
                        r.Banned,
                        r.BanExpiresUtc,
                        r.BanPermanent,
                        topUsers = string.Join(", ", r.TopUsers.Select(u => $"{u.User}({u.Attempts})")),
                    }).ToList()));
                    break;

                case "/api/users":
                    int userHours = Int(q["hours"], 24, 1, MaxHours);
                    int userLimit = Int(q["limit"], 20, 1, MaxLimit);
                    WriteJson(context, WithDb(db => new StatsQueries(db).TopUsers(now.AddHours(-userHours), userLimit)));
                    break;

                case "/api/timeseries/attempts":
                case "/api/timeseries/bans":
                    int hours = Int(q["hours"], path.EndsWith("bans", StringComparison.Ordinal) ? 168 : 24, 1, MaxHours);
                    int step = Int(q["step"], path.EndsWith("bans", StringComparison.Ordinal) ? 3600 : 300, 60, 86400);
                    if ((long)hours * 3600 / step > MaxPoints) step = (int)Math.Ceiling(hours * 3600.0 / MaxPoints);
                    var since = now.AddHours(-hours);
                    WriteJson(context, WithDb(db =>
                    {
                        var stats = new StatsQueries(db);
                        var points = path.EndsWith("bans", StringComparison.Ordinal)
                            ? stats.BansSeries(since, now, step)
                            : stats.AttemptsSeries(since, now, step);
                        return points.Select(p => new
                        {
                            time = p.TimeUtc,
                            timeMs = new DateTimeOffset(p.TimeUtc).ToUnixTimeMilliseconds(),
                            count = p.Count,
                            ips = p.Ips,
                        }).ToList();
                    }));
                    break;

                default:
                    TryRespond(context, 404, "text/plain", "not found");
                    break;
            }
        }
        catch (ArgumentException ex)
        {
            TryRespond(context, 400, "text/plain", ex.Message);
        }
        catch (FileNotFoundException)
        {
            TryRespond(context, 503, "text/plain", "database is not created yet");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Statistics API request {Path} failed", request.Url?.AbsolutePath);
            TryRespond(context, 500, "text/plain", "internal error");
        }
    }

    private T WithDb<T>(Func<GuardDb, T> query)
    {
        using var db = GuardDb.OpenReadOnly(_options.DatabasePath);
        return query(db);
    }

    private bool IsAllowed(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return _allowed.Any(c => c.Contains(address));
    }

    private bool IsAuthorized(string? header, IPAddress remote)
    {
        string? name = null;
        if (header is not null && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                name = WithDb(db => ApiTokens.Validate(db, header[7..].Trim()));
            }
            catch (FileNotFoundException)
            {
                name = null;
            }
        }
        if (name is not null) return true;

        // Не чаще раза в минуту на адрес, чтобы перебор токенов не забивал лог.
        var now = _time.GetUtcNow().UtcDateTime;
        var key = remote.ToString();
        bool log;
        lock (_authFailureLog)
        {
            log = !_authFailureLog.TryGetValue(key, out var last) || now - last >= TimeSpan.FromMinutes(1);
            if (log) _authFailureLog[key] = now;
            if (_authFailureLog.Count > 10_000) _authFailureLog.Clear();
        }
        if (log) _log.LogWarning("Statistics API: rejected request from {Ip} ({Reason})", key, header is null ? "no token" : "invalid or revoked token");
        return false;
    }

    private static int Int(string? value, int defaultValue, int min, int max)
    {
        if (string.IsNullOrEmpty(value)) return defaultValue;
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
            throw new ArgumentException($"'{value}' is not an integer");
        return Math.Clamp(n, min, max);
    }

    private static bool Bool(string? value, bool defaultValue) =>
        string.IsNullOrEmpty(value) ? defaultValue : value is "1" or "true" or "True" or "yes";

    private static void WriteJson(HttpListenerContext context, object value) =>
        TryRespond(context, 200, "application/json; charset=utf-8", JsonSerializer.Serialize(value, Json));

    private static void TryRespond(HttpListenerContext context, int status, string contentType, string body)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            var response = context.Response;
            response.StatusCode = status;
            response.ContentType = contentType;
            response.Headers["Cache-Control"] = "no-store";
            response.ContentLength64 = bytes.Length;
            if (context.Request.HttpMethod != "HEAD") response.OutputStream.Write(bytes);
            response.Close();
        }
        catch (Exception)
        {
            // клиент отключился
        }
    }

    /// <summary>Время в JSON — ISO 8601 UTC с "Z".</summary>
    private sealed class UtcDateTimeConverter : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.GetDateTime().ToUniversalTime();

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) =>
            writer.WriteStringValue(DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
    }
}
