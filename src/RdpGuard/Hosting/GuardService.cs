using System.Runtime.Versioning;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;
using RdpGuard.Events;
using RdpGuard.Firewall;

namespace RdpGuard.Hosting;

[SupportedOSPlatform("windows")]
public sealed class GuardService : BackgroundService
{
    private static readonly TimeSpan QuickTick = TimeSpan.FromSeconds(5);
    private const int MaintenanceEveryQuickTicks = 12; // 12 * 5 c = раз в минуту

    private readonly GuardOptions _options;
    private readonly IFirewall _firewall;
    private readonly IAuthEventSource _source;
    private readonly TimeProvider _time;
    private readonly ILoggerFactory _loggers;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly GuardMetrics _metrics;
    private readonly ILogger _log;

    public GuardService(GuardOptions options, IFirewall firewall, IAuthEventSource source, TimeProvider time,
        ILoggerFactory loggers, IHostApplicationLifetime lifetime, GuardMetrics metrics)
    {
        _metrics = metrics;
        _options = options;
        _firewall = firewall;
        _source = source;
        _time = time;
        _loggers = loggers;
        _lifetime = lifetime;
        _log = loggers.CreateLogger("RdpGuard.Service");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();

        GuardDb db;
        GuardEngine engine;
        try
        {
            db = GuardDb.Open(_options.DatabasePath);
            engine = new GuardEngine(_options, db, _firewall, RdpPortResolver.Resolve(_options.Firewall), _time, _loggers, _metrics);
            engine.Initialize();
        }
        catch (Exception ex)
        {
            // Без БД работать нельзя: ненулевой код выхода — SCM перезапустит службу по настройкам восстановления.
            _log.LogCritical(LogEvents.Error, ex, "RdpGuard failed to start");
            Environment.ExitCode = 1;
            _lifetime.StopApplication();
            return;
        }

        if (!_options.DryRun && ComFirewall.IsEnabledForCurrentProfiles() == false)
            _log.LogWarning(LogEvents.FirewallError, "Windows Firewall is disabled for an active profile: bans will have no effect");

        var channel = Channel.CreateUnbounded<WorkItem>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
        });

        _metrics.QueueLength = () => channel.Reader.Count;

        using var tickerCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var ticker = RunTickerAsync(channel.Writer, tickerCts.Token);
        try
        {
            _source.Start(channel.Writer, engine.GetBookmark);
            await engine.RunAsync(channel.Reader, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // остановка службы
        }
        finally
        {
            _source.Dispose();
            tickerCts.Cancel();
            channel.Writer.TryComplete();
            try
            {
                await ticker;
            }
            catch (OperationCanceledException)
            {
            }
            db.Dispose();
            _log.LogInformation("RdpGuard stopped");
        }
    }

    private static async Task RunTickerAsync(ChannelWriter<WorkItem> writer, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(QuickTick);
        int n = 0;
        while (await timer.WaitForNextTickAsync(ct))
        {
            n++;
            var kind = n % MaintenanceEveryQuickTicks == 0 ? TickKind.Quick | TickKind.Maintenance : TickKind.Quick;
            writer.TryWrite(new TickWork(kind));
        }
    }
}
