using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using RdpGuard.Configuration;
using RdpGuard.Engine;
using RdpGuard.Events;
using RdpGuard.Firewall;
using RdpGuard.Logging;

namespace RdpGuard.Hosting;

[SupportedOSPlatform("windows")]
public static class ServiceHost
{
    public const string ServiceName = "RdpGuard";

    public static IConfigurationRoot LoadConfiguration() =>
        new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .AddEnvironmentVariables("RDPGUARD_")
            .Build();

    public static int Run(string[] args, bool asService)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.Configuration.AddEnvironmentVariables("RDPGUARD_");

        var options = GuardOptions.Load(builder.Configuration);
        var errors = options.Validate();
        if (errors.Count > 0)
        {
            var text = "Invalid configuration:" + Environment.NewLine + string.Join(Environment.NewLine, errors);
            Console.Error.WriteLine(text);
            TryWriteEventLog(text, EventLogEntryType.Error);
            return 2;
        }

        builder.Services.AddWindowsService(o => o.ServiceName = ServiceName);
        builder.Services.Configure<HostOptions>(o =>
        {
            o.ShutdownTimeout = TimeSpan.FromSeconds(20);
            o.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.StopHost;
        });

        ConfigureLogging(builder.Logging, options, console: !asService);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IFirewall, ComFirewall>();
        builder.Services.AddSingleton<IAuthEventSource, EventLogAuthSource>();
        builder.Services.AddHostedService<GuardService>();

        using var host = builder.Build();
        host.Run();
        return Environment.ExitCode;
    }

    private static void ConfigureLogging(ILoggingBuilder logging, GuardOptions options, bool console)
    {
        logging.ClearProviders();
        if (console) logging.AddSimpleConsole(o =>
        {
            o.SingleLine = true;
            o.TimestampFormat = "HH:mm:ss ";
        });

        if (options.FileLog.Enabled)
        {
            try
            {
                var provider = new RollingFileLoggerProvider(options.LogDirectory,
                    (long)options.FileLog.MaxFileSizeMB * 1024 * 1024, options.FileLog.RetainedFiles);
                logging.Services.AddSingleton<ILoggerProvider>(provider);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"File logging disabled: {ex.Message}");
            }
        }

        // Источник журнала создаётся командой install; без прав администратора создать его нельзя,
        // а провайдер EventLog при отсутствии источника бросал бы исключения из логгера.
        if (EventSourceExists())
        {
            logging.AddEventLog(new EventLogSettings
            {
                SourceName = LogEvents.EventSourceName,
                LogName = "Application",
            });
            logging.AddFilter<EventLogLoggerProvider>(null, LogLevel.Warning);
            logging.AddFilter<EventLogLoggerProvider>(LogEvents.AuditCategory, LogLevel.Information);
        }
    }

    public static bool EventSourceExists()
    {
        try
        {
            return EventLog.SourceExists(LogEvents.EventSourceName);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void TryWriteEventLog(string message, EventLogEntryType type, int eventId = 1900)
    {
        try
        {
            if (EventSourceExists()) EventLog.WriteEntry(LogEvents.EventSourceName, message, type, eventId);
        }
        catch (Exception)
        {
            // ignore
        }
    }
}
