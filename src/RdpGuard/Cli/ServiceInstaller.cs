using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using RdpGuard.Engine;
using RdpGuard.Hosting;

namespace RdpGuard.Cli;

/// <summary>Регистрация службы через sc.exe: LocalSystem, автозапуск, перезапуск при сбое.</summary>
[SupportedOSPlatform("windows")]
public static class ServiceInstaller
{
    private const string Name = ServiceHost.ServiceName;

    public static ServiceControllerStatus? GetStatus()
    {
        try
        {
            using var sc = new ServiceController(Name);
            return sc.Status;
        }
        catch (InvalidOperationException)
        {
            return null; // служба не установлена
        }
    }

    public static bool IsRunning() => GetStatus() is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;

    public static void InstallOrUpdate(string exePath)
    {
        string binPath = "\"" + exePath + "\"";
        if (GetStatus() is null)
        {
            Sc("create", Name, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem",
                "DisplayName=", "RdpGuard", "depend=", "EventLog/MpsSvc");
        }
        else
        {
            Sc("config", Name, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem",
                "DisplayName=", "RdpGuard", "depend=", "EventLog/MpsSvc");
        }
        Sc("description", Name, "Bans IP addresses that brute-force Windows logons (RDP/SMB) in Windows Firewall.");
        // Перезапуск через 5 с, 15 с, 60 с; счётчик сбоев обнуляется через сутки.
        Sc("failure", Name, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000");
        // Считать сбоем и остановку с ненулевым кодом выхода.
        Sc("failureflag", Name, "1");
    }

    public static void Start(TimeSpan timeout)
    {
        using var sc = new ServiceController(Name);
        if (sc.Status is ServiceControllerStatus.Running) return;
        sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
    }

    public static void Stop(TimeSpan timeout)
    {
        using var sc = new ServiceController(Name);
        if (sc.Status is ServiceControllerStatus.Stopped) return;
        if (sc.Status is not ServiceControllerStatus.StopPending) sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
    }

    public static void Delete() => Sc("delete", Name);

    public static void EnsureEventSource()
    {
        if (!EventLog.SourceExists(LogEvents.EventSourceName))
            EventLog.CreateEventSource(new EventSourceCreationData(LogEvents.EventSourceName, "Application"));
    }

    public static void DeleteEventSource()
    {
        if (EventLog.SourceExists(LogEvents.EventSourceName)) EventLog.DeleteEventSource(LogEvents.EventSourceName);
    }

    private static void Sc(params string[] args)
    {
        var psi = new ProcessStartInfo("sc.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new CliException("Cannot start sc.exe");
        var output = new StringBuilder();
        output.Append(p.StandardOutput.ReadToEnd());
        output.Append(p.StandardError.ReadToEnd());
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new CliException($"sc.exe {args[0]} failed with code {p.ExitCode}: {output.ToString().Trim()}");
    }
}
