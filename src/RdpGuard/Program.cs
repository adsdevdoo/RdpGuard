using Microsoft.Extensions.Hosting.WindowsServices;
using RdpGuard.Cli;
using RdpGuard.Hosting;

namespace RdpGuard;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("RdpGuard runs on Windows only.");
            return 1;
        }

        if (WindowsServiceHelpers.IsWindowsService())
            return ServiceHost.Run(args, asService: true);

        if (args.Length > 0 && string.Equals(args[0], "run", StringComparison.OrdinalIgnoreCase))
        {
            // Два экземпляра — два писателя и две конкурирующие синхронизации брандмауэра.
            if (CliApp.IsServiceRunningForConsoleRun())
            {
                Console.Error.WriteLine("The RdpGuard service is running; stop it before using 'run'.");
                return 2;
            }
            return ServiceHost.Run(args[1..], asService: false);
        }

        return CliApp.Run(args);
    }
}
