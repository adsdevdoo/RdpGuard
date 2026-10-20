using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using RdpGuard.Api;
using RdpGuard.Configuration;
using RdpGuard.Data;
using RdpGuard.Engine;
using RdpGuard.Events;
using RdpGuard.Firewall;
using RdpGuard.Hosting;
using RdpGuard.Net;
using RdpGuard.Policy;

namespace RdpGuard.Cli;

[SupportedOSPlatform("windows")]
public static class CliApp
{
    private const string Help = """
        RdpGuard — bans IP addresses that brute-force Windows logons.

        Usage: RdpGuard <command> [options]

        Service:
          install [--no-start]        Register the Windows service (LocalSystem, automatic start,
                                      restart on failure) and the Application event log source.
          uninstall [--purge]         Stop and remove the service and ALL RdpGuard-* firewall rules.
                                      --purge also deletes the database and logs.
          run                         Run in the console (for diagnostics; the service must be stopped).
          status                      Service state, mode, active bans, recent attempts.

        Bans:
          bans [--active] [--limit N] [--ip IP]
                                      Ban history with expiry and offense number.
          top [--hours 24] [--limit 20]
                                      Top attacking IPs and targeted user names.
          ban <ip> [--days N | --hours N | --permanent] [--reason TEXT] [--force]
                                      Ban manually. Without a duration the escalating policy is used.
          unban <ip> [--reset]        Lift the active ban; --reset also zeroes the offense counter.

        Whitelist:
          allow <ip|cidr> [--note TEXT]   Never ban this address/network (lifts matching bans).
          disallow <ip|cidr>              Remove a whitelist entry added with 'allow'.
          whitelist                       Show all whitelist entries.

        Statistics API (Grafana / Prometheus):
          api-token create <name>     Create an API token (shown once; only its hash is stored).
          api-token list              List tokens.
          api-token revoke <name>     Revoke a token immediately.

        Other:
          export --csv [--out DIR]    Write ips.csv and bans.csv (default: current directory).
          sync                        Reconcile firewall rules with the database now.

        Configuration: appsettings.json next to RdpGuard.exe (defaults, replaced on update), overridden by
        %ProgramData%\RdpGuard\appsettings.local.json (this server's settings). All commands require an elevated prompt.
        """;

    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "-h" or "--help" or "/?" or "-?")
        {
            Console.WriteLine(Help);
            return args.Length == 0 ? 1 : 0;
        }

        var command = args[0].ToLowerInvariant();
        var a = new CliArgs(args.Skip(1));
        try
        {
            return command switch
            {
                "install" => Install(a),
                "uninstall" => Uninstall(a),
                "status" => Status(a),
                "bans" => Bans(a),
                "top" => Top(a),
                "ban" => Ban(a),
                "unban" => Unban(a),
                "allow" => Allow(a),
                "disallow" => Disallow(a),
                "whitelist" => Whitelist(a),
                "export" => Export(a),
                "sync" => Sync(a),
                "api-token" => ApiToken(a),
                _ => throw new CliException($"Unknown command '{args[0]}'. Run 'RdpGuard help'."),
            };
        }
        catch (Exception ex) when (ex is CliException or AdminException)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex);
            return 1;
        }
    }

    // ---------------- infrastructure ----------------

    private static GuardOptions LoadOptions()
    {
        var options = GuardOptions.Load(ServiceHost.LoadConfiguration());
        var errors = options.Validate();
        if (errors.Count > 0) throw new CliException("Invalid configuration:\n  " + string.Join("\n  ", errors));
        return options;
    }

    private static void RequireAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new CliException("This command must be run from an elevated (Administrator) prompt.");
    }

    private sealed class Context : IDisposable
    {
        public Context()
        {
            RequireAdmin();
            Options = LoadOptions();
            Db = GuardDb.Open(Options.DatabasePath);
            Repo = new Repository(Db);
            Admin = new AdminOperations(Options, Repo);
        }

        public GuardOptions Options { get; }
        public GuardDb Db { get; }
        public Repository Repo { get; }
        public AdminOperations Admin { get; }
        public DateTime Now => DateTime.UtcNow;

        public void Dispose() => Db.Dispose();
    }

    private static ILogger AuditLogger()
    {
        // CLI пишет аудит ручных действий в журнал Application, файл лога принадлежит службе.
        if (!ServiceHost.EventSourceExists()) return Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var factory = LoggerFactory.Create(b => b.AddEventLog(new EventLogSettings
        {
            SourceName = LogEvents.EventSourceName,
            LogName = "Application",
        }).SetMinimumLevel(LogLevel.Information));
        return factory.CreateLogger(LogEvents.AuditCategory);
    }

    /// <summary>
    /// После изменения БД: работающая служба увидит новую ревизию в течение ~5 секунд.
    /// Если служба не запущена — синхронизируем брандмауэр сами.
    /// </summary>
    private static void ApplyToFirewall(Context ctx)
    {
        if (ServiceInstaller.IsRunning())
        {
            Console.WriteLine("The service will apply the change within a few seconds.");
            return;
        }
        if (ctx.Options.DryRun)
        {
            Console.WriteLine("DryRun is enabled: the firewall is not modified.");
            return;
        }
        var wl = ctx.Admin.LoadWhitelist();
        var ips = ctx.Repo.GetActiveBannedIps(ctx.Now).Where(ip => !wl.IsWhitelisted(ip)).ToList();
        var result = new FirewallSync(new ComFirewall(), ctx.Options.Firewall, RdpPortResolver.Resolve(ctx.Options.Firewall)).Sync(ips);
        Console.WriteLine($"Service is not running; firewall updated directly: {result}");
    }

    private static string Local(DateTime? utc) =>
        utc is { } t ? t.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "";

    private static string Remaining(BanRow b, DateTime now)
    {
        if (!b.IsActive(now)) return "";
        if (b.ExpiresAtUtc is not { } e) return "forever";
        return FormatLeft(e - now);
    }

    private static string FormatLeft(TimeSpan left)
    {
        return left.TotalDays >= 1 ? $"{(int)left.TotalDays}d {left.Hours}h"
            : left.TotalHours >= 1 ? $"{(int)left.TotalHours}h {left.Minutes}m"
            : $"{Math.Max(0, (int)left.TotalMinutes)}m";
    }

    // ---------------- service ----------------

    private static int Install(CliArgs a)
    {
        a.EnsureKnown("no-start");
        RequireAdmin();
        var exe = Environment.ProcessPath ?? throw new CliException("Cannot determine the executable path.");
        if (Path.GetFileName(exe).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
            throw new CliException("Run 'install' from the published RdpGuard.exe, not via 'dotnet'.");

        var options = LoadOptions();
        Directory.CreateDirectory(options.ResolvedDataDirectory);
        using (var db = GuardDb.Open(options.DatabasePath))
            Console.WriteLine($"Database:   {db.Path} (schema v{db.CurrentSchemaVersion})");
        Console.WriteLine(ServiceInstaller.SecureDataDirectory(options.ResolvedDataDirectory)
            ? "Access:     data folder restricted to SYSTEM and Administrators"
            : $"Access:     folder name does not contain 'RdpGuard'; permissions of {options.ResolvedDataDirectory} left unchanged");

        if (ConfigSources.LocalPath is { } localConfig && !File.Exists(localConfig))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(localConfig)!);
            File.WriteAllText(localConfig, ConfigSources.LocalTemplate + Environment.NewLine);
            Console.WriteLine($"Config:     created {localConfig} for this server's settings");
        }

        ServiceInstaller.EnsureEventSource();
        Console.WriteLine("Event log:  source 'RdpGuard' in the Application log");

        try
        {
            var before = LogonAuditPolicy.Query();
            Console.WriteLine(LogonAuditPolicy.EnsureEnabled()
                ? $"Auditing:   logon auditing was '{before}', enabled Success and Failure"
                : "Auditing:   logon auditing already logs Success and Failure");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Auditing:   could not enable logon auditing ({ex.Message}); " +
                              "run: auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable");
        }

        bool existed = ServiceInstaller.GetStatus() is not null;
        if (existed && ServiceInstaller.IsRunning()) ServiceInstaller.Stop(TimeSpan.FromSeconds(30));
        ServiceInstaller.InstallOrUpdate(exe);
        Console.WriteLine($"Service:    {(existed ? "updated" : "installed")} ({exe})");

        if (!a.Has("no-start"))
        {
            ServiceInstaller.Start(TimeSpan.FromSeconds(30));
            Console.WriteLine("Service:    started");
        }

        Console.WriteLine();
        Console.WriteLine(options.DryRun
            ? "Mode: DRY RUN. Bans are recorded but the firewall is NOT modified.\n" +
              "Check 'RdpGuard bans' and 'RdpGuard top' for a while, then set \"DryRun\": false in\n" +
              $"{Path.Combine(AppContext.BaseDirectory, "appsettings.json")} and restart the service."
            : "Mode: ENFORCING. Banned addresses are blocked in Windows Firewall.");
        return 0;
    }

    private static int Uninstall(CliArgs a)
    {
        a.EnsureKnown("purge");
        RequireAdmin();
        var options = LoadOptions();

        if (ServiceInstaller.GetStatus() is not null)
        {
            ServiceInstaller.Stop(TimeSpan.FromSeconds(30));
            ServiceInstaller.Delete();
            Console.WriteLine("Service:    stopped and removed");
        }
        else
        {
            Console.WriteLine("Service:    not installed");
        }

        int removed = new FirewallSync(new ComFirewall(), options.Firewall, RdpPortResolver.DefaultPort).RemoveAll();
        Console.WriteLine($"Firewall:   removed {removed} RdpGuard-* rule(s)");

        if (a.Has("purge"))
        {
            var dir = options.ResolvedDataDirectory;
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
                Console.WriteLine($"Data:       deleted {dir}");
            }
            try
            {
                ServiceInstaller.DeleteEventSource();
                Console.WriteLine("Event log:  source removed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Event log:  could not remove the source ({ex.Message})");
            }
        }
        else
        {
            Console.WriteLine($"Data:       kept in {options.ResolvedDataDirectory} (use --purge to delete)");
        }
        return 0;
    }

    private static int Status(CliArgs a)
    {
        a.EnsureKnown();
        using var ctx = new Context();
        var now = ctx.Now;
        var db = ctx.Db;

        var status = ServiceInstaller.GetStatus();
        Console.WriteLine($"Service:          {(status is null ? "not installed" : status.ToString())}");
        Console.WriteLine($"Mode:             {(ctx.Options.DryRun ? "DRY RUN (firewall is not modified)" : "enforcing")}");
        Console.WriteLine($"Database:         {db.Path} (schema v{db.CurrentSchemaVersion})");
        Console.WriteLine($"Config:           {string.Join(" + ", ConfigSources.LoadedFiles())}");
        Console.WriteLine($"Ban rules:        {BanPolicy.DescribeRules(ctx.Options.Policy)}");
        Console.WriteLine($"Ban duration:     {BanPolicy.FormatSpan(ctx.Options.Policy.BaseBanDuration)} x2 per offense, max {BanPolicy.FormatSpan(ctx.Options.Policy.MaxBanDuration)}" +
                          (ctx.Options.Policy.PermanentAfterOffenses > 0 ? $", permanent after {ctx.Options.Policy.PermanentAfterOffenses} offenses" : ""));

        var active = ctx.Repo.GetActiveBans(now);
        Console.WriteLine($"Active bans:      {active.Count} (permanent: {active.Count(b => b.ExpiresAtUtc is null)})");

        foreach (var (label, span) in new[] { ("Attempts 1h:", TimeSpan.FromHours(1)), ("Attempts 24h:", TimeSpan.FromDays(1)) })
        {
            var since = DbTime.ToDb(now - span);
            long n = db.ScalarLong("SELECT COUNT(*) FROM attempts WHERE ts_utc >= $s", ("$s", since));
            long ips = db.ScalarLong("SELECT COUNT(DISTINCT ip) FROM attempts WHERE ts_utc >= $s", ("$s", since));
            Console.WriteLine($"{label,-17} {n} from {ips} IP(s)");
        }

        foreach (var attack in new StatsQueries(db).Summary(now).AccountAttacks.Take(3))
            Console.WriteLine($"Password guessing: {attack.User}: {attack.WrongPasswords} wrong password(s) from {attack.Ips} IP(s) in 24h");

        long bans24 = db.ScalarLong("SELECT COUNT(*) FROM bans WHERE banned_at_utc >= $s", ("$s", DbTime.ToDb(now.AddDays(-1))));
        long logons24 = db.ScalarLong("SELECT COUNT(*) FROM successes WHERE ts_utc >= $s", ("$s", DbTime.ToDb(now.AddDays(-1))));
        Console.WriteLine($"New bans 24h:     {bans24}");
        Console.WriteLine($"External logons:  {logons24} in 24h (see the Application log, event 1003)");

        try
        {
            var audit = LogonAuditPolicy.Query();
            Console.WriteLine($"Logon auditing:   {audit}" + (audit.IsComplete ? "" : "  <-- WARNING: failed logons may not be logged"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Logon auditing:   cannot read ({ex.Message})");
        }

        var sec = ctx.Repo.GetBookmark(EventParser.SecurityChannel);
        var rdp = ctx.Repo.GetBookmark(EventParser.RdpCoreTsChannel);
        Console.WriteLine($"Last record:      Security #{sec?.ToString(CultureInfo.InvariantCulture) ?? "-"}, RdpCoreTS #{rdp?.ToString(CultureInfo.InvariantCulture) ?? "-"}");

        try
        {
            var rules = new ComFirewall().GetRules(FirewallSync.ManagedPrefix);
            int addresses = rules.Sum(r => r.RemoteAddresses.Count);
            Console.WriteLine($"Firewall rules:   {rules.Count} RdpGuard-* rule(s), {addresses} address(es)");
            if (ComFirewall.IsEnabledForCurrentProfiles() == false)
                Console.WriteLine("WARNING:          Windows Firewall is disabled for an active profile!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Firewall rules:   cannot read ({ex.Message})");
        }
        return 0;
    }

    // ---------------- bans ----------------

    private static int Bans(CliArgs a)
    {
        a.EnsureKnown("active", "limit", "ip");
        using var ctx = new Context();
        var now = ctx.Now;
        string? ip = a.Get("ip") is { } t ? IpUtil.Normalize(t) ?? throw new CliException($"Invalid IP '{t}'") : null;
        var bans = ctx.Repo.GetBans(a.Has("active"), now, a.GetInt("limit", 100), ip);

        var table = new Table("ID", "IP", "#", "Banned", "Expires", "Left", "State", "Fails", "Reason");
        foreach (var b in bans)
        {
            string state = b.IsActive(now) ? "active"
                : b.UnbannedAtUtc is not null ? $"lifted: {b.UnbanReason}"
                : "expired";
            table.Add(b.Id, b.Ip, b.OffenseNo, Local(b.BannedAtUtc), b.ExpiresAtUtc is null ? "never" : Local(b.ExpiresAtUtc),
                Remaining(b, now), state, b.FailuresInWindow, b.Reason);
        }
        if (table.Count == 0)
        {
            Console.WriteLine(a.Has("active") ? "No active bans." : "No bans recorded.");
            return 0;
        }
        table.Print();
        Console.WriteLine($"\nTimes are local. {table.Count} row(s).{(ctx.Options.DryRun ? " DryRun: nothing is blocked in the firewall." : "")}");
        return 0;
    }

    private static int Top(CliArgs a)
    {
        a.EnsureKnown("hours", "limit");
        using var ctx = new Context();
        double hours = a.GetDouble("hours") ?? 24;
        int limit = a.GetInt("limit", 20);
        var now = ctx.Now;
        var since = now.AddHours(-hours);
        var stats = new StatsQueries(ctx.Db);
        string h = hours.ToString(CultureInfo.InvariantCulture);

        var top = stats.TopIps(since, limit, now);
        if (top.Count == 0)
        {
            Console.WriteLine($"No failed logons in the last {h} hour(s).");
            return 0;
        }

        Console.WriteLine($"Top IPs, last {h} hour(s):");
        var t = new Table("IP", "Attempts", "Users", "First", "Last", "Offenses", "Banned", "Most tried users");
        foreach (var row in top)
        {
            string banned = !row.Banned ? "" : row.BanPermanent ? "forever"
                : row.BanExpiresUtc is { } e ? FormatLeft(e - now) : "";
            t.Add(row.Ip, row.Attempts, row.Users, Local(row.FirstUtc), Local(row.LastUtc), row.Offenses, banned,
                string.Join(", ", row.TopUsers.Select(u => $"{u.User}({u.Attempts})")));
        }
        t.Print();

        Console.WriteLine();
        Console.WriteLine("Most targeted user names:");
        var u = new Table("User", "Attempts", "IPs");
        foreach (var row in stats.TopUsers(since, limit)) u.Add(row.User, row.Attempts, row.Ips);
        u.Print();
        return 0;
    }

    private static int ApiToken(CliArgs a)
    {
        a.EnsureKnown();
        var action = a.RequirePositional(0, "create | list | revoke").ToLowerInvariant();
        using var ctx = new Context();
        switch (action)
        {
            case "create":
            {
                var name = a.RequirePositional(1, "<name>");
                string token;
                try
                {
                    token = ApiTokens.Create(ctx.Repo, name, ctx.Now);
                }
                catch (ArgumentException ex)
                {
                    throw new CliException(ex.Message);
                }
                Console.WriteLine($"Token '{name}' created. Copy it now, it is not stored and will not be shown again:");
                Console.WriteLine();
                Console.WriteLine("  " + token);
                Console.WriteLine();
                Console.WriteLine("Use it as the HTTP header:  Authorization: Bearer <token>");
                if (!ctx.Options.Api.Enabled) Console.WriteLine("Note: the API is disabled (RdpGuard:Api:Enabled = false).");
                AuditLogger().LogWarning(LogEvents.ApiTokenChanged, "API token {Name} created by {User}", name, Environment.UserName);
                return 0;
            }
            case "list":
            {
                var t = new Table("Name", "Token", "Created", "State");
                foreach (var row in ApiTokens.List(ctx.Db))
                    t.Add(row.Name, row.Prefix, Local(row.CreatedUtc), row.RevokedUtc is { } r ? $"revoked {Local(r)}" : "active");
                if (t.Count == 0)
                {
                    Console.WriteLine("No API tokens. Create one with: RdpGuard api-token create <name>");
                    return 0;
                }
                t.Print();
                return 0;
            }
            case "revoke":
            {
                var name = a.RequirePositional(1, "<name>");
                if (!ApiTokens.Revoke(ctx.Db, name, ctx.Now))
                {
                    Console.WriteLine($"No active token named '{name}'.");
                    return 1;
                }
                Console.WriteLine($"Token '{name}' revoked; it is rejected starting with the next request.");
                AuditLogger().LogWarning(LogEvents.ApiTokenChanged, "API token {Name} revoked by {User}", name, Environment.UserName);
                return 0;
            }
            default:
                throw new CliException("Usage: api-token create <name> | api-token list | api-token revoke <name>");
        }
    }

    private static int Ban(CliArgs a)
    {
        a.EnsureKnown("days", "hours", "permanent", "reason", "force");
        var ip = a.RequirePositional(0, "<ip>");
        using var ctx = new Context();

        TimeSpan? duration = null;
        if (a.GetDouble("days") is { } d) duration = TimeSpan.FromDays(d);
        if (a.GetDouble("hours") is { } h) duration = (duration ?? TimeSpan.Zero) + TimeSpan.FromHours(h);
        bool permanent = a.Has("permanent");
        if (permanent && duration is not null) throw new CliException("Use either --permanent or --days/--hours.");

        var r = ctx.Admin.Ban(ip, duration, permanent, a.Get("reason"), a.Has("force"), ctx.Now);
        Console.WriteLine($"Banned {r.Ip}: offense #{r.OffenseNo}, " +
                          (r.ExpiresAtUtc is { } e ? $"until {Local(e)} (local)" : "permanently") +
                          (r.ReplacedExisting ? "; the previous active ban was replaced" : ""));
        AuditLogger().LogWarning(LogEvents.ManualBan, "Manual ban of {Ip} by {User}: offense #{Offense}, until {Expires}. {Reason}",
            r.Ip, Environment.UserName, r.OffenseNo, r.ExpiresAtUtc is { } x ? DbTime.ToDb(x) + " UTC" : "forever", a.Get("reason") ?? "");
        ApplyToFirewall(ctx);
        return 0;
    }

    private static int Unban(CliArgs a)
    {
        a.EnsureKnown("reset");
        var ip = a.RequirePositional(0, "<ip>");
        using var ctx = new Context();
        bool lifted = ctx.Admin.Unban(ip, a.Has("reset"), ctx.Now);
        var normalized = IpUtil.Normalize(ip);
        Console.WriteLine(lifted ? $"Unbanned {normalized}." : $"{normalized} has no active ban.");
        if (a.Has("reset")) Console.WriteLine("Offense counter reset to 0.");
        if (lifted)
            AuditLogger().LogWarning(LogEvents.ManualUnban, "Manual unban of {Ip} by {User}", normalized, Environment.UserName);
        ApplyToFirewall(ctx);
        return 0;
    }

    // ---------------- whitelist ----------------

    private static int Allow(CliArgs a)
    {
        a.EnsureKnown("note");
        var cidr = a.RequirePositional(0, "<ip|cidr>");
        using var ctx = new Context();
        var (key, unbanned) = ctx.Admin.Allow(cidr, a.Get("note"), ctx.Now);
        Console.WriteLine($"Whitelisted {key}.");
        if (unbanned.Count > 0) Console.WriteLine($"Lifted active bans: {string.Join(", ", unbanned)}");
        AuditLogger().LogWarning(LogEvents.WhitelistChanged, "Whitelist: {Cidr} added by {User}", key, Environment.UserName);
        ApplyToFirewall(ctx);
        return 0;
    }

    private static int Disallow(CliArgs a)
    {
        a.EnsureKnown();
        var cidr = a.RequirePositional(0, "<ip|cidr>");
        using var ctx = new Context();
        var (key, removed) = ctx.Admin.Disallow(cidr);
        if (!removed)
        {
            bool inConfig = ctx.Options.Whitelist.Cidrs.Any(c => IpCidr.TryParse(c, out var x) && x.ToString() == key);
            Console.WriteLine(inConfig
                ? $"{key} is defined in appsettings.json (RdpGuard:Whitelist:Cidrs); remove it there."
                : $"{key} is not in the whitelist.");
            return 1;
        }
        Console.WriteLine($"Removed {key} from the whitelist.");
        AuditLogger().LogWarning(LogEvents.WhitelistChanged, "Whitelist: {Cidr} removed by {User}", key, Environment.UserName);
        ApplyToFirewall(ctx);
        return 0;
    }

    private static int Whitelist(CliArgs a)
    {
        a.EnsureKnown();
        using var ctx = new Context();
        var t = new Table("Entry", "Source", "Added", "Note");
        if (ctx.Options.Whitelist.TrustPrivateRanges)
            foreach (var r in IpWhitelist.PrivateRanges) t.Add(r, "built-in", "", "private/special range");
        foreach (var c in ctx.Options.Whitelist.Cidrs) t.Add(c, "appsettings.json", "", "");
        foreach (var w in ctx.Repo.GetWhitelist()) t.Add(w.Cidr, "allow", Local(w.AddedUtc), w.Note);
        t.Print();
        return 0;
    }

    // ---------------- other ----------------

    private static int Export(CliArgs a)
    {
        a.EnsureKnown("csv", "out");
        if (!a.Has("csv")) throw new CliException("Specify the format: export --csv [--out DIR]");
        using var ctx = new Context();
        var dir = Path.GetFullPath(a.Get("out") ?? Directory.GetCurrentDirectory());
        Directory.CreateDirectory(dir);

        var ipsPath = Path.Combine(dir, "ips.csv");
        WriteCsv(ipsPath,
            new[] { "ip", "first_seen_utc", "last_seen_utc", "total_failures", "offenses", "last_offense_utc", "last_success_utc", "note", "whitelisted" },
            ctx.Repo.GetAllIps().Select(r => new object?[]
            {
                r.Ip, r.FirstSeenUtc, r.LastSeenUtc, r.TotalFailures, r.Offenses, r.LastOffenseUtc, r.LastSuccessUtc, r.Note, r.Whitelisted ? 1 : 0,
            }));

        var bansPath = Path.Combine(dir, "bans.csv");
        WriteCsv(bansPath,
            new[] { "id", "ip", "banned_at_utc", "expires_at_utc", "offense_no", "reason", "failures_in_window", "unbanned_at_utc", "unban_reason" },
            ctx.Repo.GetAllBans().Select(b => new object?[]
            {
                b.Id, b.Ip, b.BannedAtUtc, b.ExpiresAtUtc, b.OffenseNo, b.Reason, b.FailuresInWindow, b.UnbannedAtUtc, b.UnbanReason,
            }));

        Console.WriteLine($"Written {ipsPath}");
        Console.WriteLine($"Written {bansPath}");
        return 0;
    }

    private static void WriteCsv(string path, string[] header, IEnumerable<object?[]> rows)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(true));
        w.WriteLine(string.Join(",", header));
        foreach (var row in rows) w.WriteLine(string.Join(",", row.Select(CsvCell)));
    }

    private static string CsvCell(object? value)
    {
        string s = value switch
        {
            null => "",
            DateTime dt => DbTime.ToDb(dt),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? "",
        };
        // Защита от CSV-инъекций в Excel: имена пользователей приходят от атакующих.
        if (s.Length > 0 && "=+-@\t\r".Contains(s[0]) && value is string) s = "'" + s;
        return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;
    }

    private static int Sync(CliArgs a)
    {
        a.EnsureKnown();
        using var ctx = new Context();
        ctx.Repo.BumpAdminRevision();
        ApplyToFirewall(ctx);
        return 0;
    }

    public static bool IsServiceRunningForConsoleRun() => ServiceInstaller.IsRunning();
}
