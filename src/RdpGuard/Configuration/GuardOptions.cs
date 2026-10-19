using Microsoft.Extensions.Configuration;
using RdpGuard.Net;

namespace RdpGuard.Configuration;

public sealed class GuardOptions
{
    public const string SectionName = "RdpGuard";

    public bool DryRun { get; set; } = true;
    public string DataDirectory { get; set; } = @"%ProgramData%\RdpGuard";
    public DetectionOptions Detection { get; set; } = new();
    public PolicyOptions Policy { get; set; } = new();
    public WhitelistOptions Whitelist { get; set; } = new();
    public FirewallOptions Firewall { get; set; } = new();
    public StorageOptions Storage { get; set; } = new();
    public FileLogOptions FileLog { get; set; } = new();
    public ApiOptions Api { get; set; } = new();

    public string ResolvedDataDirectory =>
        Path.GetFullPath(Environment.ExpandEnvironmentVariables(DataDirectory));

    public string DatabasePath => Path.Combine(ResolvedDataDirectory, "rdpguard.db");
    public string LogDirectory => Path.Combine(ResolvedDataDirectory, "logs");

    public static GuardOptions Load(IConfiguration configuration)
    {
        var options = new GuardOptions();
        configuration.GetSection(SectionName).Bind(options);
        return options;
    }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        var p = Policy;
        if (p.MaxFailures < 1) errors.Add("Policy:MaxFailures must be >= 1");
        if (p.FailureWindow <= TimeSpan.Zero) errors.Add("Policy:FailureWindow must be positive");
        if (p.BaseBanDuration <= TimeSpan.Zero) errors.Add("Policy:BaseBanDuration must be positive");
        if (p.MaxBanDuration < p.BaseBanDuration) errors.Add("Policy:MaxBanDuration must be >= BaseBanDuration");
        if (p.PermanentAfterOffenses < 0) errors.Add("Policy:PermanentAfterOffenses must be >= 0");
        if (p.OffenseResetDays < 0) errors.Add("Policy:OffenseResetDays must be >= 0");
        if (p.SuccessTrustDays < 0) errors.Add("Policy:SuccessTrustDays must be >= 0");
        if (Firewall.MaxAddressesPerRule is < 1 or > 1000) errors.Add("Firewall:MaxAddressesPerRule must be 1..1000");
        if (Firewall.RdpPort is < 0 or > 65535) errors.Add("Firewall:RdpPort must be 0..65535");
        if (Storage.AttemptRetentionDays < 1) errors.Add("Storage:AttemptRetentionDays must be >= 1");
        if (Detection.RdpCoreTsDedupSeconds < 0) errors.Add("Detection:RdpCoreTsDedupSeconds must be >= 0");
        if (Detection.InitialLookbackMinutes < 0) errors.Add("Detection:InitialLookbackMinutes must be >= 0");
        foreach (var cidr in Whitelist.Cidrs)
        {
            if (!IpCidr.TryParse(cidr, out _)) errors.Add($"Whitelist:Cidrs: invalid entry '{cidr}'");
        }
        if (Api.Enabled)
        {
            if (Api.EffectiveUrls.Count == 0) errors.Add("Api:Urls must contain at least one URL");
            foreach (var url in Api.EffectiveUrls)
            {
                if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                    || !url.EndsWith('/'))
                    errors.Add($"Api:Urls: '{url}' must start with http:// or https:// and end with '/'");
            }
            foreach (var cidr in Api.AllowedClients)
            {
                if (!IpCidr.TryParse(cidr, out _)) errors.Add($"Api:AllowedClients: invalid entry '{cidr}'");
            }
        }
        try
        {
            _ = ResolvedDataDirectory;
        }
        catch (Exception ex)
        {
            errors.Add($"DataDirectory is invalid: {ex.Message}");
        }
        return errors.Select(e => $"{SectionName}:{e}").ToList();
    }
}

public sealed class DetectionOptions
{
    // Биндер конфигурации дописывает элементы к коллекции со значениями по умолчанию,
    // поэтому список по умолчанию пуст, а EffectiveLogonTypes подставляет 3 и 10.
    public List<int> LogonTypes { get; set; } = new();
    public bool EnableRdpCoreTs { get; set; } = true;
    public int RdpCoreTsDedupSeconds { get; set; } = 5;
    public int InitialLookbackMinutes { get; set; } = 60;
    public bool TrackSuccessfulLogons { get; set; } = true;

    /// <summary>
    /// Проверять при старте и раз в час, что аудит входов (Success и Failure) включён, и включать его.
    /// Без него 4625/4624 не пишутся и служба ничего не видит.
    /// </summary>
    public bool EnsureLogonAuditing { get; set; } = true;

    public IReadOnlySet<int> EffectiveLogonTypes =>
        LogonTypes.Count == 0 ? new HashSet<int> { 3, 10 } : LogonTypes.ToHashSet();
}

public sealed class PolicyOptions
{
    public int MaxFailures { get; set; } = 10;
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan BaseBanDuration { get; set; } = TimeSpan.FromDays(1);
    public TimeSpan MaxBanDuration { get; set; } = TimeSpan.FromDays(30);
    public int PermanentAfterOffenses { get; set; }
    public int OffenseResetDays { get; set; } = 90;
    public int SuccessTrustDays { get; set; } = 30;
    public bool SuccessfulLogonLiftsBan { get; set; } = true;
}

public sealed class WhitelistOptions
{
    public bool TrustPrivateRanges { get; set; } = true;
    public List<string> Cidrs { get; set; } = new();
}

public enum FirewallScope
{
    AllPorts,
    RdpPort,
}

public sealed class FirewallOptions
{
    public FirewallScope Scope { get; set; } = FirewallScope.AllPorts;
    public int RdpPort { get; set; }
    public int MaxAddressesPerRule { get; set; } = 1000;
}

public sealed class StorageOptions
{
    public int AttemptRetentionDays { get; set; } = 30;
}

/// <summary>HTTP API статистики: /metrics (Prometheus) и /api/* (JSON для Grafana Infinity).</summary>
public sealed class ApiOptions
{
    public const string DefaultUrl = "http://127.0.0.1:9645/";

    public bool Enabled { get; set; } = true;

    // Пустые по умолчанию по той же причине, что LogonTypes: биндер дописывает к списку.
    public List<string> Urls { get; set; } = new();

    /// <summary>Клиенты, которым разрешён доступ. Пусто — только localhost.</summary>
    public List<string> AllowedClients { get; set; } = new();

    /// <summary>
    /// Требовать "Authorization: Bearer &lt;token&gt;" (токены — командой "api-token create").
    /// Выключать имеет смысл только если API слушает localhost и его читает локальный Prometheus.
    /// </summary>
    public bool RequireToken { get; set; } = true;

    public IReadOnlyList<string> EffectiveUrls => Urls.Count == 0 ? new[] { DefaultUrl } : Urls;

    public IReadOnlyList<string> EffectiveAllowedClients =>
        AllowedClients.Count == 0 ? new[] { "127.0.0.0/8", "::1/128" } : AllowedClients;
}

public sealed class FileLogOptions
{
    public bool Enabled { get; set; } = true;
    public int MaxFileSizeMB { get; set; } = 10;
    public int RetainedFiles { get; set; } = 10;
}
