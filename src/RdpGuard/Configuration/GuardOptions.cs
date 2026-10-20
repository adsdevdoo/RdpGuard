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
        if (p.MaxFailures < 0) errors.Add("Policy:MaxFailures must be >= 0 (0 disables the rule)");
        if (p.FailureWindow <= TimeSpan.Zero) errors.Add("Policy:FailureWindow must be positive");
        if (p.SlowMaxFailures < 0) errors.Add("Policy:SlowMaxFailures must be >= 0");
        if (p.SlowFailureWindow <= TimeSpan.Zero) errors.Add("Policy:SlowFailureWindow must be positive");
        if (p.NoSuchUserMaxFailures < 0) errors.Add("Policy:NoSuchUserMaxFailures must be >= 0");
        if (p.NoSuchUserWindow <= TimeSpan.Zero) errors.Add("Policy:NoSuchUserWindow must be positive");
        if (p.WrongPasswordMaxFailures < 0) errors.Add("Policy:WrongPasswordMaxFailures must be >= 0");
        if (p.WrongPasswordWindow <= TimeSpan.Zero) errors.Add("Policy:WrongPasswordWindow must be positive");
        if (p.BadCredentialsMaxFailures < 0) errors.Add("Policy:BadCredentialsMaxFailures must be >= 0");
        if (p.BadCredentialsWindow <= TimeSpan.Zero) errors.Add("Policy:BadCredentialsWindow must be positive");
        if (p.PeriodicMinAttempts is < 0 or 1 or 2) errors.Add("Policy:PeriodicMinAttempts must be 0 (off) or >= 3");
        if (p.PeriodicMaxDeviation is < 0 or > 1) errors.Add("Policy:PeriodicMaxDeviation must be 0..1");
        if (p.PeriodicWindow <= TimeSpan.Zero) errors.Add("Policy:PeriodicWindow must be positive");
        if (p.AccountAlertWrongPasswords < 0 || p.AccountAlertMinIps < 0) errors.Add("Policy:AccountAlert* must be >= 0");
        if (p.MaxFailures == 0 && p.SlowMaxFailures == 0 && p.NoSuchUserMaxFailures == 0
            && p.WrongPasswordMaxFailures == 0 && p.BadCredentialsMaxFailures == 0 && p.PeriodicMinAttempts == 0)
            errors.Add("Policy: all ban rules are disabled");
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

/// <summary>
/// Правила бана. Любое сработавшее правило даёт бан; правило с порогом 0 выключено.
/// Все окна начинаются не раньше конца предыдущего бана адреса.
/// </summary>
public sealed class PolicyOptions
{
    /// <summary>Быстрый перебор: столько неудач за FailureWindow.</summary>
    public int MaxFailures { get; set; } = 5;
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Медленный перебор: столько неудач за SlowFailureWindow.</summary>
    public int SlowMaxFailures { get; set; } = 15;
    public TimeSpan SlowFailureWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Перебор имён: столько попыток с несуществующим именем (SubStatus 0xC0000064).</summary>
    public int NoSuchUserMaxFailures { get; set; } = 3;
    public TimeSpan NoSuchUserWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Подбор пароля к существующей учётке: столько неверных паролей (SubStatus 0xC000006A).</summary>
    public int WrongPasswordMaxFailures { get; set; } = 5;
    public TimeSpan WrongPasswordWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Неверные учётные данные вместе: несуществующее имя ИЛИ неверный пароль. Ловит медленный
    /// целенаправленный подбор, который переключается между именами и не набирает порог ни одного
    /// из правил по отдельности.
    /// </summary>
    public int BadCredentialsMaxFailures { get; set; } = 3;
    public TimeSpan BadCredentialsWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>«По таймеру»: столько попыток подряд с почти равными интервалами; 0 — выключено.</summary>
    public int PeriodicMinAttempts { get; set; } = 5;
    /// <summary>Допустимое отклонение интервала от среднего, доля (0.1 = 10%).</summary>
    public double PeriodicMaxDeviation { get; set; } = 0.1;
    /// <summary>В каком окне искать серию.</summary>
    public TimeSpan PeriodicWindow { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Предупреждение (не бан) о распределённом подборе: столько неверных паролей к одной учётке
    /// за сутки со всех адресов, и не меньше AccountAlertMinIps разных адресов. 0 — выключено.
    /// </summary>
    public int AccountAlertWrongPasswords { get; set; } = 20;
    public int AccountAlertMinIps { get; set; } = 3;

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
