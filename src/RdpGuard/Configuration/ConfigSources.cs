using Microsoft.Extensions.Configuration;

namespace RdpGuard.Configuration;

/// <summary>
/// Источники конфигурации, по возрастанию приоритета:
/// <list type="number">
/// <item><c>appsettings.json</c> рядом с exe — заводские настройки, заменяются при обновлении;</item>
/// <item><c>%ProgramData%\RdpGuard\appsettings.local.json</c> — местные настройки сервера, обновлением не трогаются;</item>
/// <item>переменные окружения <c>RDPGUARD_*</c> — для разовых запусков и тестов.</item>
/// </list>
/// Массивы в .NET-конфигурации сливаются по индексам, поэтому в заводском файле списки
/// <c>Api:Urls</c>, <c>Api:AllowedClients</c>, <c>Whitelist:Cidrs</c> пустые.
/// </summary>
public static class ConfigSources
{
    public const string LocalFileName = "appsettings.local.json";

    /// <summary>Переопределяет путь к local-файлу; "none" — не читать его вовсе.</summary>
    public const string LocalPathVariable = "RDPGUARD_LOCAL_CONFIG";

    public static string DefaultLocalPath =>
        Path.Combine(Environment.ExpandEnvironmentVariables(@"%ProgramData%\RdpGuard"), LocalFileName);

    /// <summary>Путь к local-файлу или null, если он отключён.</summary>
    public static string? LocalPath
    {
        get
        {
            var value = Environment.GetEnvironmentVariable(LocalPathVariable);
            if (value is null) return DefaultLocalPath;
            if (value.Length == 0 || value.Equals("none", StringComparison.OrdinalIgnoreCase)) return null;
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value));
        }
    }

    public static string BaseFilePath => Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    /// <summary>Добавляет local-файл и переменные RDPGUARD_ поверх уже подключённого appsettings.json.</summary>
    public static IConfigurationBuilder AddLocalOverrides(this IConfigurationBuilder builder, string? localPath)
    {
        if (localPath is not null) builder.AddJsonFile(localPath, optional: true, reloadOnChange: false);
        return builder.AddEnvironmentVariables("RDPGUARD_");
    }

    /// <summary>Полная конфигурация для CLI (служба собирает её через HostApplicationBuilder).</summary>
    public static IConfigurationRoot Build(string? baseFilePath = null, string? localPath = "default")
    {
        var builder = new ConfigurationBuilder()
            .AddJsonFile(baseFilePath ?? BaseFilePath, optional: true, reloadOnChange: false);
        return builder.AddLocalOverrides(localPath == "default" ? LocalPath : localPath).Build();
    }

    /// <summary>Какие файлы конфигурации реально прочитаны — для status.</summary>
    public static IReadOnlyList<string> LoadedFiles()
    {
        var files = new List<string>();
        if (File.Exists(BaseFilePath)) files.Add(BaseFilePath);
        if (LocalPath is { } local && File.Exists(local)) files.Add(local);
        return files;
    }

    /// <summary>Шаблон local-файла: install создаёт его, если файла нет.</summary>
    public const string LocalTemplate = """
        {
          // Местные настройки этого сервера. Перекрывают appsettings.json из папки программы,
          // который заменяется при обновлении RdpGuard. Указывайте только то, что отличается.
          // Списки (Urls, AllowedClients, Cidrs) указывайте целиком.
          //
          // Пример:
          // "RdpGuard": {
          //   "DryRun": false,
          //   "Api": {
          //     "Urls": [ "http://127.0.0.1:9645/", "http://192.168.1.4:9645/" ],
          //     "AllowedClients": [ "127.0.0.0/8", "::1/128", "192.168.1.10/32" ]
          //   },
          //   "Whitelist": { "Cidrs": [ "203.0.113.0/24" ] }
          // }
          "RdpGuard": {
          }
        }
        """;
}
