using RdpGuard.Configuration;

namespace RdpGuard.Tests;

public sealed class ConfigSourcesTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rdpguard-cfg-" + Guid.NewGuid().ToString("N"));

    public ConfigSourcesTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, true);

    private string Write(string name, string json)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, json);
        return path;
    }

    private static string ShippedConfig => Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    [Fact]
    public void ShippedConfig_IsValid_AndApiDefaultsToLocalhost()
    {
        Assert.True(File.Exists(ShippedConfig), "appsettings.json must be copied next to the binaries");
        var options = GuardOptions.Load(ConfigSources.Build(ShippedConfig, localPath: null));

        Assert.Empty(options.Validate());
        Assert.True(options.DryRun); // безопасный старт
        Assert.Empty(options.Api.Urls);
        Assert.Equal(new[] { ApiOptions.DefaultUrl }, options.Api.EffectiveUrls);
        Assert.Equal(new[] { "127.0.0.0/8", "::1/128" }, options.Api.EffectiveAllowedClients);
    }

    [Fact]
    public void LocalFile_OverridesShippedDefaults()
    {
        var local = Write("appsettings.local.json", """
            {
              // комментарии допустимы
              "RdpGuard": {
                "DryRun": false,
                "Api": {
                  "Urls": [ "http://127.0.0.1:9645/", "http://192.168.1.4:9645/" ],
                  "AllowedClients": [ "192.168.1.10/32" ]
                },
                "Policy": { "MaxFailures": 7 }
              }
            }
            """);

        var options = GuardOptions.Load(ConfigSources.Build(ShippedConfig, local));

        Assert.False(options.DryRun);
        Assert.Equal(new[] { "http://127.0.0.1:9645/", "http://192.168.1.4:9645/" }, options.Api.EffectiveUrls);
        // В заводском файле список пуст, поэтому лишние элементы не «просачиваются»: только то, что задано локально.
        Assert.Equal(new[] { "192.168.1.10/32" }, options.Api.EffectiveAllowedClients);
        Assert.Equal(7, options.Policy.MaxFailures);
        // Не указанное локально берётся из заводского файла.
        Assert.Equal(3, options.Policy.BadCredentialsMaxFailures);
        Assert.Empty(options.Validate());
    }

    [Fact]
    public void MissingLocalFile_IsFine()
    {
        var options = GuardOptions.Load(ConfigSources.Build(ShippedConfig, Path.Combine(_dir, "nope.json")));
        Assert.True(options.DryRun);
    }

    [Fact]
    public void LocalTemplate_IsValidJsonWithEmptySection()
    {
        var local = Write("appsettings.local.json", ConfigSources.LocalTemplate);
        var options = GuardOptions.Load(ConfigSources.Build(ShippedConfig, local));
        Assert.True(options.DryRun);
        Assert.Empty(options.Validate());
    }
}
