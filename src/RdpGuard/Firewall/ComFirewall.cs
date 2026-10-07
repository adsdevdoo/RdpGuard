using System.Collections;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RdpGuard.Configuration;

namespace RdpGuard.Firewall;

/// <summary>Windows Firewall через COM (HNetCfg.FwPolicy2 / INetFwPolicy2), без netsh.</summary>
[SupportedOSPlatform("windows")]
public sealed class ComFirewall : IFirewall
{
    private const int DirectionIn = 1;       // NET_FW_RULE_DIR_IN
    private const int ActionBlock = 0;       // NET_FW_ACTION_BLOCK
    private const int ProfilesAll = 0x7FFFFFFF; // NET_FW_PROFILE2_ALL

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    private static dynamic CreateRule()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    public IReadOnlyList<FirewallRuleInfo> GetRules(string namePrefix)
    {
        dynamic policy = CreatePolicy();
        try
        {
            var result = new List<FirewallRuleInfo>();
            IEnumerable rules = policy.Rules;
            foreach (dynamic rule in rules)
            {
                try
                {
                    string? name = rule.Name;
                    if (name is null || !name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)) continue;
                    result.Add(new FirewallRuleInfo
                    {
                        Name = name,
                        RemoteAddresses = FirewallAddress.Split((string?)rule.RemoteAddresses),
                        Protocol = (int)rule.Protocol,
                        LocalPorts = (string?)rule.LocalPorts,
                        Inbound = (int)rule.Direction == DirectionIn,
                        Block = (int)rule.Action == ActionBlock,
                        Enabled = (bool)rule.Enabled,
                        Description = (string?)rule.Description,
                        Grouping = (string?)rule.Grouping,
                    });
                }
                finally
                {
                    Release(rule);
                }
            }
            return result;
        }
        finally
        {
            Release(policy);
        }
    }

    public void AddRule(FirewallRuleInfo spec)
    {
        if (spec.RemoteAddresses.Count == 0)
            throw new ArgumentException("Refusing to create a rule without addresses: it would block everything.");

        dynamic policy = CreatePolicy();
        dynamic rule = CreateRule();
        try
        {
            rule.Name = spec.Name;
            rule.Description = spec.Description ?? "";
            rule.Grouping = spec.Grouping ?? "";
            rule.Direction = spec.Inbound ? DirectionIn : 2;
            rule.Action = spec.Block ? ActionBlock : 1;
            rule.Protocol = spec.Protocol; // до LocalPorts: порты допустимы только для TCP/UDP
            if (!string.IsNullOrEmpty(spec.LocalPorts)) rule.LocalPorts = spec.LocalPorts;
            rule.RemoteAddresses = string.Join(",", spec.RemoteAddresses);
            rule.Profiles = ProfilesAll;
            rule.InterfaceTypes = "All";
            rule.Enabled = spec.Enabled;
            policy.Rules.Add(rule);
        }
        finally
        {
            Release(rule);
            Release(policy);
        }
    }

    public void SetRemoteAddresses(string name, IReadOnlyCollection<string> addresses)
    {
        // Пустой RemoteAddresses у брандмауэра означает "любой адрес".
        if (addresses.Count == 0)
            throw new ArgumentException("Refusing to set an empty address list: it would block everything.");

        dynamic policy = CreatePolicy();
        try
        {
            dynamic rule = policy.Rules.Item(name);
            try
            {
                rule.RemoteAddresses = string.Join(",", addresses);
            }
            finally
            {
                Release(rule);
            }
        }
        finally
        {
            Release(policy);
        }
    }

    public void RemoveRule(string name)
    {
        dynamic policy = CreatePolicy();
        try
        {
            dynamic rules = policy.Rules;
            // При дублях имён Remove удаляет одно правило за вызов.
            for (int i = 0; i < 100 && Exists(rules, name); i++) rules.Remove(name);
        }
        finally
        {
            Release(policy);
        }
    }

    private static bool Exists(dynamic rules, string name)
    {
        try
        {
            dynamic rule = rules.Item(name);
            Release(rule);
            return true;
        }
        catch (Exception ex) when (ex is COMException or FileNotFoundException)
        {
            return false;
        }
    }

    /// <summary>Включён ли брандмауэр в текущих активных профилях. null — не удалось определить.</summary>
    public static bool? IsEnabledForCurrentProfiles()
    {
        try
        {
            dynamic policy = CreatePolicy();
            try
            {
                int current = policy.CurrentProfileTypes;
                foreach (int profile in new[] { 1, 2, 4 })
                {
                    if ((current & profile) != 0 && !(bool)policy.FirewallEnabled[profile]) return false;
                }
                return true;
            }
            finally
            {
                Release(policy);
            }
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static void Release(object? com)
    {
        if (com is not null && Marshal.IsComObject(com)) Marshal.ReleaseComObject(com);
    }
}

[SupportedOSPlatform("windows")]
public static class RdpPortResolver
{
    public const int DefaultPort = 3389;

    public static int Resolve(FirewallOptions options)
    {
        if (options.RdpPort > 0) return options.RdpPort;
        try
        {
            var value = Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "PortNumber", null);
            if (value is int port and > 0 and <= 65535) return port;
        }
        catch (Exception)
        {
            // нет доступа к реестру — порт по умолчанию
        }
        return DefaultPort;
    }
}
