using System.Net;
using System.Net.Sockets;
using RdpGuard.Net;

namespace RdpGuard.Firewall;

public static class FirewallConstants
{
    public const int ProtocolTcp = 6;
    public const int ProtocolAny = 256;
}

public sealed record FirewallRuleInfo
{
    public required string Name { get; init; }
    public IReadOnlyList<string> RemoteAddresses { get; init; } = Array.Empty<string>();
    public int Protocol { get; init; } = FirewallConstants.ProtocolAny;
    public string? LocalPorts { get; init; }
    public bool Inbound { get; init; } = true;
    public bool Block { get; init; } = true;
    public bool Enabled { get; init; } = true;
    public string? Description { get; init; }
    public string? Grouping { get; init; }
}

/// <summary>Минимальный набор операций с брандмауэром; в тестах подменяется фейком.</summary>
public interface IFirewall
{
    /// <summary>Правила, имя которых начинается с префикса (без учёта регистра).</summary>
    IReadOnlyList<FirewallRuleInfo> GetRules(string namePrefix);

    void AddRule(FirewallRuleInfo rule);

    void SetRemoteAddresses(string name, IReadOnlyCollection<string> addresses);

    /// <summary>Удаляет все правила с этим именем.</summary>
    void RemoveRule(string name);
}

public static class FirewallAddress
{
    /// <summary>
    /// Брандмауэр возвращает адреса как "1.2.3.4/255.255.255.255" или "2001:db8::1/128".
    /// Приводит одиночный адрес к виду "1.2.3.4"; для подсетей, диапазонов и "*" возвращает false.
    /// </summary>
    public static bool TryNormalizeHost(string token, out string ip)
    {
        ip = "";
        var t = token.Trim();
        if (t.Length == 0 || t == "*" || t.Contains('-')) return false;

        int slash = t.IndexOf('/');
        if (slash < 0)
        {
            var n = IpUtil.Normalize(t);
            if (n is null) return false;
            ip = n;
            return true;
        }

        if (!IpUtil.TryNormalize(t[..slash], out var address)) return false;
        var suffix = t[(slash + 1)..];
        int full = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        bool isHost = int.TryParse(suffix, out var prefix)
            ? prefix == full
            : IPAddress.TryParse(suffix, out var mask) && mask.GetAddressBytes().All(b => b == 0xFF);
        if (!isHost) return false;
        ip = address.ToString();
        return true;
    }

    public static IReadOnlyList<string> Split(string? remoteAddresses) =>
        string.IsNullOrWhiteSpace(remoteAddresses)
            ? Array.Empty<string>()
            : remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
