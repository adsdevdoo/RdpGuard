using System.Net;
using System.Net.Sockets;

namespace RdpGuard.Net;

public static class IpUtil
{
    /// <summary>
    /// Разбирает адрес из журнала/CLI: убирает зону IPv6, IPv4-mapped IPv6 превращает в IPv4,
    /// отбрасывает "-", пустые и неспецифицированные адреса.
    /// </summary>
    public static bool TryNormalize(string? text, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var s = text.Trim();
        if (s == "-") return false;
        if (s.StartsWith('[') && s.EndsWith(']')) s = s[1..^1];
        if (!IPAddress.TryParse(s, out var parsed)) return false;
        // IPAddress.TryParse принимает "1" и "1.2" — для IPv4 требуем полную запись.
        if (parsed.AddressFamily == AddressFamily.InterNetwork && s.Count(c => c == '.') != 3) return false;

        if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
        if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.ScopeId != 0)
            parsed = new IPAddress(parsed.GetAddressBytes());

        if (parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any) || parsed.Equals(IPAddress.Broadcast))
            return false;

        address = parsed;
        return true;
    }

    public static string? Normalize(string? text) => TryNormalize(text, out var ip) ? ip.ToString() : null;

    public static IPAddress Parse(string normalized) =>
        TryNormalize(normalized, out var ip) ? ip : throw new FormatException($"Invalid IP address '{normalized}'");
}
