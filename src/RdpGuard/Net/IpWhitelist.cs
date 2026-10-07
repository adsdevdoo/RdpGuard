using System.Net;
using RdpGuard.Configuration;

namespace RdpGuard.Net;

/// <summary>
/// Белый список: частные диапазоны + CIDR из конфига (статические) + записи из БД (меняются командой allow/disallow).
/// </summary>
public sealed class IpWhitelist
{
    public static readonly IReadOnlyList<IpCidr> PrivateRanges = new[]
    {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fe80::/10", "fc00::/7",
    }.Select(IpCidr.Parse).ToArray();

    private readonly IpCidr[] _static;
    private volatile IpCidr[] _dynamic = Array.Empty<IpCidr>();

    public IpWhitelist(bool trustPrivateRanges, IEnumerable<string> cidrs)
    {
        var list = new List<IpCidr>();
        if (trustPrivateRanges) list.AddRange(PrivateRanges);
        foreach (var c in cidrs)
        {
            if (IpCidr.TryParse(c, out var cidr)) list.Add(cidr);
        }
        _static = list.ToArray();
    }

    public static IpWhitelist FromOptions(WhitelistOptions options) => new(options.TrustPrivateRanges, options.Cidrs);

    public void SetDynamic(IEnumerable<IpCidr> entries) => _dynamic = entries.ToArray();

    public bool IsWhitelisted(IPAddress address) => IsWhitelisted(address, out _);

    public bool IsWhitelisted(IPAddress address, out IpCidr? matched)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        foreach (var c in _static)
            if (c.Contains(address)) { matched = c; return true; }
        foreach (var c in _dynamic)
            if (c.Contains(address)) { matched = c; return true; }
        matched = null;
        return false;
    }

    public bool IsWhitelisted(string ip) => IpUtil.TryNormalize(ip, out var a) && IsWhitelisted(a);

    /// <summary>Частный/служебный адрес — независимо от настройки TrustPrivateRanges.</summary>
    public static bool IsPrivate(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return PrivateRanges.Any(r => r.Contains(address));
    }
}
