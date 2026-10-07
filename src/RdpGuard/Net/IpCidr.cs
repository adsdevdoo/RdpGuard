using System.Net;
using System.Net.Sockets;

namespace RdpGuard.Net;

/// <summary>Сеть в нотации CIDR. Биты хоста при разборе обнуляются ("10.1.2.3/8" -> "10.0.0.0/8").</summary>
public sealed class IpCidr : IEquatable<IpCidr>
{
    private readonly byte[] _network;

    private IpCidr(byte[] network, int prefixLength, AddressFamily family)
    {
        _network = network;
        PrefixLength = prefixLength;
        Family = family;
    }

    public int PrefixLength { get; }
    public AddressFamily Family { get; }
    public IPAddress Network => new(_network);
    public bool IsSingleHost => PrefixLength == _network.Length * 8;

    public static IpCidr Parse(string text) =>
        TryParse(text, out var cidr) ? cidr : throw new FormatException($"Invalid IP or CIDR '{text}'");

    public static bool TryParse(string? text, out IpCidr cidr)
    {
        cidr = null!;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var s = text.Trim();
        string addressPart = s;
        int? prefix = null;
        int slash = s.IndexOf('/');
        if (slash >= 0)
        {
            addressPart = s[..slash];
            if (!int.TryParse(s[(slash + 1)..], out var p)) return false;
            prefix = p;
        }

        if (!IpUtil.TryNormalize(addressPart, out var address))
        {
            // 0.0.0.0/0 и ::/0 нормализатор отбрасывает как "unspecified", здесь они допустимы.
            if (!IPAddress.TryParse(addressPart.Trim(), out address!)
                || !(address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                || (address.AddressFamily == AddressFamily.InterNetwork && addressPart.Count(c => c == '.') != 3))
                return false;
        }

        var bytes = address.GetAddressBytes();
        int maxPrefix = bytes.Length * 8;
        int len = prefix ?? maxPrefix;
        if (len < 0 || len > maxPrefix) return false;

        for (int bit = len; bit < maxPrefix; bit++)
            bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));

        cidr = new IpCidr(bytes, len, address.AddressFamily);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != Family) return false;
        var bytes = address.GetAddressBytes();
        int fullBytes = PrefixLength / 8;
        for (int i = 0; i < fullBytes; i++)
            if (bytes[i] != _network[i]) return false;
        int rem = PrefixLength % 8;
        if (rem == 0) return true;
        byte mask = (byte)(0xFF << (8 - rem));
        return (bytes[fullBytes] & mask) == _network[fullBytes];
    }

    public override string ToString() => $"{Network}/{PrefixLength}";
    public bool Equals(IpCidr? other) => other is not null && ToString() == other.ToString();
    public override bool Equals(object? obj) => Equals(obj as IpCidr);
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
}
