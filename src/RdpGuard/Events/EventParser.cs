using System.Globalization;
using RdpGuard.Net;

namespace RdpGuard.Events;

/// <summary>
/// Разбор событий по позициям EventData (Properties), а не по тексту сообщения:
/// текст локализован, а порядок полей шаблона — нет.
/// </summary>
public static class EventParser
{
    public const string SecurityChannel = "Security";
    public const string RdpCoreTsChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

    public const int FailedLogonId = 4625;
    public const int SuccessfulLogonId = 4624;
    public const int RdpAuthFailedId = 140;

    // 4625: 5 TargetUserName, 9 SubStatus, 10 LogonType, 19 IpAddress
    private const int F_User = 5, F_SubStatus = 9, F_LogonType = 10, F_Ip = 19;
    // 4624: 5 TargetUserName, 8 LogonType, 18 IpAddress
    private const int S_User = 5, S_LogonType = 8, S_Ip = 18;
    // RdpCoreTS 140: 0 ClientIP
    private const int R_Ip = 0;

    public static AuthEvent? Parse(
        string channel, int eventId, long recordId, DateTime timeUtc,
        IReadOnlyList<object?> props, IReadOnlySet<int> logonTypes)
    {
        timeUtc = timeUtc.Kind == DateTimeKind.Utc ? timeUtc : DateTime.SpecifyKind(timeUtc.ToUniversalTime(), DateTimeKind.Utc);

        if (IsChannel(channel, SecurityChannel))
        {
            if (eventId == FailedLogonId)
            {
                var failure = ParseLogon(AuthEventKind.Failure, channel, eventId, recordId, timeUtc, props, F_User, F_LogonType, F_Ip, logonTypes);
                return failure is null ? null : failure with { SubStatus = AsUInt(props[F_SubStatus]) };
            }
            if (eventId == SuccessfulLogonId)
                return ParseLogon(AuthEventKind.Success, channel, eventId, recordId, timeUtc, props, S_User, S_LogonType, S_Ip, logonTypes);
            return null;
        }

        if (IsChannel(channel, RdpCoreTsChannel) && eventId == RdpAuthFailedId)
        {
            if (props.Count <= R_Ip) return null;
            var ip = IpUtil.Normalize(AsString(props[R_Ip]));
            if (ip is null) return null;
            return new AuthEvent(AuthEventKind.Failure, channel, eventId, recordId, timeUtc, ip, null, null);
        }

        return null;
    }

    private static AuthEvent? ParseLogon(
        AuthEventKind kind, string channel, int eventId, long recordId, DateTime timeUtc,
        IReadOnlyList<object?> props, int userIdx, int logonTypeIdx, int ipIdx, IReadOnlySet<int> logonTypes)
    {
        if (props.Count <= Math.Max(ipIdx, Math.Max(userIdx, logonTypeIdx))) return null;

        var logonType = AsInt(props[logonTypeIdx]);
        if (logonType is null || !logonTypes.Contains(logonType.Value)) return null;

        var ip = IpUtil.Normalize(AsString(props[ipIdx]));
        if (ip is null) return null;

        return new AuthEvent(kind, channel, eventId, recordId, timeUtc, ip, CleanUser(AsString(props[userIdx])), logonType);
    }

    private static bool IsChannel(string actual, string expected) =>
        string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);

    private static string? AsString(object? value) => value switch
    {
        null => null,
        string s => s,
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString(),
    };

    private static int? AsInt(object? value)
    {
        try
        {
            return value switch
            {
                null => null,
                int i => i,
                uint u => (int)u,
                string s => int.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r : null,
                IConvertible c => c.ToInt32(CultureInfo.InvariantCulture),
                _ => null,
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>NTSTATUS приходит как uint, а в части API — как отрицательный int.</summary>
    private static uint? AsUInt(object? value)
    {
        try
        {
            return value switch
            {
                null => null,
                uint u => u,
                int i => unchecked((uint)i),
                long l => unchecked((uint)l),
                string s when s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) =>
                    uint.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : null,
                string s => uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) ? d : null,
                IConvertible c => unchecked((uint)c.ToInt64(CultureInfo.InvariantCulture)),
                _ => null,
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string? CleanUser(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return null;
        user = user.Trim();
        if (user == "-") return null;
        return user.Length > 256 ? user[..256] : user;
    }
}
