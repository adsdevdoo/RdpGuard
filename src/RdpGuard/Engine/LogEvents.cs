using Microsoft.Extensions.Logging;

namespace RdpGuard.Engine;

/// <summary>Коды событий в журнале Application (источник RdpGuard).</summary>
public static class LogEvents
{
    /// <summary>Категория аудита: пишется в журнал Application начиная с Information.</summary>
    public const string AuditCategory = "RdpGuard.Audit";
    public const string EventSourceName = "RdpGuard";

    public static readonly EventId Started = new(1000, nameof(Started));
    public static readonly EventId Ban = new(1001, nameof(Ban));
    public static readonly EventId Unban = new(1002, nameof(Unban));
    public static readonly EventId ExternalLogon = new(1003, nameof(ExternalLogon));
    public static readonly EventId ManualBan = new(1004, nameof(ManualBan));
    public static readonly EventId ManualUnban = new(1005, nameof(ManualUnban));
    public static readonly EventId WhitelistChanged = new(1006, nameof(WhitelistChanged));
    public static readonly EventId ApiTokenChanged = new(1007, nameof(ApiTokenChanged));
    public static readonly EventId LogonAuditing = new(1008, nameof(LogonAuditing));
    public static readonly EventId FirewallChanged = new(1010, nameof(FirewallChanged));
    public static readonly EventId Error = new(1900, nameof(Error));
    public static readonly EventId FirewallError = new(1901, nameof(FirewallError));
}
