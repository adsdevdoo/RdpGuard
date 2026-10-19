using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RdpGuard.Events;

/// <summary>Состояние подкатегории аудита «Вход в систему» (Logon): от неё зависят события 4624 и 4625.</summary>
public readonly record struct LogonAuditState(bool Success, bool Failure)
{
    public bool IsComplete => Success && Failure;

    public override string ToString() => (Success, Failure) switch
    {
        (true, true) => "Success and Failure",
        (true, false) => "Success only",
        (false, true) => "Failure only",
        _ => "No auditing",
    };
}

/// <summary>
/// Чтение и включение аудита входов через advapi32 (AuditQuerySystemPolicy / AuditSetSystemPolicy).
/// Вывод auditpol.exe локализован, а GUID подкатегории и флаги — нет.
/// Нужна привилегия SeSecurityPrivilege: она есть у LocalSystem и администраторов, включается здесь же.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LogonAuditPolicy
{
    /// <summary>Подкатегория Logon (Audit Logon) в категории Logon/Logoff.</summary>
    public static readonly Guid LogonSubcategory = new("0CCE9215-69AE-11D9-BED3-505054503030");
    private static readonly Guid LogonLogoffCategory = new("69979849-797A-11D9-BED3-505054503030");

    private const uint PolicyAuditEventSuccess = 0x1;
    private const uint PolicyAuditEventFailure = 0x2;

    public static LogonAuditState Query()
    {
        EnableSecurityPrivilege();
        var guids = new[] { LogonSubcategory };
        if (!AuditQuerySystemPolicy(guids, 1, out var buffer))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AuditQuerySystemPolicy failed");
        try
        {
            var info = Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
            return new LogonAuditState(
                (info.AuditingInformation & PolicyAuditEventSuccess) != 0,
                (info.AuditingInformation & PolicyAuditEventFailure) != 0);
        }
        finally
        {
            AuditFree(buffer);
        }
    }

    /// <summary>Включает аудит успешных и неудачных входов.</summary>
    /// <returns>true, если настройку пришлось менять.</returns>
    public static bool EnsureEnabled()
    {
        if (Query().IsComplete) return false;
        var policy = new[]
        {
            new AuditPolicyInformation
            {
                AuditSubCategoryGuid = LogonSubcategory,
                AuditingInformation = PolicyAuditEventSuccess | PolicyAuditEventFailure,
                AuditCategoryGuid = LogonLogoffCategory,
            },
        };
        if (!AuditSetSystemPolicy(policy, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AuditSetSystemPolicy failed");
        return true;
    }

    private static void EnableSecurityPrivilege()
    {
        const uint TokenAdjustPrivileges = 0x20, TokenQuery = 0x8, SePrivilegeEnabled = 0x2;
        const int ErrorNotAllAssigned = 1300;

        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        try
        {
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValue failed");
            var tp = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AdjustTokenPrivileges failed");
            if (Marshal.GetLastWin32Error() == ErrorNotAllAssigned)
                throw new UnauthorizedAccessException("SeSecurityPrivilege is not held: run as Administrator or LocalSystem.");
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditSetSystemPolicy([In] AuditPolicyInformation[] pAuditPolicy, uint dwPolicyCount);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
