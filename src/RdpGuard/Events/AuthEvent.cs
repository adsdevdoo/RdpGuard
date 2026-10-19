using System.Threading.Channels;

namespace RdpGuard.Events;

public enum AuthEventKind
{
    Failure,
    Success,
}

/// <summary>Почему не удался вход — по SubStatus события 4625.</summary>
public enum FailureReason
{
    /// <summary>Причина неизвестна (событие 140, старые записи).</summary>
    Unknown,
    /// <summary>0xC0000064: такой учётной записи нет — перебор имён.</summary>
    NoSuchUser,
    /// <summary>0xC000006A: учётная запись есть, пароль неверный — подбор пароля к реальной учётке.</summary>
    WrongPassword,
    /// <summary>Прочее: учётка отключена, заблокирована и т. п.</summary>
    Other,
}

public static class FailureCodes
{
    public const uint NoSuchUser = 0xC0000064;
    public const uint WrongPassword = 0xC000006A;

    public static FailureReason Classify(uint? subStatus) => subStatus switch
    {
        null => FailureReason.Unknown,
        NoSuchUser => FailureReason.NoSuchUser,
        WrongPassword => FailureReason.WrongPassword,
        _ => FailureReason.Other,
    };
}

/// <summary>Нормализованное событие входа. Ip — уже нормализованная строка.</summary>
/// <param name="SubStatus">SubStatus из 4625 (код причины отказа); null — неизвестен.</param>
public sealed record AuthEvent(
    AuthEventKind Kind,
    string Channel,
    int EventId,
    long RecordId,
    DateTime TimeUtc,
    string Ip,
    string? UserName,
    int? LogonType,
    uint? SubStatus = null)
{
    public FailureReason Reason => FailureCodes.Classify(SubStatus);
}

/// <summary>Элемент очереди единственного писателя в БД.</summary>
public abstract record WorkItem;

/// <summary>
/// Прочитанная запись журнала. Event == null, если запись не интересна (например, IP "-"),
/// но закладку всё равно надо сдвинуть.
/// </summary>
public sealed record RecordWork(string Channel, long RecordId, AuthEvent? Event) : WorkItem;

[Flags]
public enum TickKind
{
    None = 0,
    /// <summary>Раз в несколько секунд: проверить изменения от CLI.</summary>
    Quick = 1,
    /// <summary>Раз в минуту: снять истёкшие баны, сверить брандмауэр, чистка.</summary>
    Maintenance = 2,
}

public sealed record TickWork(TickKind Kind) : WorkItem;

public interface IAuthEventSource : IDisposable
{
    /// <summary>
    /// Запускает подписки. События пишутся в writer; getBookmark(channel) возвращает последний
    /// обработанный RecordId канала (null — первый запуск).
    /// </summary>
    void Start(ChannelWriter<WorkItem> writer, Func<string, long?> getBookmark);
}
