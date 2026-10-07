using System.Threading.Channels;

namespace RdpGuard.Events;

public enum AuthEventKind
{
    Failure,
    Success,
}

/// <summary>Нормализованное событие входа. Ip — уже нормализованная строка.</summary>
public sealed record AuthEvent(
    AuthEventKind Kind,
    string Channel,
    int EventId,
    long RecordId,
    DateTime TimeUtc,
    string Ip,
    string? UserName,
    int? LogonType);

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
