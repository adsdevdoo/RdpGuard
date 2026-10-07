using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace RdpGuard.Logging;

/// <summary>
/// Файловый лог с ротацией по размеру: rdpguard.log -> rdpguard.1.log -> ... -> rdpguard.N.log.
/// Запись идёт в фоновом потоке, чтобы логирование не тормозило обработку событий.
/// </summary>
[ProviderAlias("File")]
public sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private const string BaseName = "rdpguard";
    private readonly string _directory;
    private readonly long _maxBytes;
    private readonly int _retainedFiles;
    private readonly BlockingCollection<string> _queue = new(new ConcurrentQueue<string>(), 100_000);
    private readonly Thread _thread;
    private StreamWriter? _writer;
    private long _size;

    public RollingFileLoggerProvider(string directory, long maxBytes, int retainedFiles)
    {
        _directory = directory;
        _maxBytes = Math.Max(64 * 1024, maxBytes);
        _retainedFiles = Math.Max(1, retainedFiles);
        Directory.CreateDirectory(directory);
        _thread = new Thread(WriteLoop) { IsBackground = true, Name = "RdpGuard file logger" };
        _thread.Start();
    }

    private string CurrentPath => Path.Combine(_directory, BaseName + ".log");
    private string ArchivePath(int n) => Path.Combine(_directory, $"{BaseName}.{n}.log");

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    internal void Enqueue(string line)
    {
        if (!_queue.IsAddingCompleted) _queue.TryAdd(line);
    }

    private void WriteLoop()
    {
        foreach (var line in _queue.GetConsumingEnumerable())
        {
            try
            {
                EnsureWriter();
                int bytes = Encoding.UTF8.GetByteCount(line) + 2;
                if (_size > 0 && _size + bytes > _maxBytes)
                {
                    Roll();
                    EnsureWriter();
                }
                _writer!.WriteLine(line);
                _size += bytes;
                if (_queue.Count == 0) _writer.Flush();
            }
            catch (Exception)
            {
                // Логгер не должен ронять службу; при ошибке файл переоткроется на следующей строке.
                CloseWriter();
            }
        }
        CloseWriter();
    }

    private void EnsureWriter()
    {
        if (_writer is not null) return;
        var stream = new FileStream(CurrentPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        _size = stream.Length;
        _writer = new StreamWriter(stream, new UTF8Encoding(false));
    }

    private void Roll()
    {
        CloseWriter();
        var oldest = ArchivePath(_retainedFiles);
        if (File.Exists(oldest)) File.Delete(oldest);
        for (int i = _retainedFiles - 1; i >= 1; i--)
        {
            var src = ArchivePath(i);
            if (File.Exists(src)) File.Move(src, ArchivePath(i + 1), overwrite: true);
        }
        if (File.Exists(CurrentPath)) File.Move(CurrentPath, ArchivePath(1), overwrite: true);
    }

    private void CloseWriter()
    {
        try
        {
            _writer?.Dispose();
        }
        catch (Exception)
        {
            // ignore
        }
        _writer = null;
        _size = 0;
    }

    public void Dispose()
    {
        _queue.CompleteAdding();
        _thread.Join(TimeSpan.FromSeconds(5));
    }

    private sealed class FileLogger(RollingFileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var sb = new StringBuilder(256);
            sb.Append(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture))
                .Append("Z [").Append(Level(logLevel)).Append("] ")
                .Append(category);
            if (eventId.Id != 0) sb.Append('[').Append(eventId.Id).Append(']');
            sb.Append(": ").Append(formatter(state, exception));
            if (exception is not null) sb.AppendLine().Append(exception);
            provider.Enqueue(sb.ToString());
        }

        private static string Level(LogLevel l) => l switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Critical => "CRT",
            _ => "???",
        };
    }
}
