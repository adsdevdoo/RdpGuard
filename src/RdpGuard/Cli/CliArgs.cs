using System.Globalization;

namespace RdpGuard.Cli;

public sealed class CliException(string message) : Exception(message);

/// <summary>Простой разбор: позиционные аргументы и --опции (флаги или со значением).</summary>
public sealed class CliArgs
{
    private static readonly HashSet<string> Flags = new(StringComparer.OrdinalIgnoreCase)
    {
        "active", "csv", "permanent", "reset", "purge", "no-start", "force",
    };

    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);

    public CliArgs(IEnumerable<string> args)
    {
        var list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            var a = list[i];
            if (a.StartsWith("--", StringComparison.Ordinal) && a.Length > 2)
            {
                var name = a[2..];
                string? value = null;
                int eq = name.IndexOf('=');
                if (eq >= 0)
                {
                    value = name[(eq + 1)..];
                    name = name[..eq];
                }
                else if (!Flags.Contains(name) && i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    value = list[++i];
                }
                _options[name] = value;
            }
            else
            {
                Positional.Add(a);
            }
        }
    }

    public List<string> Positional { get; } = new();

    public bool Has(string name) => _options.ContainsKey(name);

    public string? Get(string name) => _options.TryGetValue(name, out var v) ? v : null;

    public string RequirePositional(int index, string what) =>
        index < Positional.Count ? Positional[index] : throw new CliException($"Missing argument: {what}");

    public double? GetDouble(string name)
    {
        if (!_options.TryGetValue(name, out var v)) return null;
        if (v is null || !double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) || d <= 0)
            throw new CliException($"--{name} requires a positive number");
        return d;
    }

    public int GetInt(string name, int defaultValue)
    {
        if (!_options.TryGetValue(name, out var v)) return defaultValue;
        if (v is null || !int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n <= 0)
            throw new CliException($"--{name} requires a positive integer");
        return n;
    }

    public void EnsureKnown(params string[] allowed)
    {
        var unknown = _options.Keys.Where(k => !allowed.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
        if (unknown.Count > 0) throw new CliException("Unknown option(s): " + string.Join(", ", unknown.Select(u => "--" + u)));
    }
}

/// <summary>Вывод таблицы в консоль.</summary>
public sealed class Table
{
    private readonly string[] _headers;
    private readonly List<string[]> _rows = new();

    public Table(params string[] headers) => _headers = headers;

    public void Add(params object?[] cells) =>
        _rows.Add(cells.Select(c => c switch
        {
            null => "",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => c.ToString() ?? "",
        }).ToArray());

    public int Count => _rows.Count;

    public void Print(TextWriter? output = null)
    {
        output ??= Console.Out;
        var widths = _headers.Select((h, i) => Math.Max(h.Length, _rows.Count == 0 ? 0 : _rows.Max(r => i < r.Length ? r[i].Length : 0))).ToArray();
        output.WriteLine(Line(_headers, widths));
        output.WriteLine(string.Join("  ", widths.Select(w => new string('-', w))));
        foreach (var row in _rows) output.WriteLine(Line(row, widths));
    }

    private static string Line(string[] cells, int[] widths) =>
        string.Join("  ", widths.Select((w, i) => (i < cells.Length ? cells[i] : "").PadRight(w))).TrimEnd();
}
