using System.Globalization;
using Microsoft.Data.Sqlite;

namespace RdpGuard.Data;

/// <summary>Время в БД — UTC-строка фиксированного формата: сортируется лексикографически и читается глазами.</summary>
public static class DbTime
{
    public const string Format = "yyyy-MM-dd HH:mm:ss.fff";

    public static string ToDb(DateTime utc)
    {
        if (utc.Kind == DateTimeKind.Local) utc = utc.ToUniversalTime();
        return utc.ToString(Format, CultureInfo.InvariantCulture);
    }

    public static DateTime FromDb(string s) =>
        DateTime.SpecifyKind(DateTime.ParseExact(s, Format, CultureInfo.InvariantCulture), DateTimeKind.Utc);

    public static DateTime? FromDbNullable(object? value) =>
        value is string s && s.Length > 0 ? FromDb(s) : null;
}

/// <summary>Соединение с SQLite (WAL) и миграции схемы.</summary>
public sealed class GuardDb : IDisposable
{
    public const int SchemaVersion = 3;

    private static readonly string[][] Migrations =
    {
        // v1
        new[]
        {
            """
            CREATE TABLE IF NOT EXISTS attempts(
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc      TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                user_name   TEXT,
                logon_type  INTEGER,
                event_id    INTEGER NOT NULL,
                record_id   INTEGER)
            """,
            "CREATE INDEX IF NOT EXISTS ix_attempts_ip_ts ON attempts(ip, ts_utc)",
            "CREATE INDEX IF NOT EXISTS ix_attempts_ts ON attempts(ts_utc)",
            """
            CREATE TABLE IF NOT EXISTS bans(
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                  TEXT    NOT NULL,
                banned_at_utc       TEXT    NOT NULL,
                expires_at_utc      TEXT    NULL,
                offense_no          INTEGER NOT NULL,
                reason              TEXT,
                failures_in_window  INTEGER NOT NULL DEFAULT 0,
                unbanned_at_utc     TEXT    NULL,
                unban_reason        TEXT    NULL)
            """,
            "CREATE INDEX IF NOT EXISTS ix_bans_ip ON bans(ip)",
            "CREATE INDEX IF NOT EXISTS ix_bans_active ON bans(expires_at_utc) WHERE unbanned_at_utc IS NULL",
            """
            CREATE TABLE IF NOT EXISTS ips(
                ip                TEXT PRIMARY KEY,
                first_seen_utc    TEXT    NOT NULL,
                last_seen_utc     TEXT    NOT NULL,
                total_failures    INTEGER NOT NULL DEFAULT 0,
                offenses          INTEGER NOT NULL DEFAULT 0,
                last_offense_utc  TEXT    NULL,
                last_success_utc  TEXT    NULL,
                note              TEXT    NULL,
                whitelisted       INTEGER NOT NULL DEFAULT 0)
            """,
            """
            CREATE TABLE IF NOT EXISTS successes(
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc      TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                user_name   TEXT,
                logon_type  INTEGER,
                record_id   INTEGER)
            """,
            "CREATE INDEX IF NOT EXISTS ix_successes_ts ON successes(ts_utc)",
            """
            CREATE TABLE IF NOT EXISTS whitelist(
                cidr       TEXT PRIMARY KEY,
                added_utc  TEXT NOT NULL,
                note       TEXT NULL)
            """,
        },
        // v2: токены HTTP API (хранится только SHA-256)
        new[]
        {
            """
            CREATE TABLE IF NOT EXISTS api_tokens(
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL UNIQUE,
                token_hash   TEXT NOT NULL UNIQUE,
                prefix       TEXT NOT NULL,
                created_utc  TEXT NOT NULL,
                revoked_utc  TEXT NULL)
            """,
        },
        // v3: код причины отказа (SubStatus 4625) — для правил «нет такого пользователя» / «неверный пароль»
        new[]
        {
            "ALTER TABLE attempts ADD COLUMN sub_status INTEGER NULL",
        },
    };

    private readonly SqliteConnection _connection;
    private SqliteTransaction? _transaction;

    private GuardDb(string path, SqliteConnection connection)
    {
        Path = path;
        _connection = connection;
    }

    public string Path { get; }

    public static GuardDb Open(string path)
    {
        var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
            DefaultTimeout = 30,
        };
        var db = new GuardDb(path, new SqliteConnection(csb.ToString()));
        try
        {
            db._connection.Open();
            db.Exec("PRAGMA journal_mode=WAL");
            db.Exec("PRAGMA synchronous=NORMAL");
            db.Exec("PRAGMA busy_timeout=10000");
            db.Migrate();
            return db;
        }
        catch
        {
            db.Dispose();
            throw;
        }
    }

    /// <summary>Подключение только для чтения (API статистики): без миграций, не мешает писателю.</summary>
    public static GuardDb OpenReadOnly(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Database does not exist yet", path);
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
            DefaultTimeout = 10,
        };
        var db = new GuardDb(path, new SqliteConnection(csb.ToString()));
        try
        {
            db._connection.Open();
            db.Exec("PRAGMA busy_timeout=5000");
            return db;
        }
        catch
        {
            db.Dispose();
            throw;
        }
    }

    public int CurrentSchemaVersion =>
        int.TryParse(GetState("schema_version"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private void Migrate()
    {
        Exec("CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT)");
        if (CurrentSchemaVersion > SchemaVersion)
            throw new InvalidOperationException(
                $"Database schema v{CurrentSchemaVersion} is newer than this build supports (v{SchemaVersion}).");

        while (true)
        {
            using var tx = Begin(immediate: true);
            int version = CurrentSchemaVersion; // перечитываем под блокировкой: CLI и служба могут мигрировать одновременно
            if (version >= Migrations.Length) return;
            foreach (var sql in Migrations[version])
            {
                // ADD COLUMN не идемпотентна: пропускаем, если колонка уже есть (повторная или прерванная миграция).
                var m = System.Text.RegularExpressions.Regex.Match(sql, @"^ALTER TABLE (\w+) ADD COLUMN (\w+)",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success && ColumnExists(m.Groups[1].Value, m.Groups[2].Value)) continue;
                Exec(sql);
            }
            SetState("schema_version", (version + 1).ToString(CultureInfo.InvariantCulture));
            tx.Commit();
        }
    }

    public bool ColumnExists(string table, string column) =>
        Query($"PRAGMA table_info({table})", r => r.GetString(1))
            .Any(c => string.Equals(c, column, StringComparison.OrdinalIgnoreCase));

    public Tx Begin(bool immediate = false)
    {
        if (_transaction is not null) throw new InvalidOperationException("Transaction already active");
        _transaction = _connection.BeginTransaction(deferred: !immediate);
        return new Tx(this, _transaction);
    }

    public sealed class Tx : IDisposable
    {
        private readonly GuardDb _db;
        private readonly SqliteTransaction _tx;

        internal Tx(GuardDb db, SqliteTransaction tx)
        {
            _db = db;
            _tx = tx;
        }

        public void Commit() => _tx.Commit();

        public void Dispose()
        {
            try
            {
                _tx.Dispose();
            }
            finally
            {
                _db._transaction = null;
            }
        }
    }

    public SqliteCommand Command(string sql, params (string Name, object? Value)[] parameters)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = _transaction;
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    public int Exec(string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = Command(sql, parameters);
        return cmd.ExecuteNonQuery();
    }

    public object? Scalar(string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = Command(sql, parameters);
        var r = cmd.ExecuteScalar();
        return r is DBNull ? null : r;
    }

    public long ScalarLong(string sql, params (string Name, object? Value)[] parameters) =>
        Convert.ToInt64(Scalar(sql, parameters) ?? 0L, CultureInfo.InvariantCulture);

    public List<T> Query<T>(string sql, Func<SqliteDataReader, T> map, params (string Name, object? Value)[] parameters)
    {
        using var cmd = Command(sql, parameters);
        using var reader = cmd.ExecuteReader();
        var list = new List<T>();
        while (reader.Read()) list.Add(map(reader));
        return list;
    }

    public string? GetState(string key) => Scalar("SELECT value FROM state WHERE key = $k", ("$k", key)) as string;

    public void SetState(string key, string? value) =>
        Exec("INSERT INTO state(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("$k", key), ("$v", value));

    public void Dispose()
    {
        _connection.Dispose();
    }
}
