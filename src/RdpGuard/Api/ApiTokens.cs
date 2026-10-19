using System.Security.Cryptography;
using System.Text;
using RdpGuard.Data;

namespace RdpGuard.Api;

public sealed record ApiTokenRow(long Id, string Name, string Prefix, DateTime CreatedUtc, DateTime? RevokedUtc);

/// <summary>
/// Токены API: "rg_" + 32 случайных байта (base64url). В БД хранится только SHA-256,
/// сам токен показывается один раз при создании.
/// </summary>
public static class ApiTokens
{
    public const string TokenPrefix = "rg_";

    public static string Generate() =>
        TokenPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    /// <summary>Первые символы — чтобы в списке токенов было видно, какой где используется.</summary>
    public static string DisplayPrefix(string token) => token[..Math.Min(token.Length, TokenPrefix.Length + 6)] + "…";

    public static string Create(Repository repo, string name, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 64)
            throw new ArgumentException("Token name must be 1..64 characters.");
        if (repo.Db.ScalarLong("SELECT COUNT(*) FROM api_tokens WHERE name = $n", ("$n", name)) > 0)
            throw new ArgumentException($"A token named '{name}' already exists (revoke it first).");

        var token = Generate();
        repo.Db.Exec("""
                     INSERT INTO api_tokens(name, token_hash, prefix, created_utc) VALUES($n, $h, $p, $t)
                     """, ("$n", name), ("$h", Hash(token)), ("$p", DisplayPrefix(token)), ("$t", DbTime.ToDb(nowUtc)));
        return token;
    }

    public static List<ApiTokenRow> List(GuardDb db) =>
        db.Query("SELECT id, name, prefix, created_utc, revoked_utc FROM api_tokens ORDER BY id",
            r => new ApiTokenRow(r.GetInt64(0), r.GetString(1), r.GetString(2), DbTime.FromDb(r.GetString(3)),
                DbTime.FromDbNullable(r.GetValue(4))));

    /// <summary>Отзыв по имени; удаление не нужно — отозванный токен сразу перестаёт приниматься.</summary>
    public static bool Revoke(GuardDb db, string name, DateTime nowUtc) =>
        db.Exec("UPDATE api_tokens SET revoked_utc = $t WHERE name = $n AND revoked_utc IS NULL",
            ("$n", name), ("$t", DbTime.ToDb(nowUtc))) > 0;

    /// <returns>Имя токена или null.</returns>
    public static string? Validate(GuardDb db, string presentedToken)
    {
        if (!presentedToken.StartsWith(TokenPrefix, StringComparison.Ordinal) || presentedToken.Length > 128) return null;
        return db.Scalar("SELECT name FROM api_tokens WHERE token_hash = $h AND revoked_utc IS NULL",
            ("$h", Hash(presentedToken))) as string;
    }
}
