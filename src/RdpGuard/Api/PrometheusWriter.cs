using System.Globalization;
using System.Text;
using RdpGuard.Data;
using RdpGuard.Engine;

namespace RdpGuard.Api;

/// <summary>Текстовый формат экспозиции Prometheus 0.0.4.</summary>
public static class PrometheusWriter
{
    public const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    public static string Render(GuardMetrics metrics, StatsSummary? summary, bool dryRun, string version, DateTime nowUtc)
    {
        var sb = new StringBuilder(4096);

        Gauge(sb, "rdpguard_info", "Build information.", 1, ("version", version));
        Gauge(sb, "rdpguard_dry_run", "1 if DryRun is enabled (firewall is not modified).", dryRun ? 1 : 0);
        Gauge(sb, "rdpguard_start_time_seconds", "Process start time, Unix seconds.", Unix(metrics.StartedUtc));

        foreach (var family in metrics.Counters())
        {
            Header(sb, family.Name, family.Help, "counter");
            foreach (var (label, value) in family.Snapshot()) Sample(sb, family.Name, value, (family.Label, label));
        }

        if (metrics.QueueLength is { } queue)
            Gauge(sb, "rdpguard_queue_length", "Events waiting to be written to the database.", queue());

        if (metrics.LastEventUtc.Count > 0)
        {
            Header(sb, "rdpguard_last_event_timestamp_seconds", "Time of the newest processed logon event, per channel.", "gauge");
            foreach (var (channel, time) in metrics.LastEventUtc.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                Sample(sb, "rdpguard_last_event_timestamp_seconds", Unix(time), ("channel", channel));
        }

        if (metrics.LastFirewallSync is { } sync && metrics.LastFirewallSyncUtc is { } syncedAt)
        {
            Gauge(sb, "rdpguard_firewall_rules", "RdpGuard-Block-NN rules after the last reconciliation.", sync.Rules);
            Gauge(sb, "rdpguard_firewall_addresses", "Blocked addresses after the last reconciliation.", sync.Addresses);
            Gauge(sb, "rdpguard_firewall_last_sync_timestamp_seconds", "Time of the last successful reconciliation.", Unix(syncedAt));
        }

        if (summary is not null)
        {
            Gauge(sb, "rdpguard_active_bans", "Currently active bans.", summary.ActiveBans);
            Header(sb, "rdpguard_active_bans_by_offense", "Currently active bans, per offense number.", "gauge");
            foreach (var (offense, n) in summary.ActiveBansByOffense.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                Sample(sb, "rdpguard_active_bans_by_offense", n, ("offense", offense));
            Gauge(sb, "rdpguard_failed_logons_last_1h", "Failed logons during the last hour.", summary.FailedLogons1h);
            Gauge(sb, "rdpguard_failed_logons_last_24h", "Failed logons during the last 24 hours.", summary.FailedLogons24h);
            Gauge(sb, "rdpguard_attacking_ips_last_1h", "Distinct IPs with failed logons during the last hour.", summary.AttackingIps1h);
            Gauge(sb, "rdpguard_attacking_ips_last_24h", "Distinct IPs with failed logons during the last 24 hours.", summary.AttackingIps24h);
            Gauge(sb, "rdpguard_bans_last_24h", "Bans issued during the last 24 hours (automatic and manual).", summary.Bans24h);
            Gauge(sb, "rdpguard_external_logons_last_24h", "Successful logons from external IPs during the last 24 hours.", summary.ExternalLogons24h);
            Gauge(sb, "rdpguard_tracked_ips", "Addresses known to the database.", summary.TrackedIps);
            Gauge(sb, "rdpguard_whitelist_entries", "Whitelist entries added with 'allow'.", summary.WhitelistEntries);
            Gauge(sb, "rdpguard_bans_recorded", "All bans in the database (history).", summary.TotalBans);
        }

        Gauge(sb, "rdpguard_database_up", "1 if the database could be read for this scrape.", summary is null ? 0 : 1);
        Gauge(sb, "rdpguard_scrape_timestamp_seconds", "Time this response was generated.", Unix(nowUtc));
        return sb.ToString();
    }

    private static double Unix(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeMilliseconds() / 1000.0;

    private static void Gauge(StringBuilder sb, string name, string help, double value, params (string Name, string Value)[] labels)
    {
        Header(sb, name, help, "gauge");
        Sample(sb, name, value, labels);
    }

    private static void Header(StringBuilder sb, string name, string help, string type)
    {
        sb.Append("# HELP ").Append(name).Append(' ').Append(help.Replace("\\", "\\\\").Replace("\n", "\\n")).Append('\n');
        sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
    }

    private static void Sample(StringBuilder sb, string name, double value, params (string Name, string Value)[] labels)
    {
        sb.Append(name);
        if (labels.Length > 0)
        {
            sb.Append('{');
            for (int i = 0; i < labels.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(labels[i].Name).Append("=\"")
                    .Append(labels[i].Value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n"))
                    .Append('"');
            }
            sb.Append('}');
        }
        sb.Append(' ').Append(value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
    }
}
