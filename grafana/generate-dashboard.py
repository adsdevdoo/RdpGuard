"""Генерирует grafana/rdpguard-dashboard.json (источник данных — Prometheus).

    python grafana/generate-dashboard.py

Панели описаны здесь, JSON не правится руками.
"""
import json
import pathlib

DS = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
SEL = 'instance=~"$instance"'
_ids = iter(range(1, 1000))


def target(expr, legend="", ref="A", instant=False, fmt=None):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref}
    if instant:
        t["instant"] = True
        t["range"] = False
    if fmt:
        t["format"] = fmt
    return t


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


GREEN_RED = thresholds(("green", None), ("red", 1))
BLUE = thresholds(("blue", None))


def stat(title, expr, x, y, w=4, h=4, unit="short", th=BLUE, mappings=None, desc=""):
    return {
        "id": next(_ids), "type": "stat", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(expr, instant=True)],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "none", "justifyMode": "center", "textMode": "value"},
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "mappings": mappings or [], "thresholds": th},
                        "overrides": []},
    }


def timeseries(title, targets, x, y, w=12, h=8, unit="short", stack=False, bars=False, desc=""):
    return {
        "id": next(_ids), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "fieldConfig": {"defaults": {"unit": unit, "min": 0, "custom": {
            "drawStyle": "bars" if bars else "line", "lineWidth": 1, "fillOpacity": 60 if bars else 15,
            "stacking": {"mode": "normal" if stack else "none", "group": "A"}, "showPoints": "never"}},
            "overrides": []},
    }


def bargauge(title, expr, legend, x, y, w, h, th, desc=""):
    return {
        "id": next(_ids), "type": "bargauge", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(expr, legend, instant=True)],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True,
                    "valueMode": "color", "namePlacement": "left", "minVizHeight": 16, "maxVizHeight": 24},
        "fieldConfig": {"defaults": {"unit": "short", "min": 0, "decimals": 0, "thresholds": th}, "overrides": []},
    }


def row(title, y):
    return {"id": next(_ids), "type": "row", "title": title, "collapsed": False,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def value_map(pairs):
    return [{"type": "value", "options": {
        str(k): {"text": text, "color": color, "index": i} for i, (k, text, color) in enumerate(pairs)}}]


panels = [
    row("Overview", 0),
    stat("Mode", f"max(rdpguard_dry_run{{{SEL}}})", 0, 1,
         mappings=value_map([(0, "ENFORCING", "green"), (1, "DRY RUN", "orange")]), th=thresholds(("green", None)),
         desc="DRY RUN: bans are recorded but the firewall is not modified."),
    stat("Active bans", f"sum(rdpguard_active_bans{{{SEL}}})", 4, 1),
    stat("Failed logons, 1h", f"sum(rdpguard_failed_logons_last_1h{{{SEL}}})", 8, 1,
         th=thresholds(("green", None), ("orange", 100), ("red", 1000))),
    stat("Attacking IPs, 24h", f"sum(rdpguard_attacking_ips_last_24h{{{SEL}}})", 12, 1, th=thresholds(("purple", None))),
    stat("External logons, 24h", f"sum(rdpguard_external_logons_last_24h{{{SEL}}})", 16, 1, th=GREEN_RED,
         desc="Successful logons from public addresses. Check the Application log (event 1003) if unexpected."),
    stat("Accounts being guessed", f"count(rdpguard_account_wrong_password_ips_last_24h{{{SEL}}} >= 3) or vector(0)", 20, 1,
         th=GREEN_RED,
         desc="Existing accounts that got wrong passwords from 3+ addresses within 24h (distributed guessing, event 1009)."),

    row("Attacks", 5),
    timeseries("Failed logons per minute",
               [target(f"sum by (event_id) (rate(rdpguard_failed_logons_total{{{SEL}}}[5m])) * 60", "event {{event_id}}")],
               0, 6, stack=True,
               desc="4625 = Security failed logon, 140 = RdpCoreTS authentication failure (4625 duplicates removed)."),
    timeseries("Attacking IPs",
               [target(f"sum(rdpguard_attacking_ips_last_1h{{{SEL}}})", "last 1h", "A"),
                target(f"sum(rdpguard_attacking_ips_last_24h{{{SEL}}})", "last 24h", "B")], 12, 6),

    row("Bans", 14),
    timeseries("New bans per hour, by rule",
               [target(f"sum by (rule) (increase(rdpguard_ban_triggers_total{{{SEL}}}[1h]))", "{{rule}}")],
               0, 15, stack=True, bars=True,
               desc="wrong_password: 5 wrong passwords for an existing account/day; no_such_user: 3 unknown user names/day; "
                    "periodic: 5 attempts at regular intervals (bots); fast: 5/10 min; slow: 15/day."),
    timeseries("Active bans by offense",
               [target(f"sum by (offense) (rdpguard_active_bans_by_offense{{{SEL}}})", "offense {{offense}}")],
               12, 15, stack=True, desc="Offense n bans last BaseBanDuration * 2^(n-1), capped at MaxBanDuration."),
    timeseries("New bans per hour, by offense",
               [target(f"sum by (offense) (increase(rdpguard_bans_total{{{SEL}}}[1h]))", "offense {{offense}}")],
               0, 23, stack=True, bars=True),
    timeseries("Lifted bans per hour",
               [target(f"sum by (reason) (increase(rdpguard_unbans_total{{{SEL}}}[1h]))", "{{reason}}")],
               12, 23, stack=True, bars=True),

    row("Accounts", 31),
    bargauge("Wrong passwords per account, 24h",
             f"sort_desc(sum by (account) (rdpguard_account_wrong_passwords_last_24h{{{SEL}}}))", "{{account}}",
             0, 32, 8, 8, thresholds(("green", None), ("orange", 5), ("red", 20)),
             desc="Wrong passwords for EXISTING accounts from all addresses. Someone knows these account names."),
    bargauge("Addresses guessing each account, 24h",
             f"sort_desc(max by (account) (rdpguard_account_wrong_password_ips_last_24h{{{SEL}}}))", "{{account}}",
             8, 32, 8, 8, thresholds(("green", None), ("orange", 2), ("red", 3)),
             desc="3+ addresses on one account means distributed guessing: per-IP bans do not stop it."),
    timeseries("Wrong passwords per account (rolling 24h)",
               [target(f"sum by (account) (rdpguard_account_wrong_passwords_last_24h{{{SEL}}})", "{{account}}")],
               16, 32, w=8),
    timeseries("Successful external logons per hour",
               [target(f"sum by (whitelisted) (increase(rdpguard_external_logons_total{{{SEL}}}[1h]))",
                       "whitelisted={{whitelisted}}")], 0, 40, w=24, bars=True,
               desc="whitelisted=false: a successful logon from a public address that is not in the whitelist."),

    row("Health", 48),
    stat("Blocked addresses", f"sum(rdpguard_firewall_addresses{{{SEL}}})", 0, 49,
         desc="Addresses in RdpGuard-Block-NN rules after the last reconciliation (absent in DRY RUN)."),
    stat("Firewall rules", f"sum(rdpguard_firewall_rules{{{SEL}}})", 4, 49),
    stat("Since last firewall sync", f"time() - max(rdpguard_firewall_last_sync_timestamp_seconds{{{SEL}}})", 8, 49, unit="s",
         th=thresholds(("green", None), ("orange", 180), ("red", 600)),
         desc="The service reconciles every minute; a growing value means firewall errors."),
    stat("Logon auditing", f"min(rdpguard_logon_audit_enabled{{{SEL}}})", 12, 49,
         mappings=value_map([(0, "OFF", "red"), (1, "ON", "green")]), th=thresholds(("red", None), ("green", 1)),
         desc="Windows must log Success and Failure logons (Audit Logon), otherwise RdpGuard sees no attacks. "
              "RdpGuard re-enables it hourly; OFF that persists means a Group Policy disables it."),
    stat("Event queue", f"sum(rdpguard_queue_length{{{SEL}}})", 16, 49,
         th=thresholds(("green", None), ("orange", 1000), ("red", 10000))),
    stat("Database", f"min(rdpguard_database_up{{{SEL}}})", 20, 49,
         mappings=value_map([(0, "DOWN", "red"), (1, "OK", "green")]), th=thresholds(("red", None), ("green", 1))),
    timeseries("Errors per hour",
               [target(f"sum by (stage) (increase(rdpguard_errors_total{{{SEL}}}[1h]))", "{{stage}}"),
                target(f'sum(increase(rdpguard_firewall_syncs_total{{result="error",{SEL}}}[1h]))', "firewall sync errors", "B")],
               0, 53, w=18, bars=True),
    stat("Uptime", f"time() - max(rdpguard_start_time_seconds{{{SEL}}})", 18, 53, w=6, h=8, unit="s"),
]

dashboard = {
    "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "description": "", "type": "datasource",
                  "pluginId": "prometheus", "pluginName": "Prometheus"}],
    "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
                   {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
                   {"type": "panel", "id": "bargauge", "name": "Bar gauge", "version": ""},
                   {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
                   {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""}],
    "title": "RdpGuard", "uid": "rdpguard", "tags": ["rdpguard", "security", "windows"],
    "timezone": "browser", "schemaVersion": 39, "version": 2, "editable": True, "graphTooltip": 1,
    "time": {"from": "now-24h", "to": "now"}, "refresh": "1m",
    "templating": {"list": [{
        "name": "instance", "label": "Server", "type": "query", "datasource": DS,
        "query": {"query": "label_values(rdpguard_info, instance)", "refId": "Instance"},
        "definition": "label_values(rdpguard_info, instance)", "refresh": 2, "includeAll": True, "multi": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "allValue": ".*", "sort": 1}]},
    "annotations": {"list": []},
    "panels": panels,
}

out = pathlib.Path(__file__).with_name("rdpguard-dashboard.json")
out.write_text(json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"{out.name}: {len(panels)} panels")
