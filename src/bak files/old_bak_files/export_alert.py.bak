#!/usr/bin/env python3
"""
MFF v2 — Module: Export & Alert
- JSON threat summary for SIEM/SOAR ingestion
- Slack / generic webhook alerts on critical findings
- Uses only stdlib (urllib) — no requests library needed
"""

import json
import os
import urllib.request
import urllib.error
import ssl
import pandas as pd
from datetime import datetime, UTC


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# ============================================================
# JSON Threat Summary  (SIEM/SOAR format)
# ============================================================

def build_json_summary(
    case_id: str,
    baseline_path: str,
    attack_path: str,
    new_df: pd.DataFrame,
    gone_df: pd.DataFrame,
    scores_df: pd.DataFrame,
    tagged_df: pd.DataFrame,
    ioc_df: pd.DataFrame,
    net_new_df: pd.DataFrame,
    net_flagged_df: pd.DataFrame,
) -> dict:
    """
    Build a structured JSON threat summary suitable for SIEM/SOAR ingestion.
    Schema is compatible with common SIEM event formats (Elastic ECS inspired).
    """

    def df_to_records(df):
        if df is None or df.empty:
            return []
        # Drop internal datetime columns before serialising
        drop_cols = [c for c in df.columns if c.endswith("_dt")]
        return df.drop(columns=drop_cols, errors="ignore").fillna("").to_dict(orient="records")

    # Severity roll-up
    critical_count = 0
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        critical_count = int((scores_df["RiskLevel"] == "CRITICAL").sum())
    high_count = 0
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        high_count = int((scores_df["RiskLevel"] == "HIGH").sum())

    overall_severity = "CRITICAL" if critical_count > 0 else \
                       "HIGH"     if high_count > 0     else \
                       "MEDIUM"   if not new_df.empty   else "LOW"

    summary = {
        "schema_version": "mff-v2.0",
        "generated_at":   now_utc(),
        "case_id":        case_id,
        "baseline_path":  baseline_path,
        "attack_path":    attack_path,

        "severity": {
            "overall":   overall_severity,
            "critical_processes": critical_count,
            "high_processes":     high_count,
        },

        "statistics": {
            "new_processes":        len(new_df)          if new_df is not None else 0,
            "gone_processes":       len(gone_df)         if gone_df is not None else 0,
            "attack_techniques":    len(tagged_df["Technique"].unique()) if not tagged_df.empty else 0,
            "attack_tactics":       len(tagged_df["Tactic"].unique())    if not tagged_df.empty else 0,
            "iocs_extracted":       len(ioc_df)          if not ioc_df.empty else 0,
            "new_network_conns":    len(net_new_df)      if not net_new_df.empty else 0,
            "flagged_network_conns":len(net_flagged_df)  if not net_flagged_df.empty else 0,
        },

        "mitre_attack": {
            "tactics_observed": sorted(tagged_df["Tactic"].unique().tolist())
                                 if not tagged_df.empty else [],
            "techniques_observed": df_to_records(
                tagged_df[["Technique","TechniqueName","Tactic","HitCount"]].drop_duplicates()
                if not tagged_df.empty and "HitCount" in tagged_df.columns
                else (tagged_df[["Technique","TechniqueName","Tactic"]].drop_duplicates()
                      if not tagged_df.empty else pd.DataFrame())
            ),
        },

        "process_diff": {
            "new":  df_to_records(new_df),
            "gone": df_to_records(gone_df),
        },

        "risk_scores": df_to_records(scores_df),

        "iocs": {
            "all": df_to_records(ioc_df),
            "ipv4":    [r["Value"] for r in df_to_records(ioc_df) if r.get("Type") == "IPv4"],
            "domains": [r["Value"] for r in df_to_records(ioc_df) if r.get("Type") == "Domain"],
            "hashes":  [r["Value"] for r in df_to_records(ioc_df) if r.get("Type") in ("MD5","SHA1","SHA256")],
            "urls":    [r["Value"] for r in df_to_records(ioc_df) if r.get("Type") == "URL"],
            "paths":   [r["Value"] for r in df_to_records(ioc_df) if r.get("Type") == "FilePath"],
        },

        "network": {
            "new_connections":     df_to_records(net_new_df),
            "flagged_connections": df_to_records(net_flagged_df),
        },
    }

    return summary


def write_json_summary(summary: dict, out_dir: str) -> str:
    path = os.path.join(out_dir, "threat_summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"  [+] JSON threat summary: {path}")
    return path


# ============================================================
# Slack / Webhook Alerter
# ============================================================

def _build_slack_payload(summary: dict) -> dict:
    """Build a Slack Block Kit message from the threat summary."""
    sev       = summary["severity"]["overall"]
    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
    stats     = summary["statistics"]
    tactics   = summary["mitre_attack"]["tactics_observed"]
    iocs      = summary["iocs"]

    header = f"{sev_emoji} *MFF Alert — {sev}* | Case: `{summary['case_id']}`"

    fields_text = (
        f"• New Processes: *{stats['new_processes']}*\n"
        f"• Critical Risk: *{summary['severity']['critical_processes']}*\n"
        f"• ATT&CK Techniques: *{stats['attack_techniques']}*\n"
        f"• IOCs Extracted: *{stats['iocs_extracted']}*\n"
        f"• New Net Connections: *{stats['new_network_conns']}*"
    )

    tactics_text = ", ".join(tactics) if tactics else "_None detected_"

    ioc_text = ""
    if iocs["ipv4"]:    ioc_text += f"IPs: `{'`, `'.join(iocs['ipv4'][:5])}`\n"
    if iocs["domains"]: ioc_text += f"Domains: `{'`, `'.join(iocs['domains'][:5])}`\n"
    if not ioc_text:    ioc_text = "_No external IOCs_"

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": f"MFF Memory Forensics Alert"}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": header}},
        {"type": "divider"},
        {"type": "section",
         "fields": [
             {"type": "mrkdwn", "text": f"*Statistics*\n{fields_text}"},
             {"type": "mrkdwn", "text": f"*ATT&CK Tactics*\n{tactics_text}"},
         ]},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*Top IOCs*\n{ioc_text}"}},
        {"type": "context",
         "elements": [{"type": "mrkdwn",
                       "text": f"Generated: {summary['generated_at']} | Baseline: `{summary['baseline_path']}` | Attack: `{summary['attack_path']}`"}]},
    ]
    return {"blocks": blocks}


def _build_generic_payload(summary: dict) -> dict:
    """Generic JSON webhook payload (for Teams, PagerDuty, custom SOAR)."""
    sev = summary["severity"]["overall"]
    return {
        "alert_type":   "memory_forensics",
        "severity":     sev,
        "case_id":      summary["case_id"],
        "generated_at": summary["generated_at"],
        "summary":      summary["statistics"],
        "tactics":      summary["mitre_attack"]["tactics_observed"],
        "top_iocs": {
            "ips":     summary["iocs"]["ipv4"][:10],
            "domains": summary["iocs"]["domains"][:10],
        },
    }


def send_webhook(webhook_url: str, summary: dict,
                 mode: str = "slack") -> bool:
    """
    Send alert to webhook.
    mode: 'slack' | 'generic'
    Returns True on success.
    """
    if not webhook_url:
        print("  [!] No webhook URL configured — skipping alert")
        return False

    payload = (_build_slack_payload(summary)   if mode == "slack"
               else _build_generic_payload(summary))

    data    = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "MFF-v2/1.0"}
    req     = urllib.request.Request(webhook_url, data=data, headers=headers)

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            status = resp.getcode()
            if status in (200, 204):
                print(f"  [+] Webhook alert sent ({mode}) — HTTP {status}")
                return True
            else:
                print(f"  [!] Webhook returned HTTP {status}")
                return False
    except urllib.error.URLError as e:
        print(f"  [!] Webhook failed: {e}")
        return False
    except Exception as e:
        print(f"  [!] Unexpected webhook error: {e}")
        return False
