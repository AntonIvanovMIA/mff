#!/usr/bin/env python3
"""
MFF v2 — Module: Network Diff + IOC Extractor
- Diffs netscan baseline vs attack (new connections, new listeners, new foreign IPs)
- Extracts IOCs: IPs, file paths, hashes, domains from all dataframes
"""

import re
import hashlib
import pandas as pd
from datetime import datetime, UTC


# ============================================================
# Network Diff
# ============================================================

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    1337:  "Hacker classic",
    31337: "Hacker classic (elite)",
    9001:  "Tor",
    9050:  "Tor SOCKS",
    6666:  "IRC/C2",
    6667:  "IRC/C2",
    8888:  "Common C2",
    2222:  "Alt SSH",
    5555:  "Android ADB / RAT",
    3389:  "RDP",
    445:   "SMB",
    135:   "DCOM/RPC",
    139:   "NetBIOS",
}


def parse_port(addr_str: str) -> int:
    """Extract port number from '1.2.3.4:443' or '[::1]:443'."""
    try:
        return int(str(addr_str).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return 0


def network_diff(base_df: pd.DataFrame, attack_df: pd.DataFrame):
    """
    Compare netscan DataFrames.
    Returns:
        new_conns  — connections present in attack but not baseline
        gone_conns — connections present in baseline but not attack
        flagged    — new connections hitting suspicious ports
    """
    if base_df.empty and attack_df.empty:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # Normalize key columns
    key_cols = ["PID", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State"]
    key_cols = [c for c in key_cols if c in (attack_df.columns if not attack_df.empty else [])]

    if attack_df.empty:
        return pd.DataFrame(), base_df.copy(), pd.DataFrame()
    if base_df.empty:
        return attack_df.copy(), pd.DataFrame(), pd.DataFrame()

    # Build composite keys for dedup comparison
    def make_key(df):
        cols = [c for c in key_cols if c in df.columns]
        # fillna("") before astype(str) prevents NaN float leaking into join
        return df[cols].fillna("").astype(str).apply(lambda r: "|".join(r.values), axis=1)

    base_keys   = set(make_key(base_df))
    attack_keys = set(make_key(attack_df))

    atk_mask  = make_key(attack_df).isin(attack_keys - base_keys)
    gone_mask = make_key(base_df).isin(base_keys - attack_keys)

    new_conns  = attack_df[atk_mask].copy()
    gone_conns = base_df[gone_mask].copy()

    # Flag suspicious ports in new connections
    flagged_rows = []
    for _, row in new_conns.iterrows():
        for port_col in ("ForeignPort", "LocalPort", "ForeignAddr", "LocalAddr"):
            if port_col not in row.index:
                continue
            port = parse_port(str(row[port_col]))
            if port in SUSPICIOUS_PORTS:
                r = row.to_dict()
                r["SuspiciousPort"]  = port
                r["PortMeaning"]     = SUSPICIOUS_PORTS[port]
                flagged_rows.append(r)
                break

    flagged = pd.DataFrame(flagged_rows) if flagged_rows else pd.DataFrame()

    return new_conns, gone_conns, flagged


# ============================================================
# IOC Extractor
# ============================================================

IPV4_RE     = re.compile(r'\b(?!10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE   = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|gov|edu|mil|xyz|top|biz|info|ru|cn|tk|pw|cc|co|us|uk|de|fr|onion)\b', re.I)
HASH_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
FILEPATH_RE = re.compile(r'(?:[A-Za-z]:\\|\\\\|/tmp/|/var/|/home/|/root/|/usr/)[^\s\'"<>|;,\x00-\x1f]+', re.I)
URL_RE      = re.compile(r'https?://[^\s\'"<>|;,\x00-\x1f]+', re.I)


def _scan_text(text: str, source_label: str) -> list:
    """Scan a string for IOCs. Returns list of dicts."""
    iocs = []
    text = str(text)

    for m in IPV4_RE.findall(text):
        iocs.append({"Type": "IPv4", "Value": m, "Source": source_label})

    for m in DOMAIN_RE.findall(text):
        iocs.append({"Type": "Domain", "Value": m, "Source": source_label})

    for m in URL_RE.findall(text):
        iocs.append({"Type": "URL", "Value": m[:200], "Source": source_label})

    for m in HASH_SHA256.findall(text):
        iocs.append({"Type": "SHA256", "Value": m, "Source": source_label})

    for m in HASH_SHA1.findall(text):
        iocs.append({"Type": "SHA1", "Value": m, "Source": source_label})

    for m in HASH_MD5.findall(text):
        iocs.append({"Type": "MD5", "Value": m, "Source": source_label})

    for m in FILEPATH_RE.findall(text):
        clean = m.strip("\\/ \t\r\n")
        if len(clean) > 4:
            iocs.append({"Type": "FilePath", "Value": clean[:200], "Source": source_label})

    return iocs


def extract_iocs(pslist_df, cmdline_df, malfind_df, netscan_df) -> pd.DataFrame:
    """
    Scan all available dataframes for IOCs.
    Returns deduplicated IOC table with Type, Value, Source columns.
    """
    all_iocs = []

    source_map = {
        "pslist":  (pslist_df,  ["ImageFileName", "PPID"]),
        "cmdline": (cmdline_df, ["Args", "ImageFileName"]),
        "malfind": (malfind_df, ["Protection", "Hexdump", "Disasm"]),
        "netscan": (netscan_df, ["LocalAddr", "ForeignAddr", "Owner"]),
    }

    for label, (df, cols) in source_map.items():
        if df.empty:
            continue
        for col in cols:
            if col not in df.columns:
                continue
            for val in df[col].dropna().astype(str):
                all_iocs.extend(_scan_text(val, label))

    if not all_iocs:
        return pd.DataFrame(columns=["Type", "Value", "Source", "Count"])

    ioc_df = pd.DataFrame(all_iocs)
    ioc_df = (ioc_df.groupby(["Type", "Value"])
                    .agg(Source=("Source", lambda x: ", ".join(sorted(set(x)))),
                         Count=("Value", "count"))
                    .reset_index()
                    .sort_values(["Type", "Count"], ascending=[True, False]))

    return ioc_df


def ioc_to_json(ioc_df: pd.DataFrame) -> list:
    """Convert IOC dataframe to list of dicts for JSON/SIEM export."""
    if ioc_df.empty:
        return []
    return ioc_df.to_dict(orient="records")
