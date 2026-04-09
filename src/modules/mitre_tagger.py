#!/usr/bin/env python3
"""
MFF v2 — Module: MITRE ATT&CK Auto-Tagger
Maps process names, cmdline patterns, and memory findings to ATT&CK Tactic/Technique IDs.
No external ATT&CK library needed — uses a built-in curated mapping.
"""

import pandas as pd
import re

# ============================================================
# ATT&CK Mapping Database  (curated for Windows memory forensics)
# ============================================================
ATTACK_MAP = [
    # ── Execution ────────────────────────────────────────────
    {"tactic": "Execution",         "technique": "T1059.001", "name": "PowerShell",
     "keywords": ["powershell", "pwsh"],  "source": ["cmdline", "pslist"]},
    {"tactic": "Execution",         "technique": "T1059.003", "name": "Windows Command Shell",
     "keywords": ["cmd.exe", "cmd /c", "cmd /k"], "source": ["cmdline", "pslist"]},
    {"tactic": "Execution",         "technique": "T1059.005", "name": "VBScript",
     "keywords": ["wscript", "cscript", "vbscript", ".vbs"], "source": ["cmdline"]},
    {"tactic": "Execution",         "technique": "T1059.007", "name": "JavaScript",
     "keywords": ["mshta", ".hta", "jscript"], "source": ["cmdline"]},
    {"tactic": "Execution",         "technique": "T1204",     "name": "User Execution",
     "keywords": ["AtomicRedTeam", "invoke-", "iex ", "invoke-expression"], "source": ["cmdline"]},

    # ── Defense Evasion ──────────────────────────────────────
    {"tactic": "Defense Evasion",   "technique": "T1055.001", "name": "Dynamic-link Library Injection",
     "keywords": ["VirtualAllocEx", "WriteProcessMemory", "RWXinjection", "LoadLibrary"],
     "source": ["cmdline", "malfind"]},
    {"tactic": "Defense Evasion",   "technique": "T1055.002", "name": "Portable Executable Injection",
     "keywords": ["CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread"],
     "source": ["cmdline", "malfind"]},
    {"tactic": "Defense Evasion",   "technique": "T1218.010", "name": "Regsvr32",
     "keywords": ["regsvr32"], "source": ["cmdline", "pslist"]},
    {"tactic": "Defense Evasion",   "technique": "T1218.011", "name": "Rundll32",
     "keywords": ["rundll32"], "source": ["cmdline", "pslist"]},
    {"tactic": "Defense Evasion",   "technique": "T1140",     "name": "Deobfuscate/Decode Files",
     "keywords": ["certutil", "-decode", "-urlcache", "base64"], "source": ["cmdline"]},
    {"tactic": "Defense Evasion",   "technique": "T1036",     "name": "Masquerading",
     "keywords": ["svchost32", "svch0st", "lsass64", "csrss32", "scvhost", "svhost", "lsasss"],  "source": ["pslist", "cmdline"]},

    # ── DLL Hijacking (T1574) — detected from cmdline patterns ──
    {"tactic": "Defense Evasion",   "technique": "T1574.001", "name": "DLL Search Order Hijacking",
     "keywords": ["copy-item", "amsi.dll", "version.dll", "cryptbase.dll",
                  "dll sideload", "invoke-atomictest t1574", "T1574"],
     "source": ["cmdline"]},
    {"tactic": "Defense Evasion",   "technique": "T1574.006", "name": "Dynamic Linker Hijacking",
     "keywords": ["ld_preload", "dyld_insert"], "source": ["cmdline"]},

    # ── Process Injection (T1055 sub-techniques) ─────────────
    {"tactic": "Defense Evasion",   "technique": "T1055.005", "name": "Thread Local Storage Injection",
     "keywords": ["TlsCallback", "TlsIndex", "tls inject"], "source": ["cmdline", "malfind"]},
    {"tactic": "Defense Evasion",   "technique": "T1562.001", "name": "Disable/Modify Tools",
     "keywords": ["set-mppreference", "disablerealtimemonitoring", "disable-windowsdefender",
                  "disableantispyware", "add-mppreference"], "source": ["cmdline"]},

    # ── Credential Access ─────────────────────────────────────
    {"tactic": "Credential Access", "technique": "T1003.001", "name": "LSASS Memory Dump",
     "keywords": ["mimikatz", "procdump", "sekurlsa", "wce.exe", "lsass.dmp", "out lsass"],
     "source": ["cmdline", "malfind"]},
    {"tactic": "Credential Access", "technique": "T1003.002", "name": "Security Account Manager",
     "keywords": ["sam", "reg save", "hklm\\sam"], "source": ["cmdline"]},

    # ── Discovery ────────────────────────────────────────────
    {"tactic": "Discovery",  "technique": "T1057",  "name": "Process Discovery",
     "keywords": ["tasklist", "get-process", "ps aux", "gwmi win32_process",
                  "get-wmiobject win32_process"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1033",  "name": "System Owner/User Discovery",
     "keywords": ["whoami", "getuid", "get-localuser", "net user", "$env:username",
                  "[system.environment]::username"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1082",  "name": "System Information Discovery",
     "keywords": ["systeminfo", "get-computerinfo", "wmic os", "hostname",
                  "[system.environment]::osversion", "get-wmiobject win32_operatingsystem",
                  "gwmi win32_bios", "get-bios", "wmic bios", "wmic cpu",
                  "wmic computersystem", "[environment]::machinename"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1016",  "name": "System Network Configuration Discovery",
     "keywords": ["ipconfig", "get-netipaddress", "get-netadapter", "get-dnsclientserveraddress",
                  "netstat", "get-netroute", "arp -a", "get-netneighbor",
                  "route print", "nbtstat", "netsh interface"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1049",  "name": "System Network Connections Discovery",
     "keywords": ["netstat -an", "get-nettcpconnection", "get-netudpendpoint",
                  "ss -tulpn"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1083",  "name": "File and Directory Discovery",
     "keywords": ["get-childitem", "dir /s", "ls -la", "find . -name",
                  "tree /f", "get-item", "test-path"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1012",  "name": "Query Registry",
     "keywords": ["reg query", "get-itemproperty hklm", "get-item hkcu",
                  "get-childitem hklm:", "regedit"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1069",  "name": "Permission Groups Discovery",
     "keywords": ["net localgroup", "net group", "gpresult", "get-localgroup",
                  "get-localgroupmember", "get-adgroup"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1018",  "name": "Remote System Discovery",
     "keywords": ["net view", "nslookup", "nltest", "get-adcomputer",
                  "invoke-command -computername", "test-connection"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1007",  "name": "System Service Discovery",
     "keywords": ["get-service", "net start", "sc query", "wmic service",
                  "get-wmiobject win32_service"],
     "source": ["cmdline"]},
    {"tactic": "Discovery",  "technique": "T1087",  "name": "Account Discovery",
     "keywords": ["get-aduser", "net accounts", "query user", "lusrmgr"],
     "source": ["cmdline"]},

    # ── Collection ───────────────────────────────────────────
    {"tactic": "Collection",  "technique": "T1005",  "name": "Data from Local System",
     "keywords": ["get-content", "type ", "copy-item c:", "robocopy",
                  "compress-archive", "[io.file]::readalltext"],
     "source": ["cmdline"]},
    {"tactic": "Collection",  "technique": "T1113",  "name": "Screen Capture",
     "keywords": ["screenshot", "[drawing.bitmap]", "capturescreenshot",
                  "add-type -assemblyname system.drawing"],
     "source": ["cmdline"]},
    {"tactic": "Collection",  "technique": "T1056.001",  "name": "Keylogging",
     "keywords": ["get-keystroke", "readkey", "[console]::readkey", "keylogger"],
     "source": ["cmdline"]},

    # ── Lateral Movement ─────────────────────────────────────
    {"tactic": "Lateral Movement",  "technique": "T1021.002", "name": "SMB/Windows Admin Shares",
     "keywords": ["net use", "psexec", "\\\\admin$", "\\\\c$", "\\\\ipc$"], "source": ["cmdline", "netscan"]},

    # ── Persistence ──────────────────────────────────────────
    {"tactic": "Persistence",       "technique": "T1053.005", "name": "Scheduled Task",
     "keywords": ["schtasks", "at.exe", "taskschd"], "source": ["cmdline", "pslist"]},
    {"tactic": "Persistence",       "technique": "T1547.001", "name": "Registry Run Keys",
     "keywords": ["reg add", "currentversion\\run", "userinit"], "source": ["cmdline"]},
    {"tactic": "Persistence",       "technique": "T1546.003", "name": "WMI Event Subscription",
     "keywords": ["new-wmiobject __eventfilter", "__eventconsumer", "wmi subscription"],
     "source": ["cmdline"]},
    {"tactic": "Persistence",       "technique": "T1078",     "name": "Valid Accounts",
     "keywords": ["net user /add", "add-localuser", "new-localuser"],
     "source": ["cmdline"]},

    # ── Command and Control ──────────────────────────────────
    {"tactic": "Command and Control","technique": "T1105",    "name": "Ingress Tool Transfer",
     "keywords": ["bitsadmin", "wget", "curl", "certutil -urlcache", "invoke-webrequest"],
     "source": ["cmdline"]},
    {"tactic": "Command and Control","technique": "T1071.001","name": "Web Protocols",
     "keywords": [":80", ":443", ":8080", ":8443"], "source": ["netscan"]},
    {"tactic": "Command and Control","technique": "T1095",    "name": "Non-Application Layer Protocol",
     "keywords": [":4444", ":1337", ":31337", "meterpreter"], "source": ["netscan", "cmdline"]},

    # ── Privilege Escalation ─────────────────────────────────
    {"tactic": "Privilege Escalation", "technique": "T1055",  "name": "Process Injection",
     "keywords": ["VirtualAllocEx", "WriteProcessMemory", "OpenProcess", "inject"],
     "source": ["cmdline", "malfind"]},
    {"tactic": "Privilege Escalation", "technique": "T1548.002", "name": "Bypass UAC",
     "keywords": ["bypass-uac", "bypassuac", "fodhelper", "eventvwr", "sdclt",
                  "computerdefaults", "uacbypass"],
     "source": ["cmdline"]},

    # ── Exfiltration ─────────────────────────────────────────
    {"tactic": "Exfiltration",      "technique": "T1048",     "name": "Exfiltration Over Alt Protocol",
     "keywords": [":21", ":22", "ftp", "sftp", "scp"], "source": ["netscan"]},
]

TACTIC_COLORS = {
    "Execution":              "#f78166",
    "Defense Evasion":        "#d29922",
    "Credential Access":      "#ff6b6b",
    "Discovery":              "#58a6ff",
    "Lateral Movement":       "#c9a227",
    "Persistence":            "#bc8cff",
    "Command and Control":    "#e06c75",
    "Exfiltration":           "#e5534b",
    "Collection":             "#56d364",
    "Privilege Escalation":   "#ff7b72",
    "Initial Access":         "#ffa657",
    "Impact":                 "#f85149",
}


def tag_dataframe(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """
    Given a DataFrame and a source label (pslist/cmdline/malfind/netscan),
    return a new DataFrame of ATT&CK hits with columns:
      PID, Process/Args, Tactic, Technique, TechniqueName, MatchedKeyword
    """
    if df.empty:
        return pd.DataFrame()

    # pick the text column to scan
    text_col = None
    for candidate in ("Args", "ImageFileName", "Protection", "ForeignAddr", "LocalAddr"):
        if candidate in df.columns:
            text_col = candidate
            break

    if text_col is None:
        return pd.DataFrame()

    hits = []

    for rule in ATTACK_MAP:
        if source not in rule["source"]:
            continue

        for kw in rule["keywords"]:
            mask = df[text_col].astype(str).str.contains(
                re.escape(kw), case=False, na=False)
            matches = df[mask]
            if matches.empty:
                continue

            for _, row in matches.iterrows():
                hits.append({
                    "PID":           row.get("PID", ""),
                    "Process":       row.get("ImageFileName", row.get("Process", "?")),
                    "MatchedText":   str(row.get(text_col, ""))[:120],
                    "MatchedKeyword":kw,
                    "Tactic":        rule["tactic"],
                    "Technique":     rule["technique"],
                    "TechniqueName": rule["name"],
                    "ATT&CK_URL":    f"https://attack.mitre.org/techniques/{rule['technique'].replace('.','/')}",
                })

    if not hits:
        return pd.DataFrame()

    return pd.DataFrame(hits).drop_duplicates(
        subset=["PID", "Technique", "MatchedKeyword"])


def tag_all(pslist_df, cmdline_df, malfind_df, netscan_df) -> pd.DataFrame:
    """Tag all sources and merge into one ATT&CK findings table."""
    frames = [
        tag_dataframe(pslist_df,  "pslist"),
        tag_dataframe(cmdline_df, "cmdline"),
        tag_dataframe(malfind_df, "malfind"),
        tag_dataframe(netscan_df, "netscan"),
    ]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame()

    merged = pd.concat(frames, ignore_index=True).drop_duplicates(
        subset=["PID", "Technique", "MatchedKeyword"])

    return merged.sort_values(["Tactic", "Technique"])


def summary_by_tactic(tagged_df: pd.DataFrame) -> pd.DataFrame:
    """Group ATT&CK hits by tactic for dashboard use."""
    if tagged_df.empty:
        return pd.DataFrame()
    return (tagged_df.groupby(["Tactic", "Technique", "TechniqueName"])
                     .size()
                     .reset_index(name="HitCount")
                     .sort_values("HitCount", ascending=False))
