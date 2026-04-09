#!/usr/bin/env python3
"""
MFF v2 — Module: Parent-Child Process Tree Visualization
Renders a tree chart showing process parent/child relationships.
Highlights new (attack-only) processes in red.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
import os
from collections import defaultdict

THEME = {
    "bg":      "#0d1117",
    "panel":   "#161b22",
    "border":  "#30363d",
    "attack":  "#f78166",
    "safe":    "#3fb950",
    "warn":    "#d29922",
    "info":    "#58a6ff",
    "text":    "#e6edf3",
    "subtext": "#8b949e",
    "edge":    "#444c56",
    "line":    "#30363d",
}


# ============================================================
# Tree Builder
# ============================================================

def build_tree(pslist_df: pd.DataFrame, new_pids: set) -> dict:
    """
    Returns a dict: { pid: {"name": str, "children": [pid, ...], "is_new": bool} }
    """
    if pslist_df.empty:
        return {}

    df = pslist_df.copy()
    df["PID"]  = pd.to_numeric(df["PID"],  errors="coerce").fillna(0).astype(int)
    df["PPID"] = pd.to_numeric(df.get("PPID", pd.Series(dtype=int)), errors="coerce").fillna(0).astype(int) \
                 if "PPID" in df.columns else pd.Series([0]*len(df), dtype=int)

    nodes = {}
    for _, row in df.iterrows():
        pid  = int(row["PID"])
        ppid = int(row.get("PPID", 0))
        name = str(row.get("ImageFileName", f"PID_{pid}"))
        nodes[pid] = {
            "name":     name,
            "ppid":     ppid,
            "children": [],
            "is_new":   pid in new_pids,
        }

    # Wire up children
    for pid, node in nodes.items():
        ppid = node["ppid"]
        if ppid in nodes and ppid != pid:
            nodes[ppid]["children"].append(pid)

    return nodes


# ============================================================
# Layout Engine  (Reingold-Tilford inspired, manual)
# ============================================================

def _layout(nodes, root_pids):
    """
    Assign (x, y) positions to every node.
    Returns dict: { pid: (x, y) }
    """
    positions = {}
    x_counter = [0]

    def place(pid, depth):
        node = nodes.get(pid)
        if node is None:
            return
        children = node["children"]
        if not children:
            x_counter[0] += 1
            positions[pid] = (x_counter[0], -depth)
        else:
            for child in children:
                place(child, depth + 1)
            xs = [positions[c][0] for c in children if c in positions]
            positions[pid] = ((min(xs) + max(xs)) / 2, -depth) if xs else (x_counter[0], -depth)

    for root in root_pids:
        place(root, 0)
        x_counter[0] += 2  # gap between trees

    return positions


def _find_roots(nodes):
    """Nodes whose PPID is not in the node set (true roots)."""
    all_pids = set(nodes.keys())
    roots = [pid for pid, n in nodes.items()
             if n["ppid"] not in all_pids or n["ppid"] == pid]
    # Sort roots by PID
    return sorted(roots)


# ============================================================
# Render
# ============================================================

def render_process_tree(attack_df: pd.DataFrame, new_df: pd.DataFrame, out_dir: str):
    """
    Render and save the process tree image.
    Nodes are colored red if the process is new in the attack capture.
    """
    if attack_df.empty:
        print("  [!] No pslist data — skipping process tree")
        return

    new_pids = set(new_df["PID"].astype(int).tolist()) if not new_df.empty else set()
    nodes    = build_tree(attack_df, new_pids)

    if not nodes:
        return

    roots     = _find_roots(nodes)
    positions = _layout(nodes, roots)

    if not positions:
        return

    xs = [v[0] for v in positions.values()]
    ys = [v[1] for v in positions.values()]
    x_range = max(xs) - min(xs) + 1
    y_range = abs(min(ys)) + 1

    # Fixed readable size — wide enough for ~50 nodes across
    fig_w = min(max(x_range * 1.8, 18), 34)
    fig_h = min(max(y_range * 1.6, 9),  22)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["bg"])
    fig.subplots_adjust(left=0.01, right=0.99, top=0.93, bottom=0.03)

    # Draw edges first
    for pid, node in nodes.items():
        if pid not in positions:
            continue
        px, py = positions[pid]
        for child in node["children"]:
            if child not in positions:
                continue
            cx, cy = positions[child]
            ax.plot([px, cx], [py, cy],
                    color=THEME["edge"], linewidth=0.7, zorder=1, alpha=0.5)

    # Draw nodes — only show NEW processes + their direct parents for readability
    for pid, (x, y) in positions.items():
        node   = nodes[pid]
        is_new = node["is_new"]
        # Has a new child?
        has_new_child = any(nodes[c]["is_new"] for c in node["children"] if c in nodes)

        color  = THEME["attack"] if is_new else THEME["safe"]
        border = "#ffffff" if is_new else THEME["border"]
        size   = 280 if is_new else 180

        ax.scatter(x, y, s=size, color=color, zorder=3,
                   edgecolors=border, linewidths=1.4 if is_new else 0.8)

        # Show label for all new processes and notable parents
        show_label = is_new or has_new_child or node["ppid"] == 0
        if show_label:
            fs = 8 if is_new else 7
            fw = "bold" if is_new else "normal"
            label = f"{node['name']}\n({pid})"
            ax.text(x, y - 0.32, label,
                    ha="center", va="top",
                    fontsize=fs, fontweight=fw,
                    color=THEME["text"] if is_new else THEME["subtext"],
                    fontfamily="monospace", zorder=4)

    # Legend
    new_patch  = mpatches.Patch(color=THEME["attack"], label="New in Attack")
    safe_patch = mpatches.Patch(color=THEME["safe"],   label="Baseline Process")
    ax.legend(handles=[new_patch, safe_patch],
              loc="upper left", fontsize=9,
              facecolor=THEME["panel"], edgecolor=THEME["border"],
              labelcolor=THEME["text"])

    ax.set_title("Parent–Child Process Tree  (Attack Capture)",
                 color=THEME["text"], fontsize=13, fontweight="bold", pad=14)
    ax.axis("off")

    out_path = os.path.join(out_dir, "chart_process_tree.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close(fig)
    print(f"  [+] Process tree saved: {out_path}")


# ============================================================
# ATT&CK Matrix Heatmap  (bonus chart)
# ============================================================

def render_attack_heatmap(tagged_df: pd.DataFrame, out_dir: str):
    """Render a mini heatmap of tactic × technique hit counts."""
    if tagged_df.empty:
        return

    TACTIC_ORDER = [
        "Execution", "Persistence", "Defense Evasion",
        "Credential Access", "Discovery",
        "Lateral Movement", "Command and Control", "Exfiltration",
    ]

    pivot = (tagged_df.groupby(["Tactic", "TechniqueName"])
                      .size()
                      .reset_index(name="Hits"))

    tactics_present = [t for t in TACTIC_ORDER if t in pivot["Tactic"].values]
    if not tactics_present:
        return

    # Build matrix
    tech_list = pivot["TechniqueName"].unique().tolist()
    matrix    = pd.DataFrame(0, index=tech_list, columns=tactics_present)

    for _, row in pivot.iterrows():
        if row["Tactic"] in tactics_present:
            matrix.loc[row["TechniqueName"], row["Tactic"]] = row["Hits"]

    # Remove empty rows
    matrix = matrix[matrix.sum(axis=1) > 0]

    import matplotlib.patches as mpatches_hm
    import matplotlib.cm as cm
    import matplotlib.colors as mcolors

    n_tactics    = len(tactics_present)
    n_techniques = len(matrix.index)

    # Fixed cell size — always readable regardless of how many cells
    CELL_W = 2.8
    CELL_H = 0.9
    fig_w  = max(10, n_tactics * CELL_W + 3.5)
    fig_h  = max(4,  n_techniques * CELL_H + 2.5)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["bg"])

    data = matrix.values.astype(float)
    vmax = max(float(data.max()), 1)

    # Use patch rectangles — looks correct at any matrix size
    cmap     = cm.get_cmap("YlOrRd")
    norm     = mcolors.Normalize(vmin=0, vmax=vmax)

    for i, tech in enumerate(matrix.index):
        for j, tactic in enumerate(tactics_present):
            val  = float(data[i, j])
            rgba = cmap(norm(val)) if val > 0 else (0.12, 0.15, 0.18, 1.0)
            rect = mpatches_hm.FancyBboxPatch(
                (j + 0.05, i + 0.05), 0.9, 0.9,
                boxstyle="round,pad=0.02",
                facecolor=rgba,
                edgecolor=THEME["bg"],
                linewidth=2,
                transform=ax.transData,
            )
            ax.add_patch(rect)
            if val > 0:
                txt_c = "black" if norm(val) > 0.5 else THEME["text"]
                ax.text(j + 0.5, i + 0.5, str(int(val)),
                        ha="center", va="center",
                        fontsize=13, fontweight="bold", color=txt_c)
            else:
                ax.text(j + 0.5, i + 0.5, "·",
                        ha="center", va="center",
                        fontsize=10, color=THEME["subtext"], alpha=0.4)

    # Axes labels
    ax.set_xlim(0, n_tactics)
    ax.set_ylim(0, n_techniques)
    ax.set_xticks([j + 0.5 for j in range(n_tactics)])
    ax.set_xticklabels(tactics_present, rotation=30, ha="right",
                       fontsize=10, color=THEME["text"])
    ax.set_yticks([i + 0.5 for i in range(n_techniques)])
    ax.set_yticklabels(matrix.index, fontsize=9, color=THEME["text"])
    ax.invert_yaxis()
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)

    # Colorbar
    sm = cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax, shrink=0.6, pad=0.02)
    cbar.set_label("Hit Count", color=THEME["subtext"], fontsize=8)
    cbar.ax.yaxis.set_tick_params(color=THEME["subtext"])
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=THEME["subtext"])
    cbar.ax.tick_params(labelsize=7)

    ax.set_title("MITRE ATT\u0026CK Coverage Heatmap",
                 color=THEME["text"], fontsize=12, fontweight="bold", pad=14)
    fig.tight_layout()

    out_path = os.path.join(out_dir, "chart_attack_heatmap.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close(fig)
    print(f"  [+] ATT&CK heatmap saved: {out_path}")
