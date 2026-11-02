"""Draw the two figures of the paper from results.json (no other input)."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).parent
R = json.loads((HERE / "results.json").read_text())
COL = {
    "none": "#555555",
    "prompt_hardening": "#c8742a",
    "detector": "#2a7fb8",
    "taintguard": "#3a8f5c",
}
LAB = {
    "none": "no defense",
    "prompt_hardening": "prompt hardening",
    "detector": "detector",
    "taintguard": "TaintGuard",
}
plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False})


def funnel() -> None:
    f = R["exposure_funnel"]
    layers = f["layers"]
    x = np.arange(len(layers))
    fig, ax = plt.subplots(figsize=(5.6, 2.9))
    for i, (key, lab, c) in enumerate(
        [
            ("real1_natural", "natural pipeline (LLM summaries)", "#555555"),
            ("real2_extractive", "extractive summaries", "#2a7fb8"),
        ]
    ):
        ax.bar(x + (i - 0.5) * 0.36, f[key], 0.36, label=lab, color=c)
    ax.set_xticks(x, layers)
    ax.set_ylabel("share of attack trials")
    ax.set_ylim(0, 1.0)
    ax.legend(frameon=False, loc="upper right")
    ax.set_title("Where an injected payload is still present (no defense)", fontsize=9)
    fig.tight_layout()
    fig.savefig(HERE / "figs" / "funnel.pdf")


def enrich() -> None:
    g = R["enrichment_attack"]["by_goal"]
    goals = list(g)
    defs = ["none", "prompt_hardening", "detector", "taintguard"]
    x = np.arange(len(goals))
    fig, ax = plt.subplots(figsize=(6.2, 3.1))
    w = 0.2
    for i, d in enumerate(defs):
        ax.bar(
            x + (i - 1.5) * w,
            [g[k][d][0] / g[k][d][1] for k in goals],
            w,
            label=LAB[d],
            color=COL[d],
        )
    ax.set_xticks(x, [k.replace(": ", ":\n") for k in goals], fontsize=7.5)
    ax.set_ylabel("share of applicable attacks that steered the labeler")
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    fig.tight_layout()
    fig.savefig(HERE / "figs" / "enrich.pdf")


if __name__ == "__main__":
    funnel()
    enrich()
    print("wrote figs/funnel.pdf and figs/enrich.pdf")
