"""Small statistics helpers: Wilson and bootstrap intervals, exact paired test."""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np
from scipy import stats


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    lo, hi = c - h, c + h
    # exact endpoints at k=0 / k=n; avoids 1e-18 floating-point residue in reports
    return (0.0 if k == 0 else max(0.0, lo), 1.0 if k == n else min(1.0, hi))


def bootstrap_ci(
    values: Sequence[float], *, n_boot: int = 2000, seed: int = 0, alpha: float = 0.05
) -> tuple[float, float, float]:
    """Mean and percentile bootstrap interval."""
    x = np.asarray(values, dtype=float)
    if x.size == 0:
        return (float("nan"),) * 3
    if x.size == 1:
        return (float(x[0]), float(x[0]), float(x[0]))
    rng = np.random.default_rng(seed)
    means = rng.choice(x, size=(n_boot, x.size), replace=True).mean(axis=1)
    lo, hi = np.quantile(means, [alpha / 2, 1 - alpha / 2])
    return (float(x.mean()), float(lo), float(hi))


def cluster_bootstrap_ci(
    values: Sequence[float],
    clusters: Sequence[object],
    *,
    n_boot: int = 2000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Resample whole clusters (e.g. targets), since trials on one target are not independent."""
    x = np.asarray(values, dtype=float)
    if x.size == 0:
        return (float("nan"),) * 3
    keys = sorted({str(c) for c in clusters})
    idx = {k: np.array([i for i, c in enumerate(clusters) if str(c) == k]) for k in keys}
    rng = np.random.default_rng(seed)
    means = np.empty(n_boot)
    for b in range(n_boot):
        pick = rng.integers(0, len(keys), size=len(keys))
        sel = np.concatenate([idx[keys[j]] for j in pick])
        means[b] = x[sel].mean()
    lo, hi = np.quantile(means, [alpha / 2, 1 - alpha / 2])
    return (float(x.mean()), float(lo), float(hi))


def paired_exact(a: Sequence[bool], b: Sequence[bool]) -> dict[str, float]:
    """Exact two-sided McNemar test on matched outcomes (a = reference, b = treatment)."""
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    only_a = sum(1 for x, y in zip(a, b, strict=True) if x and not y)
    only_b = sum(1 for x, y in zip(a, b, strict=True) if y and not x)
    n = only_a + only_b
    p = 1.0 if n == 0 else float(stats.binomtest(min(only_a, only_b), n, 0.5).pvalue)
    diff = (sum(b) - sum(a)) / len(a) if a else float("nan")
    return {
        "n": float(len(a)),
        "only_ref": float(only_a),
        "only_treat": float(only_b),
        "p": p,
        "risk_diff": diff,
    }
