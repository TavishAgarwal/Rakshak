"""RAKSHAK — Dempster-Shafer evidence combination.

Implements the **real** Dempster-Shafer combination rule as a pure,
unit-testable function.  Output is always the triple:

    {belief, plausibility, uncertainty}

Never a single float (per rules.md).

Key concepts:
    - Each behavior scorer produces a *mass function* m(A) over the frame
      of discernment Θ = {Malicious, Benign}.
    - m({Malicious}) = scorer.score * reliability
    - m({Benign})    = (1 - scorer.score) * reliability
    - m(Θ)           = 1 - reliability
    - Dempster's rule combines multiple mass functions with conflict
      normalization:  m₁₂(A) = Σ_{B∩C=A} m₁(B)·m₂(C) / (1 - K)
      where K = Σ_{B∩C=∅} m₁(B)·m₂(C)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def to_bpa(raw_score: float, source_reliability: float) -> dict[str, float]:
    """Convert a 0-1 raw score and reliability into a basic probability assignment (BPA).

    Frame Θ = {Malicious, Benign}.

    Assigns:
        m({Malicious}) = raw_score * source_reliability
        m({Benign})    = (1 - raw_score) * source_reliability
        m(Θ)           = 1 - source_reliability
    """
    raw_score = max(0.0, min(1.0, raw_score))
    source_reliability = max(0.0, min(1.0, source_reliability))
    
    return {
        "Malicious": raw_score * source_reliability,
        "Benign": (1.0 - raw_score) * source_reliability,
        "Uncertain": 1.0 - source_reliability, # This is m(Θ)
    }


def ds_combine(bpas: list[dict[str, float]]) -> dict[str, float]:
    """Combine N mass functions using Dempster's rule.

    Returns a combined BPA with {Malicious, Benign, Uncertain, conflict}
    where 'conflict' tracks the total conflict K before the final step.
    """
    if not bpas:
        return {"Malicious": 0.0, "Benign": 0.0, "Uncertain": 1.0, "conflict": 0.0}

    if len(bpas) == 1:
        result = dict(bpas[0])
        result["conflict"] = 0.0
        return result

    # Start with the first BPA
    combined = dict(bpas[0])
    total_conflict = 0.0

    for i in range(1, len(bpas)):
        m1 = combined
        m2 = bpas[i]

        m1_mal = m1.get("Malicious", 0.0)
        m1_ben = m1.get("Benign", 0.0)
        m1_unc = m1.get("Uncertain", 0.0)

        m2_mal = m2.get("Malicious", 0.0)
        m2_ben = m2.get("Benign", 0.0)
        m2_unc = m2.get("Uncertain", 0.0)

        # Conflict occurs when sets are disjoint: {Malicious} ∩ {Benign} = ∅
        k = (m1_mal * m2_ben) + (m1_ben * m2_mal)

        # To track the "total conflict" over sequence (for reporting/metrics)
        # Note: True Dempster rule normalizes out conflict at each step, 
        # so total_conflict here is just accumulated conceptually: K_total = 1 - (1-K_prev)*(1-k)
        total_conflict = 1.0 - (1.0 - total_conflict) * (1.0 - k)

        # Intersections
        # {Malicious} = {Mal}∩{Mal} + {Mal}∩Θ + Θ∩{Mal}
        mal_raw = (m1_mal * m2_mal) + (m1_mal * m2_unc) + (m1_unc * m2_mal)
        
        # {Benign} = {Ben}∩{Ben} + {Ben}∩Θ + Θ∩{Ben}
        ben_raw = (m1_ben * m2_ben) + (m1_ben * m2_unc) + (m1_unc * m2_ben)
        
        # Θ = Θ∩Θ
        unc_raw = (m1_unc * m2_unc)

        normalizer = 1.0 - k

        if normalizer <= 0:
            # Full conflict (K=1). Graceful handling to avoid divide-by-zero.
            combined = {
                "Malicious": 0.0,
                "Benign": 0.0,
                "Uncertain": 1.0,
            }
        else:
            combined = {
                "Malicious": mal_raw / normalizer,
                "Benign": ben_raw / normalizer,
                "Uncertain": unc_raw / normalizer,
            }

    combined["conflict"] = total_conflict
    return combined


def belief_plausibility(combined_bpa: dict[str, float]) -> dict[str, float]:
    """Calculate Belief, Plausibility, and Uncertainty for the Malicious hypothesis."""
    bel = combined_bpa.get("Malicious", 0.0)
    unc = combined_bpa.get("Uncertain", 0.0)
    pl = bel + unc

    return {
        "belief": bel,
        "plausibility": pl,
        "uncertainty": unc,
        "conflict": combined_bpa.get("conflict", 0.0)
    }


# ---------------------------------------------------------------------------
# Legacy API Support (for existing application code)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DSResult:
    """Dempster-Shafer fusion output."""

    belief: float          # Bel({malicious}) — lower bound on probability
    plausibility: float    # Pl({malicious}) — upper bound on probability
    uncertainty: float     # Pl - Bel — width of the epistemic gap
    conflict: float        # K — total inter-source conflict before normalization
    sources: list[dict[str, Any]]   # contributing mass functions


def fuse_scores(
    scores: list[tuple[str, float]],
    default_reliability: float = 0.8
) -> DSResult:
    """Fuse a list of (scorer_class, score) pairs using Dempster-Shafer.

    This function wraps the new BPA methods to support the existing `main.py` flow.
    """
    active_scores = [(name, val) for name, val in scores if val > 0.0]

    if not active_scores:
        return DSResult(
            belief=0.0,
            plausibility=1.0,
            uncertainty=1.0,
            conflict=0.0,
            sources=[],
        )

    sources: list[dict[str, Any]] = []
    bpas: list[dict[str, float]] = []
    
    for name, val in active_scores:
        # For legacy scorers, we use a default reliability (0.8) to map 
        # roughly to the previous hardcoded `remaining * 0.8` behavior
        bpa = to_bpa(val, source_reliability=default_reliability)
        bpas.append(bpa)
        sources.append({
            "scorer_class": name,
            "raw_score": round(val, 4),
            "mass_malicious": round(bpa["Malicious"], 4),
            "mass_benign": round(bpa["Benign"], 4),
            "mass_theta": round(bpa["Uncertain"], 4),
        })

    combined = ds_combine(bpas)
    metrics = belief_plausibility(combined)

    return DSResult(
        belief=round(metrics["belief"], 4),
        plausibility=round(metrics["plausibility"], 4),
        uncertainty=round(metrics["uncertainty"], 4),
        conflict=round(metrics["conflict"], 4),
        sources=sources,
    )
