"""RAKSHAK — Analysis of Competing Hypotheses (ACH) engine.

Implements a Bayesian ACH module that takes the 7 scorer scores and DS fusion
belief/plausibility for an entity and generates 3 competing hypotheses ranked
by posterior probability.

Hypotheses:
    - ExternalAttacker:  An external threat actor targeting the organisation.
    - InsiderThreat:     A malicious or compromised insider.
    - FalsePositive:     The alert is a false alarm / benign anomaly.

Each hypothesis has:
    - prior probability (P(H))
    - a likelihood function P(E|H) derived from which indicators are predicted
      to be elevated
    - a plain-language explanation generator
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Hypothesis definitions
# ---------------------------------------------------------------------------

# Which scorer classes each hypothesis predicts should be elevated.
# Values are tuples of (expected_min_score, weight) — the likelihood
# calculation uses these to score how well the evidence matches.
#
# ExternalAttacker: mostly IT / network / credential / dns indicators
# InsiderThreat:    mostly process / cloud_api / identity / ot_physics
# FalsePositive:    predicts everything low or benign

_HYPOTHESIS_PROFILES: dict[str, dict[str, tuple[float, float]]] = {
    "ExternalAttacker": {
        "identity":    (0.15, 1.0),
        "credential":  (0.20, 1.2),
        "process":     (0.10, 0.7),
        "network":     (0.25, 1.3),
        "dns":         (0.20, 1.3),
        "cloud_api":   (0.10, 0.6),
        "ot_physics":  (0.05, 0.4),
    },
    "InsiderThreat": {
        "identity":    (0.20, 1.1),
        "credential":  (0.10, 0.6),
        "process":     (0.20, 1.2),
        "network":     (0.10, 0.7),
        "dns":         (0.05, 0.3),
        "cloud_api":   (0.20, 1.2),
        "ot_physics":  (0.20, 1.1),
    },
    "FalsePositive": {
        "identity":    (0.0,  0.3),
        "credential":  (0.0,  0.2),
        "process":     (0.0,  0.3),
        "network":     (0.0,  0.2),
        "dns":         (0.0,  0.2),
        "cloud_api":   (0.0,  0.3),
        "ot_physics":  (0.0,  0.3),
    },
}

# Priors: P(ExternalAttacker) = 0.35, P(InsiderThreat) = 0.25, P(FalsePositive) = 0.40
_PRIORS: dict[str, float] = {
    "ExternalAttacker": 0.35,
    "InsiderThreat":    0.25,
    "FalsePositive":    0.40,
}


# ---------------------------------------------------------------------------
# Likelihood computation
# ---------------------------------------------------------------------------

def _likelihood(
    hypothesis: str,
    scorer_scores: dict[str, float],
) -> float:
    """Compute P(E | H) — the probability of the observed evidence given hypothesis H.

    For each scorer, we compare the observed score against the hypothesis's
    predicted threshold.  If the observed score exceeds the expected minimum,
    that contributes positively (weighted).  If it's below, it contributes
    negatively (reduced likelihood).

    Returns a value in (0, 1) with higher = more consistent with hypothesis.
    """
    profile = _HYPOTHESIS_PROFILES.get(hypothesis, {})
    if hypothesis == "FalsePositive":
        return max(0.0, 1.0 - min(max(scorer_scores.values(), default=0.0), 1.0) / 0.3)

    total_weight = 0.0
    weighted_score = 0.0

    for scorer_class, (expected_min, weight) in profile.items():
        observed = scorer_scores.get(scorer_class, 0.0)
        total_weight += weight
        weighted_score += weight * min(observed / expected_min, 1.0)

    if total_weight == 0.0:
        return 0.5  # uniform if no profile

    return weighted_score / total_weight


# ---------------------------------------------------------------------------
# Hypothesis result container
# ---------------------------------------------------------------------------

@dataclass
class HypothesisResult:
    """A single hypothesis with its posterior probability and explanation."""

    name: str
    posterior_probability: float
    explanation: str


@dataclass
class ACHResult:
    """Ranked hypotheses output from the ACH engine."""

    hypotheses: list[HypothesisResult] = field(default_factory=list)
    belief: float = 0.0
    plausibility: float = 0.0
    top_hypothesis: str = ""


# ---------------------------------------------------------------------------
# Plain-language explanation generator
# ---------------------------------------------------------------------------

def _explanation(
    hypothesis: str,
    scorer_scores: dict[str, float],
    posterior: float,
) -> str:
    """Generate a readable explanation for why this hypothesis ranks as it does."""
    profile = _HYPOTHESIS_PROFILES.get(hypothesis, {})
    elevated: list[str] = []
    depressed: list[str] = []

    for scorer_class, (expected_min, _weight) in profile.items():
        observed = scorer_scores.get(scorer_class, 0.0)
        if expected_min > 0.0 and observed >= expected_min * 0.8:
            elevated.append(scorer_class)
        elif expected_min == 0.0 and observed > 0.15:
            # FalsePositive expects low, but this scorer is elevated
            depressed.append(scorer_class)

    if hypothesis == "ExternalAttacker":
        base = (
            f"The evidence is most consistent with an external attacker "
            f"(P={posterior:.1%}). "
        )
        if elevated:
            base += f"Key IT attack-surface indicators are elevated: {', '.join(elevated)}. "
        else:
            base += "IT indicators are not strongly elevated, reducing confidence. "
        base += "This hypothesis is reinforced when network, credential, and DNS anomalies cluster together."
        return base

    if hypothesis == "InsiderThreat":
        base = (
            f"The evidence suggests an insider-threat scenario "
            f"(P={posterior:.1%}). "
        )
        if elevated:
            base += f"Notable indicators include: {', '.join(elevated)}. "
        else:
            base += "Privilege / process / OT-physics indicators are not prominently elevated. "
        base += "Insider threats often manifest through unusual process behaviour, cloud-API abuse, or OT-physics manipulation."
        return base

    if hypothesis == "FalsePositive":
        base = (
            f"The evidence suggests this is a false positive or benign anomaly "
            f"(P={posterior:.1%}). "
        )
        if depressed:
            base += (
                f"Although some indicators ({', '.join(depressed)}) are slightly elevated, "
                f"they are individually low and lack the concentrated pattern "
                f"of a real attack. "
            )
        else:
            base += "All indicator scores are low or within normal operational variance. "
        base += "No strong multi-indicator attack signature is present."
        return base

    return f"Hypothesis {hypothesis} has posterior probability P={posterior:.1%}."


# ---------------------------------------------------------------------------
# Main ACH engine
# ---------------------------------------------------------------------------

def analyze_hypotheses(
    scorer_scores: dict[str, float],
    belief: float = 0.0,
    plausibility: float = 0.0,
    priors: dict[str, float] | None = None,
) -> ACHResult:
    """Run the ACH engine: compute posterior probabilities for each hypothesis.

    Args:
        scorer_scores:  dict mapping scorer_class → score (0–1)
        belief:         DS belief for Malicious (0–1)
        plausibility:   DS plausibility for Malicious (0–1)
        priors:         optional override for prior probabilities

    Returns:
        ACHResult with ranked hypotheses.
    """
    if priors is None:
        priors = dict(_PRIORS)

    hypotheses = ["ExternalAttacker", "InsiderThreat", "FalsePositive"]

    # Compute likelihoods
    likelihoods: dict[str, float] = {}
    for h in hypotheses:
        likelihoods[h] = _likelihood(h, scorer_scores)

    # Compute marginal likelihood P(E) = Σ P(H_i) * P(E|H_i)
    marginal = sum(
        priors[h] * likelihoods[h]
        for h in hypotheses
    )
    if marginal == 0.0:
        marginal = 1e-12  # avoid division by zero

    # Compute posteriors P(H|E) = P(E|H) * P(H) / P(E)
    posteriors: dict[str, float] = {}
    for h in hypotheses:
        posteriors[h] = (likelihoods[h] * priors[h]) / marginal

    # Sort descending by posterior probability
    ranked = sorted(
        hypotheses,
        key=lambda h: posteriors[h],
        reverse=True,
    )
    rounded_posteriors = {h: round(posteriors[h], 4) for h in hypotheses}
    if ranked:
        rounded_posteriors[ranked[-1]] = round(
            1.0 - sum(rounded_posteriors[h] for h in ranked[:-1]),
            4,
        )

    # Build explanation for each
    results: list[HypothesisResult] = []
    for h in ranked:
        results.append(HypothesisResult(
            name=h,
            posterior_probability=rounded_posteriors[h],
            explanation=_explanation(h, scorer_scores, posteriors[h]),
        ))

    top_h = ranked[0] if ranked else ""

    return ACHResult(
        hypotheses=results,
        belief=round(belief, 4),
        plausibility=round(plausibility, 4),
        top_hypothesis=top_h,
    )
