"""CERT-In style threat-intel fixtures and matching."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "threat_intel"
_ADVISORY_FILE = _DATA_DIR / "cert_in_advisories.json"
_SCENARIO_FILE = _DATA_DIR / "india_cni_scenarios.json"


def load_advisories() -> list[dict[str, Any]]:
    with open(_ADVISORY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_scenarios() -> list[dict[str, Any]]:
    with open(_SCENARIO_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", text.lower()) if len(token) > 2}


def match_advisories(
    node_id: str,
    graph_domain: str,
    node_data: dict[str, Any],
    scorer_scores: dict[str, float],
) -> list[dict[str, Any]]:
    """Match active entity evidence against CERT-In advisory fixtures."""
    matches: list[dict[str, Any]] = []
    active_scorers = {name for name, score in scorer_scores.items() if score >= 0.2}
    node_text = " ".join(
        str(node_data.get(k, "")) for k in ("label", "node_type", "security_zone", "protocol", "service", "process")
    ).lower()
    query_tokens = _tokens(f"{node_id} {graph_domain} {node_text} {' '.join(active_scorers)}")

    for advisory in load_advisories():
        indicators = set(advisory.get("scorer_indicators", []))
        indicator_hits = sorted(active_scorers & indicators)
        advisory_text = " ".join([
            advisory.get("title", ""),
            advisory.get("sector", ""),
            advisory.get("india_context", ""),
            " ".join(advisory.get("techniques", [])),
            " ".join(advisory.get("cves", [])),
            " ".join(advisory.get("scorer_indicators", [])),
        ])
        lexical_hits = sorted(query_tokens & _tokens(advisory_text))
        sector_hit = advisory.get("sector", "").lower() in node_text
        domain_hit = graph_domain in advisory.get("domains", [])
        if not indicator_hits and not sector_hit and not domain_hit and not lexical_hits:
            continue

        score = min(
            1.0,
            0.25 * len(indicator_hits)
            + 0.08 * len(lexical_hits)
            + (0.2 if sector_hit else 0.0)
            + (0.2 if domain_hit else 0.0),
        )
        if score < 0.2:
            continue

        matches.append({
            "advisory_id": advisory["id"],
            "title": advisory["title"],
            "sector": advisory["sector"],
            "published": advisory.get("published"),
            "techniques": advisory["techniques"],
            "cves": advisory["cves"],
            "matched_indicators": indicator_hits,
            "lexical_hits": lexical_hits,
            "match_score": round(score, 3),
            "recommended_mitigation": advisory["recommended_mitigation"],
            "india_context": advisory["india_context"],
            "source_refs": advisory.get("source_refs", []),
        })

    matches.sort(key=lambda item: item["match_score"], reverse=True)
    return matches
