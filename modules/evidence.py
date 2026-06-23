import re
from collections import Counter
from typing import Iterable, Optional


def new_regex_evidence(
    baseline: str,
    candidate: str,
    patterns: Iterable[str],
    flags: int = re.IGNORECASE,
) -> Optional[str]:
    """Return the first regex match introduced by the candidate response."""
    baseline_counts = _match_counts(baseline or "", patterns, flags)
    seen = Counter()

    for pattern in patterns:
        for match in re.finditer(pattern, candidate or "", flags):
            value = match.group(0)
            key = _normalise(value)
            seen[key] += 1
            if seen[key] > baseline_counts[key]:
                return value
    return None


def context_excerpt(body: str, evidence: str, window: int = 120) -> str:
    if not body or not evidence:
        return ""
    index = body.lower().find(evidence.lower())
    if index < 0:
        return evidence[: window * 2]
    return body[max(0, index - window): index + len(evidence) + window].strip()


def _match_counts(body: str, patterns: Iterable[str], flags: int) -> Counter:
    counts = Counter()
    for pattern in patterns:
        for match in re.finditer(pattern, body, flags):
            counts[_normalise(match.group(0))] += 1
    return counts


def _normalise(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()
