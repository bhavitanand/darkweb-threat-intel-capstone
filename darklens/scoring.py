"""Explainable alert scoring.

score = 100 * (1 - prod(1 - s_i/100)) over all signals, so weak signals add up and one strong
signal dominates. The same idea as noisy-OR in probabilistic models. Every signal is kept on the
alert so an analyst can see exactly why it scored what it did.
"""
from __future__ import annotations

from .models import Signal

SEVERITY = [(85, "critical"), (65, "high"), (40, "medium"), (0, "low")]


def noisy_or(scores: list[int]) -> int:
    p = 1.0
    for s in scores:
        p *= 1 - max(0, min(100, s)) / 100
    return round(100 * (1 - p))


def severity(score: int) -> str:
    for floor, label in SEVERITY:
        if score >= floor:
            return label
    return "low"


def combine(signals: list[Signal]) -> tuple[int, str]:
    score = noisy_or([s.score for s in signals])
    return score, severity(score)
