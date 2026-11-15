"""Tiny rules engine: loads rules.yaml and reports which rules fire, with evidence."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..models import Signal

RULES_PATH = Path(__file__).with_name("rules.yaml")


@dataclass
class Rule:
    id: str
    category: str
    name: str
    weight: int
    why: str
    patterns: list[re.Pattern]


def load_rules(path: Path = RULES_PATH) -> list[Rule]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = []
    for r in raw:
        rules.append(Rule(
            id=r["id"], category=r["category"], name=r["name"], weight=int(r["weight"]),
            why=r["why"], patterns=[re.compile(p, re.I | re.S) for p in r["patterns"]],
        ))
    return rules


_CACHE: list[Rule] | None = None


def rules() -> list[Rule]:
    global _CACHE
    if _CACHE is None:
        _CACHE = load_rules()
    return _CACHE


def run_rules(text: str) -> list[tuple[Rule, Signal]]:
    """Return (rule, signal) for every rule that fires on `text`."""
    hits = []
    for rule in rules():
        for pat in rule.patterns:
            m = pat.search(text)
            if m:
                ev = re.sub(r"\s+", " ", m.group(0))[:90]
                hits.append((rule, Signal(f"{rule.id} {rule.name}", rule.weight, rule.why, ev)))
                break
    return hits


def category_scores(hits: list[tuple[Rule, Signal]]) -> dict[str, float]:
    """Noisy-OR of rule weights per category, 0..1."""
    out: dict[str, float] = {}
    for rule, sig in hits:
        p = out.get(rule.category, 0.0)
        out[rule.category] = 1 - (1 - p) * (1 - sig.score / 100)
    return out
