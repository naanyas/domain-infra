"""
Risk-profile rules engine.

Pure-function evaluator: `evaluate_rules(rules, signals) -> RuleOutcome | None`.
No DB access — callers pre-build the `signals` dict from submission state.

Rule schema (validated on RiskProfile save in Phase 2.x — for now we trust admin input):

    {
      "id": "rule_abc",
      "name": "Block Tor + disposable email",
      "enabled": true,
      "priority": 10,         # lower runs first; optional, defaults to insertion order
      "when": <condition>,    # boolean tree — see _evaluate_condition
      "then": {
        "decision": "deny" | "approve" | "review",
        "reason_code": "TOR_PLUS_DISPOSABLE",  # customer taxonomy
        "summary": "Tor exit node with disposable email",
        "weight": 100         # optional — how strongly this rule's decision overrides
      }
    }

Condition tree grammar:
    * Leaf:  {"signal": "path.to.signal", "op": "eq" | "lt" | ..., "value": ...}
    * AND:   {"all": [<condition>, <condition>, ...]}
    * OR:    {"any": [<condition>, <condition>, ...]}
    * NOT:   {"not": <condition>}
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RuleOutcome:
    decision: str
    reason_code: str
    summary: str
    rule_id: str
    rule_name: str
    weight: int = 0
    extra: dict = field(default_factory=dict)


# ----------------------------------------------------------------------
# Signal lookup
# ----------------------------------------------------------------------


def _get_signal(signals: dict, path: str) -> Any:
    """Resolve a dotted path in the signals dict; missing keys return None."""
    if not path:
        return None
    cur: Any = signals
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


# ----------------------------------------------------------------------
# Operator application
# ----------------------------------------------------------------------


def _apply_op(op: str, actual: Any, expected: Any) -> bool:
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "lt":
        return actual is not None and expected is not None and actual < expected
    if op == "le":
        return actual is not None and expected is not None and actual <= expected
    if op == "gt":
        return actual is not None and expected is not None and actual > expected
    if op == "ge":
        return actual is not None and expected is not None and actual >= expected
    if op == "in":
        return actual in (expected or [])
    if op == "contains":
        if actual is None:
            return False
        return str(expected) in str(actual)
    if op == "exists":
        return actual not in (None, "", [], {})
    logger.warning("unknown rule operator %r", op)
    return False


# ----------------------------------------------------------------------
# Condition evaluation
# ----------------------------------------------------------------------


def _evaluate_condition(cond: dict | None, signals: dict) -> bool:
    if not cond:
        return False
    if "all" in cond:
        return all(_evaluate_condition(c, signals) for c in cond["all"])
    if "any" in cond:
        return any(_evaluate_condition(c, signals) for c in cond["any"])
    if "not" in cond:
        return not _evaluate_condition(cond["not"], signals)
    # Leaf
    path = cond.get("signal")
    op = cond.get("op", "eq")
    expected = cond.get("value")
    return _apply_op(op, _get_signal(signals, path), expected)


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------


def evaluate_rules(rules: list[dict] | None, signals: dict) -> RuleOutcome | None:
    """
    Evaluate rules in priority order (lower first). Returns the outcome of the
    first rule that matches, or None if no rule matched.
    """
    if not rules:
        return None
    ordered = sorted(
        enumerate(rules),
        key=lambda pair: (pair[1].get("priority", 1_000_000), pair[0]),
    )
    for _, rule in ordered:
        if not rule.get("enabled", True):
            continue
        try:
            if _evaluate_condition(rule.get("when") or {}, signals):
                then = rule.get("then") or {}
                return RuleOutcome(
                    decision=then.get("decision") or "review",
                    reason_code=then.get("reason_code") or "RULE_MATCH",
                    summary=then.get("summary") or rule.get("name") or "",
                    rule_id=str(rule.get("id") or ""),
                    rule_name=rule.get("name") or "",
                    weight=int(then.get("weight") or 0),
                    extra={k: v for k, v in then.items()
                           if k not in ("decision", "reason_code", "summary", "weight")},
                )
        except Exception:
            logger.exception("rule evaluation failed for rule %r", rule.get("id"))
            continue
    return None
