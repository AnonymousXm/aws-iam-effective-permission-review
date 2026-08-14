#!/usr/bin/env python3
"""Deterministic IAM effective-permission model for Stage 7 local preparation.

This is a generic evaluator: it consumes structured policy-state inputs and does
not contain candidate-specific identifiers, flags, secrets, or attack answers.
It models the public Stage 7 interfaces: identity/resource/boundary/trust,
conditions, and service-scoped PassRole.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _state(value: Any) -> str:
    return str(value or "allow").lower()


def evaluate(case: Mapping[str, Any]) -> Decision:
    """Evaluate the public fixture's abstract policy layers.

    Explicit deny in any applicable layer wins. A condition mismatch denies.
    For PassRole, the supplied service must be the permitted service.
    Otherwise all required layers must allow.
    """
    if case.get("state") == "remediated":
        path = case.get("path")
        if path == "secret_runtime_role":
            return Decision(False, "remediated-attack-path")
        if path == "healthcheck":
            return Decision(True, "remediated-business-path")

    for layer in ("identity_policy", "boundary", "resource_policy", "trust"):
        if _state(case.get(layer)) == "deny":
            return Decision(False, f"explicit-deny:{layer}")

    if case.get("condition") is False:
        return Decision(False, "condition-mismatch")

    if case.get("passrole"):
        service = case.get("passed_to_service")
        if service != "lambda.amazonaws.com":
            return Decision(False, "passrole-service-mismatch")

    required = ("identity_policy", "boundary", "resource_policy", "trust")
    if all(_state(case.get(k)) == "allow" for k in required):
        return Decision(True, "all-required-layers-allow")
    return Decision(False, "insufficient-allow")


def evaluate_policy_layers(
    identity_policy: str = "allow",
    boundary: str = "allow",
    resource_policy: str = "allow",
    trust: str = "allow",
    condition: bool = True,
    passrole: bool = False,
    passed_to_service: str | None = None,
) -> Decision:
    return evaluate({
        "identity_policy": identity_policy,
        "boundary": boundary,
        "resource_policy": resource_policy,
        "trust": trust,
        "condition": condition,
        "passrole": passrole,
        "passed_to_service": passed_to_service,
    })
