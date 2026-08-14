# AWS IAM Effective-Permission Evaluator

A local security-engineering project for evaluating IAM permission combinations,
testing deny precedence, trust conditions, PassRole restrictions, and
least-privilege remediation patterns.

## Components

- `enumeration/effective_permissions.py` — effective-permission evaluator
- `enumeration/run_public_tests.py` — local fixture runner
- `remediation/patches.tf` — least-privilege Terraform remediation pattern
- `tests/` — automated Python tests
- `cloud-assessment/terraform/` — Terraform reference structure

## Scope

This repository contains implementation and local-testing code only.
No credentials, private assessment identifiers, assignment markers,
AWS support evidence, or private assessment artifacts are included.

## Local validation

Run:

```bash
python3 enumeration/run_public_tests.py
python3 -m pytest -q tests
