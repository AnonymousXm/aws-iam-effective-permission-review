import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'enumeration'))
from effective_permissions import evaluate


def test_business_path_remains_allowed():
    assert evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'allow','trust':'allow'}).allowed


def test_attack_path_denied_after_remediation():
    # Local abstract representation of the remediated secret-runtime edge.
    assert not evaluate({'identity_policy':'deny','boundary':'allow','resource_policy':'allow','trust':'allow'}).allowed
