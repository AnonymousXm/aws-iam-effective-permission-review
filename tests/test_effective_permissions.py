import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'enumeration'))
from effective_permissions import evaluate


def test_identity_allow():
    assert evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'allow','trust':'allow'}) .allowed


def test_identity_deny():
    assert not evaluate({'identity_policy':'deny','boundary':'allow','resource_policy':'allow','trust':'allow'}).allowed


def test_boundary_deny():
    assert not evaluate({'identity_policy':'allow','boundary':'deny','resource_policy':'allow','trust':'allow'}).allowed


def test_resource_deny():
    assert not evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'deny','trust':'allow'}).allowed


def test_trust_deny():
    assert not evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'allow','trust':'deny'}).allowed


def test_condition_mismatch():
    assert not evaluate({'identity_policy':'allow','condition':False}).allowed


def test_passrole_lambda():
    assert evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'allow','trust':'allow','passrole':True,'passed_to_service':'lambda.amazonaws.com'}).allowed


def test_passrole_wrong_service():
    assert not evaluate({'identity_policy':'allow','boundary':'allow','resource_policy':'allow','trust':'allow','passrole':True,'passed_to_service':'ec2.amazonaws.com'}).allowed
