from pathlib import Path

import pytest

from logicpearl.ir.loaders import load_gate_ir
from logicpearl.observer import load_observer_spec, validate_gate_against_contract
from logicpearl.observer.models import FeatureContract, ObserverSpec


V3_ROOT = Path(__file__).resolve().parents[2]
VALID_OBSERVER_FIXTURE = V3_ROOT / "fixtures" / "observer" / "valid" / "auth-observer-v1.json"
INVALID_OBSERVER_FIXTURE = V3_ROOT / "fixtures" / "observer" / "invalid" / "unknown-raw-field.json"
VALID_GATE_FIXTURE = V3_ROOT / "fixtures" / "ir" / "valid" / "auth-demo-v1.json"


def test_load_valid_observer_fixture() -> None:
    observer = load_observer_spec(VALID_OBSERVER_FIXTURE)

    assert isinstance(observer, ObserverSpec)
    assert observer.observer_id == "auth_observer_v1"
    assert len(observer.mappings) == 10


def test_materialize_feature_contract() -> None:
    observer = load_observer_spec(VALID_OBSERVER_FIXTURE)
    contract = observer.to_feature_contract()

    assert isinstance(contract, FeatureContract)
    assert contract.contract_id == "auth_feature_contract_v1"
    assert [feature.id for feature in contract.features][-1] == "is_elevated_role"


def test_validate_gate_against_feature_contract() -> None:
    observer = load_observer_spec(VALID_OBSERVER_FIXTURE)
    gate = load_gate_ir(VALID_GATE_FIXTURE)

    validate_gate_against_contract(gate, observer.to_feature_contract())


def test_reject_unknown_raw_field() -> None:
    with pytest.raises(ValueError, match="unknown raw field"):
        load_observer_spec(INVALID_OBSERVER_FIXTURE)
