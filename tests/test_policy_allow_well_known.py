import importlib


class FakeRequest:
    def __init__(self, path: str, method: str = "GET"):
        self.path = path
        self.method = method


def _is_allow(result):
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    return decision is True or (isinstance(decision, str) and decision.lower() == "allow")


def _is_deny(result):
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    return decision is False or (isinstance(decision, str) and decision.lower() == "deny")


def test_allows_direct_well_known_root():
    req = FakeRequest(path="/.well-known/openid-configuration")
    module = importlib.import_module("jwt_proxy.policies.00_allow_well_known")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_nested_well_known_paths():
    req = FakeRequest(path="/fhir/.well-known/smart-configuration")
    module = importlib.import_module("jwt_proxy.policies.00_allow_well_known")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_no_decision_for_non_well_known():
    req = FakeRequest(path="/Patient/123")
    module = importlib.import_module("jwt_proxy.policies.00_allow_well_known")
    result = module.evaluate(req, user_info={})
    # Policy should not decide for non well-known paths
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    assert decision is None


