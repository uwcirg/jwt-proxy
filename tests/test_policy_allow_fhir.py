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


def test_allows_fhir_patient():
    """Test that /fhir/Patient requests are allowed."""
    req = FakeRequest(path="/fhir/Patient")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_fhir_patient_with_id():
    """Test that /fhir/Patient/<id> requests are allowed."""
    req = FakeRequest(path="/fhir/Patient/123")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_fhir_patient_search():
    """Test that /fhir/Patient search requests are allowed."""
    req = FakeRequest(path="/fhir/Patient?identifier=http://keycloak.cirg.uw.edu|wahs-test-user-1")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_fhir_observation():
    """Test that /fhir/Observation requests are allowed."""
    req = FakeRequest(path="/fhir/Observation")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_fhir_any_resource():
    """Test that any /fhir/<resource> requests are allowed."""
    req = FakeRequest(path="/fhir/Encounter")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_allows_fhir_operations():
    """Test that /fhir/ operations are allowed."""
    req = FakeRequest(path="/fhir/Patient/123/$summary")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_no_decision_for_non_fhir_paths():
    """Test that non-FHIR paths return no decision."""
    req = FakeRequest(path="/Patient")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    # Policy should not decide for non-FHIR paths
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    assert decision is None


def test_no_decision_for_api_paths():
    """Test that /api paths return no decision."""
    req = FakeRequest(path="/api/data")
    module = importlib.import_module("jwt_proxy.policies.10_allow_fhir")
    result = module.evaluate(req, user_info={})
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    assert decision is None

