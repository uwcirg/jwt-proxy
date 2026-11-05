import importlib


class FakeRequest:
    def __init__(self, path: str, method: str = "GET", args: dict = None):
        self.path = path
        self.method = method
        self.args = args or {}


def _is_allow(result):
    if isinstance(result, tuple):
        decision = result[0]
    else:
        decision = result
    return decision is True or (isinstance(decision, str) and decision.lower() == "allow")


def test_allows_get_paging_link_on_fhir_base():
    """Test that GET /fhir?_getpages=... (searchset paging link) is allowed."""
    req = FakeRequest(
        path="/fhir",
        method="GET",
        args={"_getpages": "18f545e2-4c6f-45ea-8940-837fd84a428d", "_getpagesoffset": "20"},
    )
    module = importlib.import_module("jwt_proxy.policies.16_allow_fhir_paging")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_no_decision_for_get_fhir_base_without_getpages():
    """Test that a plain GET /fhir returns no decision."""
    req = FakeRequest(path="/fhir", method="GET", args={"_count": "20"})
    module = importlib.import_module("jwt_proxy.policies.16_allow_fhir_paging")
    result = module.evaluate(req, user_info={})
    assert result is None


def test_no_decision_for_non_get_with_getpages():
    """Test that non-GET requests to /fhir return no decision even with _getpages."""
    req = FakeRequest(path="/fhir", method="PUT", args={"_getpages": "abc"})
    module = importlib.import_module("jwt_proxy.policies.16_allow_fhir_paging")
    result = module.evaluate(req, user_info={})
    assert result is None


def test_no_decision_for_other_paths_with_getpages():
    """Test that _getpages on a path other than /fhir returns no decision."""
    req = FakeRequest(path="/other", method="GET", args={"_getpages": "abc"})
    module = importlib.import_module("jwt_proxy.policies.16_allow_fhir_paging")
    result = module.evaluate(req, user_info={})
    assert result is None
