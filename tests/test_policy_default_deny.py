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


def test_denies_arbitrary_path():
    """Default deny policy should deny any path that doesn't match earlier rules."""
    req = FakeRequest(path="/Patient/123")
    module = importlib.import_module("jwt_proxy.policies.99_default_deny")
    result = module.evaluate(req, user_info={})
    assert _is_deny(result)
    # Should include a message
    if isinstance(result, tuple):
        assert len(result) >= 2
        assert "denied" in result[1].lower() or "default" in result[1].lower()


def test_denies_api_path():
    """Default deny policy should deny API paths."""
    req = FakeRequest(path="/api/data")
    module = importlib.import_module("jwt_proxy.policies.99_default_deny")
    result = module.evaluate(req, user_info={})
    assert _is_deny(result)


def test_denies_root_path():
    """Default deny policy should deny root path."""
    req = FakeRequest(path="/")
    module = importlib.import_module("jwt_proxy.policies.99_default_deny")
    result = module.evaluate(req, user_info={})
    assert _is_deny(result)


def test_denies_with_different_methods():
    """Default deny policy should deny requests regardless of HTTP method."""
    module = importlib.import_module("jwt_proxy.policies.99_default_deny")
    
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        req = FakeRequest(path="/some/resource", method=method)
        result = module.evaluate(req, user_info={})
        assert _is_deny(result)

