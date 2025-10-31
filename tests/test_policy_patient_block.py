import importlib.util
import os


class FakeRequest:
    def __init__(self, path: str, method: str = "GET"):
        self.path = path
        self.method = method


def _load_module_from_path(path):
    spec = importlib.util.spec_from_file_location("policy_patient_block", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


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


def test_allows_patient_summary():
    # Get the project root directory (parent of tests/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.path.join(project_root, "examples", "policies", "01_patient_block.py")
    module = _load_module_from_path(policy_path)
    req = FakeRequest(path="/Patient/ABC123/$summary")
    result = module.evaluate(req, user_info={})
    assert _is_allow(result)


def test_denies_patient_collection():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.path.join(project_root, "examples", "policies", "01_patient_block.py")
    module = _load_module_from_path(policy_path)
    req = FakeRequest(path="/Patient")
    result = module.evaluate(req, user_info={})
    assert _is_deny(result)


def test_denies_patient_other_paths():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.path.join(project_root, "examples", "policies", "01_patient_block.py")
    module = _load_module_from_path(policy_path)
    req = FakeRequest(path="/Patient/ABC123")
    result = module.evaluate(req, user_info={})
    assert _is_deny(result)

