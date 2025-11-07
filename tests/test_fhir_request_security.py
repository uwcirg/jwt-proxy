import importlib
import json


class FakeRequest:
    def __init__(self, path: str, method: str = "GET", json_body=None):
        self.path = path
        self.method = method
        self.json = json_body


def test_adds_security_label_to_patient_resource():
    """Test that security label is added to a Patient resource on POST."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "name": [{"given": ["John"], "family": "Doe"}]
    }
    
    user_info = {
        "sub": "wahs-test-user-1",
        "email": "test@example.com"
    }
    
    req = FakeRequest(path="/Patient", method="POST", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    assert result is not None
    assert "meta" in result
    assert "security" in result["meta"]
    assert len(result["meta"]["security"]) == 1
    
    security_label = result["meta"]["security"][0]
    assert security_label["system"] == "http://keycloak.cirg.uw.edu/fhir/security-labels"
    assert security_label["code"] == "wahs-test-user-1"
    assert security_label["display"] == "Access restricted to wahs-test-user-1"


def test_adds_security_label_to_observation_resource():
    """Test that security label is added to an Observation resource on PUT."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Observation",
        "id": "obs-123",
        "status": "final",
        "code": {"text": "Test"}
    }
    
    user_info = {
        "sub": "wahs-test-user-2",
        "email": "test2@example.com"
    }
    
    req = FakeRequest(path="/Observation/obs-123", method="PUT", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    assert result is not None
    assert result["meta"]["security"][0]["code"] == "wahs-test-user-2"


def test_removes_existing_security_labels_same_system():
    """Test that existing security labels with the same system are removed."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": "http://keycloak.cirg.uw.edu/fhir/security-labels",
                    "code": "old-user",
                    "display": "Old user"
                },
                {
                    "system": "http://other.system.com",
                    "code": "other-label",
                    "display": "Other label"
                }
            ]
        }
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient", method="POST", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    assert result is not None
    # Should have 2 security labels: the new one and the one from other system
    assert len(result["meta"]["security"]) == 2
    
    # Check that old security label with same system is gone
    security_systems = [s["system"] for s in result["meta"]["security"]]
    assert "http://keycloak.cirg.uw.edu/fhir/security-labels" in security_systems
    assert security_systems.count("http://keycloak.cirg.uw.edu/fhir/security-labels") == 1  # Only the new one
    
    # Check that other system's label is preserved
    assert "http://other.system.com" in security_systems
    
    # Check new label is correct
    new_label = next(s for s in result["meta"]["security"] if s["system"] == "http://keycloak.cirg.uw.edu/fhir/security-labels")
    assert new_label["code"] == "wahs-test-user-1"


def test_initializes_meta_if_missing():
    """Test that meta object is created if it doesn't exist."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123"
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient", method="POST", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    assert result is not None
    assert "meta" in result
    assert "security" in result["meta"]
    assert len(result["meta"]["security"]) == 1


def test_does_not_modify_get_request():
    """Test that GET requests are not modified."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123"
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient/123", method="GET", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    # Should return None (no modification)
    assert result is None


def test_does_not_modify_non_fhir_resource():
    """Test that non-FHIR resources are not modified."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    non_fhir_resource = {
        "data": "some data",
        "not_resourceType": "something"
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/api/data", method="POST", json_body=non_fhir_resource)
    result = module.transform_request(req, non_fhir_resource.copy(), user_info)
    
    # Should return None (no modification)
    assert result is None


def test_requires_user_info():
    """Test that transformer returns None if user_info is missing."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123"
    }
    
    req = FakeRequest(path="/Patient", method="POST", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info=None)
    
    # Should return None (no modification without user info)
    assert result is None


def test_requires_sub_claim():
    """Test that transformer returns None if sub claim is missing."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123"
    }
    
    user_info = {
        "email": "test@example.com"
        # Missing "sub"
    }
    
    req = FakeRequest(path="/Patient", method="POST", json_body=fhir_resource)
    result = module.transform_request(req, fhir_resource.copy(), user_info)
    
    # Should return None (no modification without sub claim)
    assert result is None


def test_policy_evaluation_returns_none():
    """Test that policy evaluation always returns None (no decision)."""
    module = importlib.import_module("jwt_proxy.policies.50_fhir_request_security")
    
    req = FakeRequest(path="/Patient", method="POST")
    result = module.evaluate(req, user_info={"sub": "test-user"})
    
    # Should return None (no decision, let other policies decide)
    assert result is None

