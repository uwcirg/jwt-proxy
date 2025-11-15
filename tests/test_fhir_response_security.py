import importlib


class FakeRequest:
    def __init__(self, path: str, method: str = "GET"):
        self.path = path
        self.method = method


SECURITY_SYSTEM = "http://keycloak.cirg.uw.edu/fhir/security-labels"


def test_allows_single_resource_with_user_security_label():
    """Test that a single FHIR resource with user's security label is allowed."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-test-user-1",
                    "display": "Access restricted to wahs-test-user-1"
                }
            ]
        }
    }
    
    user_info = {
        "sub": "wahs-test-user-1",
        "email": "test@example.com"
    }
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info)
    
    assert result is not None
    assert result == fhir_resource


def test_filters_single_resource_without_user_security_label():
    """Test that a single FHIR resource without user's security label is filtered."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-other-user",
                    "display": "Access restricted to wahs-other-user"
                }
            ]
        }
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info)
    
    # Should return None (resource filtered)
    assert result is None


def test_filters_single_resource_without_security_labels():
    """Test that a single FHIR resource without security labels is filtered."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "name": [{"given": ["John"], "family": "Doe"}]
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info)
    
    # Should return None (resource filtered)
    assert result is None


def test_filters_bundle_entries_by_security_label():
    """Test that bundle entries are filtered to only include resources with user's security label."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    bundle = {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": 3,
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "1",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-test-user-1",
                                "display": "Access restricted to wahs-test-user-1"
                            }
                        ]
                    }
                }
            },
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "2",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-other-user",
                                "display": "Access restricted to wahs-other-user"
                            }
                        ]
                    }
                }
            },
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "3",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-test-user-1",
                                "display": "Access restricted to wahs-test-user-1"
                            }
                        ]
                    }
                }
            }
        ]
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient", method="GET")
    result = module.transform_response(req, bundle.copy(), user_info)
    
    assert result is not None
    assert result["resourceType"] == "Bundle"
    assert len(result["entry"]) == 2
    assert result["total"] == 2
    assert result["entry"][0]["resource"]["id"] == "1"
    assert result["entry"][1]["resource"]["id"] == "3"


def test_returns_empty_bundle_when_no_matching_resources():
    """Test that an empty bundle is returned when no resources match."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    bundle = {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": 2,
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "1",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-other-user",
                                "display": "Access restricted to wahs-other-user"
                            }
                        ]
                    }
                }
            },
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "2",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-another-user",
                                "display": "Access restricted to wahs-another-user"
                            }
                        ]
                    }
                }
            }
        ]
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient", method="GET")
    result = module.transform_response(req, bundle.copy(), user_info)
    
    assert result is not None
    assert result["resourceType"] == "Bundle"
    assert len(result["entry"]) == 0
    assert result["total"] == 0


def test_filters_bundle_when_user_info_missing():
    """Test that bundle is filtered (empty) when user_info is missing."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    bundle = {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": 1,
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "1",
                    "meta": {
                        "security": [
                            {
                                "system": SECURITY_SYSTEM,
                                "code": "wahs-test-user-1"
                            }
                        ]
                    }
                }
            }
        ]
    }
    
    req = FakeRequest(path="/Patient", method="GET")
    result = module.transform_response(req, bundle.copy(), user_info=None)
    
    assert result is not None
    assert result["resourceType"] == "Bundle"
    assert len(result["entry"]) == 0
    assert result["total"] == 0


def test_filters_single_resource_when_user_info_missing():
    """Test that single resource is filtered when user_info is missing."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-test-user-1"
                }
            ]
        }
    }
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info=None)
    
    # Should return None (resource filtered)
    assert result is None


def test_handles_bundle_without_entries():
    """Test that bundle without entries is handled correctly."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    bundle = {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": 0,
        "entry": []
    }
    
    user_info = {
        "sub": "wahs-test-user-1"
    }
    
    req = FakeRequest(path="/Patient", method="GET")
    result = module.transform_response(req, bundle.copy(), user_info)
    
    assert result is not None
    assert result["resourceType"] == "Bundle"
    assert len(result["entry"]) == 0


def test_handles_resource_with_multiple_security_labels():
    """Test that resource with multiple security labels (including user's) is allowed."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-other-user",
                    "display": "Other user"
                },
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-test-user-1",
                    "display": "Test user"
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
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info)
    
    # Should be allowed (has user's security label)
    assert result is not None
    assert result == fhir_resource


def test_handles_missing_sub_claim():
    """Test that resource is filtered when sub claim is missing."""
    module = importlib.import_module("jwt_proxy.policies.51_fhir_response_security")
    
    fhir_resource = {
        "resourceType": "Patient",
        "id": "123",
        "meta": {
            "security": [
                {
                    "system": SECURITY_SYSTEM,
                    "code": "wahs-test-user-1"
                }
            ]
        }
    }
    
    user_info = {
        "email": "test@example.com"
        # Missing "sub"
    }
    
    req = FakeRequest(path="/Patient/123", method="GET")
    result = module.transform_response(req, fhir_resource.copy(), user_info)
    
    # Should return None (resource filtered - no sub claim)
    assert result is None

