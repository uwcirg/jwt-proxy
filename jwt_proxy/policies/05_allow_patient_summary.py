"""FHIR response transformer: Allow Patient $summary and $everything operations with relaxed filtering.

This transformer handles the FHIR Patient $summary and $everything operations
(/fhir/Patient/{id}/$summary and /fhir/Patient/{id}/$everything) which return Bundles
containing related resources. For these operations, the filtering rules are relaxed to allow:
- Composition resources (always allowed)
- Resources with matching Keycloak security labels
- Resources explicitly marked as empty/absent with the absent-unknown-uv-ips coding

This has higher precedence than the standard security filtering (51_fhir_response_security.py).
"""
import copy
import re
SECURITY_SYSTEM = "http://keycloak.cirg.uw.edu/fhir/security-labels"
ABSENT_UNKNOWN_SYSTEM = "http://hl7.org/fhir/uv/ips/CodeSystem/absent-unknown-uv-ips"


def _safe_log(level, message, *args):
    """Safely log a message, only if Flask app context is available."""
    try:
        from flask import has_app_context, current_app
        if has_app_context():
            getattr(current_app.logger, level)(message, *args)
    except Exception:
        # Ignore logging errors (e.g., no app context in tests)
        pass


def _is_patient_summary_request(request):
    """Check if the request is for a Patient $summary or $everything operation."""
    path = request.path or ""
    # Match pattern: /fhir/Patient/{id}/$summary or /fhir/Patient/{id}/$everything
    pattern = r"^/fhir/Patient/[^/]+/\$(summary|everything)$"
    return bool(re.match(pattern, path))


def _has_user_security_label(resource, keycloak_user_id):
    """Check if a FHIR resource has a Keycloak security label matching the user's ID."""
    if not isinstance(resource, dict):
        return False
    
    meta = resource.get("meta", {})
    if not isinstance(meta, dict):
        return False
    
    security = meta.get("security", [])
    if not isinstance(security, list):
        return False
    
    for sec in security:
        if not isinstance(sec, dict):
            continue
        if sec.get("system") == SECURITY_SYSTEM and sec.get("code") == keycloak_user_id:
            return True
    
    return False


def _is_composition_resource(resource):
    """Check if the resource is a Composition."""
    if not isinstance(resource, dict):
        return False
    return resource.get("resourceType") == "Composition"


def _is_absent_unknown_resource(resource):
    """Check if the resource is explicitly marked as empty/absent with absent-unknown coding."""
    if not isinstance(resource, dict):
        return False
    
    # Check for code.coding with the absent-unknown system
    code = resource.get("code")
    if not isinstance(code, dict):
        return False
    
    coding = code.get("coding")
    if not isinstance(coding, list):
        return False
    
    for c in coding:
        if not isinstance(c, dict):
            continue
        if c.get("system") == ABSENT_UNKNOWN_SYSTEM:
            return True
    
    return False


def _is_resource_allowed_for_summary(resource, keycloak_user_id):
    """Check if a resource should be allowed in a Patient $summary response.
    
    Resources are allowed if they are:
    1. Composition resources (always allowed)
    2. Have matching Keycloak security label
    3. Explicitly marked as absent/unknown with the absent-unknown-uv-ips coding
    """
    if _is_composition_resource(resource):
        return True
    
    if _has_user_security_label(resource, keycloak_user_id):
        return True
    
    if _is_absent_unknown_resource(resource):
        return True
    
    return False


def transform_response(request, response_body, user_info=None):
    """Transform FHIR response bodies for Patient $summary and $everything operations.
    
    Only processes GET requests to /fhir/Patient/{id}/$summary or /fhir/Patient/{id}/$everything
    that return Bundles. Filters bundle entries to allow Composition resources, resources with
    matching security labels, and resources marked as absent/unknown.
    
    Returns modified response body, or None if not applicable.
    """
    # Only process GET requests
    if request.method != "GET":
        return None
    
    # Only process Patient $summary or $everything requests
    if not _is_patient_summary_request(request):
        return None
    
    # Only process Bundle responses
    if not isinstance(response_body, dict) or response_body.get("resourceType") != "Bundle":
        return None
    
    # Extract keycloak user ID from JWT claims
    if not user_info or not isinstance(user_info, dict):
        keycloak_user_id = None
        _safe_log("warning", "No user_info provided for Patient operation request - denying access")
    else:
        keycloak_user_id = user_info.get("sub")
    
    if not keycloak_user_id:
        # No user ID, return empty bundle
        modified = copy.deepcopy(response_body)
        modified["entry"] = []
        modified["total"] = 0
        _safe_log("info", "Denied access to Patient operation - no user ID")
        return modified
    
    # Filter bundle entries
    entries = response_body.get("entry", [])
    if not isinstance(entries, list):
        return None
    
    modified_bundle = copy.deepcopy(response_body)
    filtered_entries = []
    original_count = len(entries)
    
    for entry in entries:
        if not isinstance(entry, dict):
            # Keep non-dict entries (shouldn't happen, but be safe)
            filtered_entries.append(entry)
            continue
        
        resource = entry.get("resource")
        if _is_resource_allowed_for_summary(resource, keycloak_user_id):
            filtered_entries.append(entry)
    
    # Update bundle with filtered entries
    modified_bundle["entry"] = filtered_entries
    modified_bundle["total"] = len(filtered_entries)
    
    filtered_count = original_count - len(filtered_entries)
    if filtered_count > 0:
        _safe_log("info",
            "Filtered %d resource(s) from Patient operation bundle (user: %s, remaining: %d)",
            filtered_count,
            keycloak_user_id,
            len(filtered_entries)
        )
    
    return modified_bundle


def evaluate(request, user_info=None):
    """Policy evaluation - always allow, filtering happens in transform_response."""
    return None  # No decision, let other policies decide

