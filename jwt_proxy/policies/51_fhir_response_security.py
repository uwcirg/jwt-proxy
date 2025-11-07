"""FHIR response transformer: Filter FHIR resources based on security labels.

This transformer filters GET/search responses to only include resources where
the user's Keycloak user ID is present in meta.security.
"""
SECURITY_SYSTEM = "http://keycloak.cirg.uw.edu/fhir/security-labels"


def _has_user_security_label(resource, keycloak_user_id):
    """Check if a FHIR resource has the user's security label."""
    if not isinstance(resource, dict):
        return False
    
    meta = resource.get("meta", {})
    if not isinstance(meta, dict):
        return False
    
    security = meta.get("security", [])
    if not isinstance(security, list):
        return False
    
    # Check if any security label matches the user's ID
    for sec in security:
        if not isinstance(sec, dict):
            continue
        if sec.get("system") == SECURITY_SYSTEM and sec.get("code") == keycloak_user_id:
            return True
    
    return False


def _filter_bundle_entries(bundle, keycloak_user_id):
    """Filter bundle entries to only include resources with user's security label."""
    if not isinstance(bundle, dict):
        return bundle
    
    entries = bundle.get("entry", [])
    if not isinstance(entries, list):
        return bundle
    
    # Filter entries
    filtered_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        
        resource = entry.get("resource")
        if _has_user_security_label(resource, keycloak_user_id):
            filtered_entries.append(entry)
    
    # Create modified bundle
    modified_bundle = bundle.copy()
    modified_bundle["entry"] = filtered_entries
    
    # Update total if present
    if "total" in modified_bundle:
        modified_bundle["total"] = len(filtered_entries)
    
    return modified_bundle


def transform_response(request, response_body, user_info=None):
    """Transform FHIR response bodies to filter resources by security labels.
    
    Only processes GET requests returning FHIR resources or bundles.
    Returns modified response body, or original body if not a FHIR resource,
    or None if a FHIR resource was filtered out.
    """
    # Only process GET requests
    if request.method != "GET":
        # Not a GET request, return None to indicate no modification needed
        return None
    
    # Extract keycloak user ID from JWT claims
    if not user_info or not isinstance(user_info, dict):
        # If no user info, deny access (filter everything)
        keycloak_user_id = None
    else:
        keycloak_user_id = user_info.get("sub")
    
    if not keycloak_user_id:
        # No user ID, filter all resources
        if isinstance(response_body, dict) and response_body.get("resourceType") == "Bundle":
            # Return empty bundle
            modified = response_body.copy()
            modified["entry"] = []
            if "total" in modified:
                modified["total"] = 0
            return modified
        elif _is_fhir_resource(response_body):
            # Single FHIR resource without user ID - filter it out
            return None
        # Not a FHIR resource, return None to indicate no modification
        return None
    
    # Check if this is a FHIR Bundle (search result)
    if isinstance(response_body, dict) and response_body.get("resourceType") == "Bundle":
        filtered_bundle = _filter_bundle_entries(response_body, keycloak_user_id)
        return filtered_bundle  # Always return the bundle (even if empty)
    
    # Check if this is a single FHIR resource
    if _is_fhir_resource(response_body):
        if _has_user_security_label(response_body, keycloak_user_id):
            # Resource has user's security label - allow it
            return response_body
        else:
            # Resource doesn't have user's security label - filter it out
            return None
    
    # Not a FHIR resource, return None to indicate no modification needed
    return None


def _is_fhir_resource(body):
    """Check if the response body is a FHIR resource."""
    if not isinstance(body, dict):
        return False
    # FHIR resources have a 'resourceType' field
    return "resourceType" in body


def evaluate(request, user_info=None):
    """Policy evaluation - always allow, filtering happens in transform_response."""
    return None  # No decision, let other policies decide

