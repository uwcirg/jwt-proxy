"""FHIR response transformer: Filter FHIR resources based on security labels.

This transformer enforces access control by filtering GET/search responses to only
include resources where the user's Keycloak user ID (sub claim) matches a Keycloak
security label in the resource's meta.security.

Access Control Rules:
- Individual resources: Only accessible if they have a Keycloak security label
  with a code matching the user's JWT subject claim. Returns 401 if not accessible.
- Bundle responses: Filters entries to only include resources with matching security
  labels. Updates bundle total to reflect filtered count.
- Resources without Keycloak security labels are always denied.
"""
import copy
SECURITY_SYSTEM = "http://keycloak.cirg.uw.edu/fhir/security-labels"


def _has_user_security_label(resource, keycloak_user_id):
    """Check if a FHIR resource has a Keycloak security label matching the user's ID.
    
    The resource must have a security label with:
    - system == SECURITY_SYSTEM (Keycloak security label system)
    - code == keycloak_user_id (matches user's JWT sub claim)
    
    Returns True only if the resource has a matching Keycloak security label.
    Resources without Keycloak security labels are not accessible.
    """
    if not isinstance(resource, dict):
        return False
    
    meta = resource.get("meta", {})
    if not isinstance(meta, dict):
        return False
    
    security = meta.get("security", [])
    if not isinstance(security, list):
        return False
    
    # Check if any security label matches the user's ID
    # Resource must have a Keycloak security label with matching code
    for sec in security:
        if not isinstance(sec, dict):
            continue
        if sec.get("system") == SECURITY_SYSTEM and sec.get("code") == keycloak_user_id:
            return True
    
    # No matching Keycloak security label found - resource is not accessible
    return False


def _filter_bundle_entries(bundle, keycloak_user_id):
    """Filter bundle entries to only include resources with user's Keycloak security label.
    
    Removes any entries where the resource doesn't have a matching Keycloak security label.
    Updates the bundle's total count to reflect the number of remaining resources.
    """
    from flask import current_app
    
    if not isinstance(bundle, dict):
        return bundle
    
    entries = bundle.get("entry", [])
    if not isinstance(entries, list):
        return bundle
    
    # Create a deep copy to avoid modifying the original
    modified_bundle = copy.deepcopy(bundle)
    
    # Filter entries - only keep those with matching Keycloak security labels
    filtered_entries = []
    original_count = len(entries)
    
    for entry in entries:
        if not isinstance(entry, dict):
            # Keep non-dict entries (shouldn't happen, but be safe)
            filtered_entries.append(entry)
            continue
        
        resource = entry.get("resource")
        if _has_user_security_label(resource, keycloak_user_id):
            filtered_entries.append(entry)
    
    # Update bundle with filtered entries
    modified_bundle["entry"] = filtered_entries
    
    # Always update total to reflect the number of remaining resources
    # This ensures the bundle accurately represents the filtered results
    modified_bundle["total"] = len(filtered_entries)
    
    filtered_count = original_count - len(filtered_entries)
    if filtered_count > 0:
        current_app.logger.info(
            "Filtered %d resource(s) from bundle (user: %s, remaining: %d)",
            filtered_count,
            keycloak_user_id,
            len(filtered_entries)
        )
    
    return modified_bundle


def transform_response(request, response_body, user_info=None):
    """Transform FHIR response bodies to enforce access control based on Keycloak security labels.
    
    Access Control:
    - Individual resources: Only accessible if they have a Keycloak security label
      matching the user's JWT subject claim. Returns None to signal 401 if denied.
    - Bundle responses: Filters entries to only include accessible resources and
      updates the total count accordingly.
    
    Only processes GET requests returning FHIR resources or bundles.
    Returns modified response body, or original body if not a FHIR resource,
    or None if a FHIR resource was filtered out (should result in 401 Unauthorized).
    """
    from flask import current_app
    
    # Only process GET requests
    if request.method != "GET":
        # Not a GET request, return None to indicate no modification needed
        return None
    
    # Extract keycloak user ID from JWT claims
    if not user_info or not isinstance(user_info, dict):
        # If no user info, deny access (filter everything)
        keycloak_user_id = None
        current_app.logger.warning("No user_info provided for GET request - denying access")
    else:
        keycloak_user_id = user_info.get("sub")
    
    if not keycloak_user_id:
        # No user ID, deny access to all resources
        if isinstance(response_body, dict) and response_body.get("resourceType") == "Bundle":
            # Return empty bundle with total = 0
            modified = copy.deepcopy(response_body)
            modified["entry"] = []
            modified["total"] = 0
            current_app.logger.info("Denied access to bundle - no user ID")
            return modified
        elif _is_fhir_resource(response_body):
            # Single FHIR resource without user ID - deny access (will result in 401)
            current_app.logger.info("Denied access to resource - no user ID")
            return None
        # Not a FHIR resource, return None to indicate no modification
        return None
    
    # Check if this is a FHIR Bundle (search result)
    if isinstance(response_body, dict) and response_body.get("resourceType") == "Bundle":
        filtered_bundle = _filter_bundle_entries(response_body, keycloak_user_id)
        return filtered_bundle  # Always return the bundle (even if empty)
    
    # Check if this is a single FHIR resource (individual resource by ID)
    if _is_fhir_resource(response_body):
        resource_type = response_body.get("resourceType", "Unknown")
        resource_id = response_body.get("id", "unknown")
        
        if _has_user_security_label(response_body, keycloak_user_id):
            # Resource has matching Keycloak security label - allow access
            current_app.logger.debug(
                "Allowed access to %s/%s (user: %s)",
                resource_type,
                resource_id,
                keycloak_user_id
            )
            return response_body
        else:
            # Resource doesn't have matching Keycloak security label - deny access
            # This will result in a 401 Unauthorized response
            current_app.logger.info(
                "Denied access to %s/%s - no matching Keycloak security label (user: %s)",
                resource_type,
                resource_id,
                keycloak_user_id
            )
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

