"""FHIR request transformer: Add security labels to FHIR resources on create/update.

This transformer modifies POST/PUT request bodies to add meta.security annotations
with the user's Keycloak user ID from the JWT sub claim.
"""
SECURITY_SYSTEM = "http://keycloak.cirg.uw.edu/fhir/security-labels"


def _is_fhir_resource(body):
    """Check if the request body is a FHIR resource."""
    if not isinstance(body, dict):
        return False
    # FHIR resources have a 'resourceType' field
    return "resourceType" in body


def _add_security_label(resource, keycloak_user_id):
    """Add or update security label for a FHIR resource."""
    if not isinstance(resource, dict):
        return resource
    
    # Initialize meta if it doesn't exist
    if "meta" not in resource:
        resource["meta"] = {}
    
    if not isinstance(resource["meta"], dict):
        resource["meta"] = {}
    
    # Initialize security if it doesn't exist
    if "security" not in resource["meta"]:
        resource["meta"]["security"] = []
    
    if not isinstance(resource["meta"]["security"], list):
        resource["meta"]["security"] = []
    
    # Remove existing security labels with the same system
    resource["meta"]["security"] = [
        sec for sec in resource["meta"]["security"]
        if isinstance(sec, dict) and sec.get("system") != SECURITY_SYSTEM
    ]
    
    # Add new security label
    security_label = {
        "system": SECURITY_SYSTEM,
        "code": keycloak_user_id,
        "display": f"Access restricted to {keycloak_user_id}"
    }
    resource["meta"]["security"].append(security_label)
    
    return resource


def transform_request(request, request_body, user_info=None):
    """Transform FHIR request bodies to add security labels.
    
    Only processes POST/PUT requests with FHIR resources.
    Handles both single resources and transaction Bundles.
    Returns modified request body or None if no changes needed.
    """
    # Only process POST/PUT requests
    if request.method not in ("POST", "PUT"):
        return None
    
    # Extract keycloak user ID from JWT claims
    if not user_info or not isinstance(user_info, dict):
        return None
    
    keycloak_user_id = user_info.get("sub")
    if not keycloak_user_id:
        return None
    
    # Check if this is a FHIR resource
    if not _is_fhir_resource(request_body):
        return None
    
    # Check if this is a transaction Bundle
    if (isinstance(request_body, dict) and 
        request_body.get("resourceType") == "Bundle" and 
        request_body.get("type") == "transaction"):
        # Process transaction Bundle entries
        entries = request_body.get("entry", [])
        if isinstance(entries, list):
            # Create a copy of the bundle to avoid modifying the original
            modified_body = request_body.copy()
            modified_entries = []
            
            for entry in entries:
                if not isinstance(entry, dict):
                    modified_entries.append(entry)
                    continue
                
                # Create a copy of the entry
                modified_entry = entry.copy()
                
                # Get the request method from the entry
                entry_request = entry.get("request", {})
                if isinstance(entry_request, dict):
                    entry_method = entry_request.get("method", "").upper()
                    
                    # Only process POST/PUT entries (resources that would be saved)
                    if entry_method in ("POST", "PUT"):
                        resource = entry.get("resource")
                        if isinstance(resource, dict) and _is_fhir_resource(resource):
                            # Create a copy of the resource and add security label
                            resource_copy = resource.copy()
                            modified_resource = _add_security_label(resource_copy, keycloak_user_id)
                            modified_entry["resource"] = modified_resource
                
                modified_entries.append(modified_entry)
            
            modified_body["entry"] = modified_entries
            return modified_body
    
    # Single FHIR resource - create a copy and add security label
    modified_body = request_body.copy()
    modified_body = _add_security_label(modified_body, keycloak_user_id)
    return modified_body


def evaluate(request, user_info=None):
    """Policy evaluation - always allow, transformation happens in transform_request."""
    return None  # No decision, let other policies decide

