def evaluate(request, user_info):
    """Allow all requests to /fhir/ paths.
    
    This policy allows all FHIR API requests. Access control and security
    labeling is handled by the FHIR security transformers (50_fhir_request_security.py
    and 51_fhir_response_security.py).
    """
    path = request.path or ""
    if path.startswith("/fhir/"):
        return "allow"
    return None

