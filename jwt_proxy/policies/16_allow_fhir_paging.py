def evaluate(request, user_info):
    """Allow GET /fhir?_getpages=...: searchset paging continuation links.

    HAPI generates these links against the server base with no trailing path,
    so they do not match the /fhir/ prefix allowed by 10_allow_fhir.py.

    Access control and security labeling is handled by the FHIR security
    transformers (50_fhir_request_security.py and 51_fhir_response_security.py).
    """
    path = request.path or ""
    if (
        path == "/fhir"
        and request.method == "GET"
        and "_getpages" in (getattr(request, "args", None) or {})
    ):
        return "allow"
    return None
