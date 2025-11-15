import re


def evaluate(request, user_info):
    """Block all /Patient requests, except allow /Patient/<ID>/$summary.

    Returns one of:
      - ("allow" | True) to allow
      - ("deny" | False, optional message) to deny
      - None for no decision
    """
    path = request.path or ""

    # Allow: /Patient/<ID>/$summary
    if re.fullmatch(r"/Patient/[^/]+/\$summary", path):
        return "allow"

    # Deny: anything else under /Patient (including collection and other ops)
    if path == "/Patient" or path.startswith("/Patient/"):
        return ("deny", "Access to Patient resources is restricted by policy")

    # No decision for other resources
    return None


