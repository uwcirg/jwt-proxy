def evaluate(request, user_info):
    """Always allow requests to /.well-known paths (any depth)."""
    path = request.path or ""
    if path.startswith("/.well-known") or "/.well-known/" in path:
        return "allow"
    return None


