def evaluate(request, user_info):
    """Default deny policy - denies all requests that don't match earlier rules.
    
    This policy should be loaded last (via filename ordering) to act as a catch-all
    default deny for any request not explicitly allowed by previous policies.
    """
    return ("deny", "Request denied by default policy - no matching rule found")


