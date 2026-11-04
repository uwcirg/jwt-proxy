"""Rewrite upstream server URLs in Bundle responses to the proxy's public URL.

HAPI builds Bundle.link[].url (self, next, previous, ...) and Bundle.entry[].fullUrl
from its own base address. Update the addresses so that clients that cannot reach
the upstream server (or that should not bypass the proxy) don't fail when following
these links.

Requires both UPSTREAM_SERVER and PUBLIC_URL to be configured, otherwise the
response is returned unchanged.

Intended to run after filtering transformers.
"""
import copy

from flask import current_app


def _prefix(key):
    value = current_app.config.get(key)
    return value.rstrip("/") if value else None


def _rewrite(url, upstream, public):
    if isinstance(url, str) and (
        url == upstream or url.startswith((upstream + "/", upstream + "?"))
    ):
        return public + url[len(upstream):]
    return url


def transform_response(request, response_body, user_info=None):
    """Rewrite Bundle link and fullUrl values from UPSTREAM_SERVER to PUBLIC_URL.

    Always returns the response body. Never filters, so it must never return None.
    """
    if not isinstance(response_body, dict) or response_body.get("resourceType") != "Bundle":
        return response_body

    upstream = _prefix("UPSTREAM_SERVER")
    public = _prefix("PUBLIC_URL")
    if not upstream or not public or upstream == public:
        return response_body

    body = copy.deepcopy(response_body)
    for link in body.get("link") or []:
        if isinstance(link, dict) and "url" in link:
            link["url"] = _rewrite(link["url"], upstream, public)
    for entry in body.get("entry") or []:
        if isinstance(entry, dict) and "fullUrl" in entry:
            entry["fullUrl"] = _rewrite(entry["fullUrl"], upstream, public)
    return body


def evaluate(request, user_info=None):
    """Policy evaluation - always allow, filtering happens in transform_response."""
    return None  # No decision, let other policies decide
