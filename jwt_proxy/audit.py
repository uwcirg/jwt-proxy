"""Audit

functions to simplify adding context and extra data to log messages destined for audit logs
"""
from flask import current_app, has_app_context
import logging
from urllib.parse import urlparse

from jwt_proxy.logserverhandler import LogServerHandler

EVENT_LOG_NAME = "jwt_proxy_event_logger"
EVENT_VERSION = "1"


def audit_log_init(app):
    log_server_handler = LogServerHandler(
        jwt=app.config["LOGSERVER_TOKEN"], url=app.config["LOGSERVER_URL"]
    )
    event_logger = logging.getLogger(EVENT_LOG_NAME)
    event_logger.setLevel(logging.INFO)
    event_logger.addHandler(log_server_handler)


def audit_entry(message, level="info", extra=None):
    """Log entry, adding in session info such as active user"""
    try:
        logger = logging.getLogger(EVENT_LOG_NAME)
        log_at_level = getattr(logger, level.lower())
    except AttributeError:
        raise ValueError(f"audit_entry given bogus level: {level}")

    if extra is None:
        extra = {}

    log_at_level(message, extra=extra)


def deets_from_url(url, resource_type, id):
    """Given url, and best guess at resource_type and id, return best guess"""
    if resource_type and id:
        return resource_type, id

    # url: UPSTREAM_SERVER/fhir/ResourceType/<id or params>
    parsed = urlparse(url)
    if not parsed.path.startswith("/fhir"):
        audit_entry(f"Unexpected fhir path: {url} can't parse", level="error")
    items = parsed.path.split('/')
    # /fhir base URL, no resourceType
    if len(items) < 3:
        return resource_type, id
    resource_type = resource_type or items[2]
    id = id or items[3] if len(items) > 3 else None
    return resource_type, id


def audit_HAPI_change(
    user_info, method, params=None, resource=None, resource_type=None, resource_id=None, url=None
):
    rt = resource_type or resource and resource.get("resourceType")
    id = resource_id or resource and resource.get("_id")
    rt, id = deets_from_url(url, rt, id)
    msg = f"{method} {rt}/{id}" if id else f"{method} {rt}"
    extra = {
        "event_version": EVENT_VERSION,
        "tags": [rt, method],
        "user": user_info}

    if rt == "Patient" and id:
        extra["subject"] = f"{rt}/{id}"
    elif resource:
        extra["resource"] = resource

    if params:
        extra["params"] = params
    # extra["url"] = url  # helpful in debugging
    audit_entry(message=msg, extra=extra)
