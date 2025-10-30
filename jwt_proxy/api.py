from flask import Blueprint, abort, current_app, jsonify, request, json as flask_json
import jwt
import requests
import json
import os
import importlib.util
from types import ModuleType

from jwt_proxy.audit import audit_HAPI_change

blueprint = Blueprint('auth', __name__)
SUPPORTED_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS')


def proxy_request(req, upstream_url, user_info=None):
    """Forward request to given url"""
    # Evaluate request against policy modules (if configured)
    decision, message = evaluate_policies(req=req, user_info=user_info)
    if decision is False:
        abort(403, description=message or "Request denied by policy")

    response = requests.request(
        method=req.method,
        url=upstream_url,
        headers=req.headers,
        params=req.args,
        json=req.json,
        data=req.data,
    )
    try:
        result = response.json()
    except json.decoder.JSONDecodeError:
        return response.text

    # Capture all changes
    try:
        if req.method in ("POST", "PUT", "DELETE"):
            audit_HAPI_change(
                user_info=_extract_user_from_claims(user_info),
                method=req.method,
                params=req.args,
                url=upstream_url,
            )
    except Exception as e:
        from flask import current_app
        current_app.logger.exception(e)
    return result


def evaluate_policies(req, user_info=None):
    """Load and evaluate policies in filename order.

    A policy module should expose a callable named `evaluate` (preferred) or `rule` with signature:
        evaluate(request, user_info) -> one of:
            - True / "allow"               => allow request
            - False / "deny"               => deny request
            - None / anything else         => no decision, continue
        Optionally, it may return a tuple: (decision, message)

    Returns a tuple: (decision: bool | None, message: str | None)
    decision == True  => allowed
    decision == False => denied
    decision == None  => no policies made a decision
    """
    policies_dir = current_app.config.get("POLICIES_DIR")
    if not policies_dir:
        return None, None
    if not os.path.isdir(policies_dir):
        current_app.logger.warning("POLICIES_DIR '%s' not found or not a directory", policies_dir)
        return None, None

    policy_files = [
        os.path.join(policies_dir, name)
        for name in sorted(os.listdir(policies_dir))
        if name.endswith(".py") and not name.startswith("__")
    ]

    for file_path in policy_files:
        try:
            module = _load_module_from_path(file_path)
        except Exception as e:
            current_app.logger.exception("Failed to load policy module %s: %s", file_path, e)
            continue

        policy_callable = None
        if hasattr(module, "evaluate") and callable(getattr(module, "evaluate")):
            policy_callable = getattr(module, "evaluate")
        elif hasattr(module, "rule") and callable(getattr(module, "rule")):
            policy_callable = getattr(module, "rule")

        if not policy_callable:
            current_app.logger.warning("Policy module %s has no callable 'evaluate' or 'rule'", file_path)
            continue

        try:
            result = policy_callable(req, user_info)
        except Exception as e:
            current_app.logger.exception("Policy module %s raised exception: %s", file_path, e)
            # Treat exceptions as no-decision; continue to next policy
            continue

        decision = None
        message = None

        if isinstance(result, tuple) and len(result) >= 1:
            decision = result[0]
            message = result[1] if len(result) >= 2 else None
        else:
            decision = result

        if isinstance(decision, str):
            lowered = decision.lower()
            if lowered == "allow":
                decision = True
            elif lowered == "deny":
                decision = False
            else:
                decision = None

        if decision is True:
            return True, message
        if decision is False:
            return False, message

    return None, None


def _load_module_from_path(path):
    """Dynamically load a module from a filesystem path."""
    module_name = f"policy_{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader  # for mypy/static analyzers
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


def _extract_user_from_claims(user_info):
    """Extract a displayable user identifier from JWT claims for audit.

    Accepts either a dict of claims (preferred) or a pre-extracted string.
    """
    if isinstance(user_info, dict):
        return (
            user_info.get("email")
            or user_info.get("preferred_username")
            or user_info.get("sub")
        )
    return user_info


@blueprint.route("/", defaults={"relative_path": ""}, methods=SUPPORTED_METHODS)
@blueprint.route("/<path:relative_path>", methods=SUPPORTED_METHODS)
def validate_jwt(relative_path):
    """Validate JWT and pass to upstream server"""
    if f"/{relative_path}" in current_app.config["PATH_WHITELIST"]:
        response_content = proxy_request(
            req=request,
            upstream_url=f"{current_app.config['UPSTREAM_SERVER']}/{relative_path}",
        )
        return response_content

    token = request.headers.get("authorization", "").split("Bearer ")[-1]
    if not token:
        return jsonify(message="token missing"), 400

    jwks_client = jwt.PyJWKClient(current_app.config["JWKS_URL"])
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    try:
        decoded_token = jwt.decode(
            jwt=token,
            # TODO cache public key in redis
            key=signing_key.key,
            algorithms=("RS256"),
            audience=("account"),
        )
    except jwt.exceptions.ExpiredSignatureError:
        return jsonify(message="token expired"), 401

    response_content = proxy_request(
        req=request,
        upstream_url=f"{current_app.config['UPSTREAM_SERVER']}/{relative_path}",
        user_info=decoded_token,
    )
    return response_content


@blueprint.route("/fhir/.well-known/smart-configuration")
def smart_configuration():
    """Non-secret application settings"""

    results = {
        "authorization_endpoint": current_app.config.get("OIDC_AUTHORIZE_URL"),
        "token_endpoint": current_app.config.get("OIDC_TOKEN_URI"),
        "introspection_endpoint": current_app.config.get(
            "OIDC_TOKEN_INTROSPECTION_URI"
        ),
    }
    return jsonify(results)


@blueprint.route("/settings", defaults={"config_key": None})
@blueprint.route("/settings/<string:config_key>")
def config_settings(config_key):
    """Non-secret application settings"""

    # workaround no JSON representation for datetime.timedelta
    class CustomJSONEncoder(flask_json.JSONEncoder):
        def default(self, obj):
            return str(obj)

    current_app.json_encoder = CustomJSONEncoder

    # return selective keys - not all can be be viewed by users, e.g.secret key
    blacklist = ("SECRET", "KEY")

    if config_key:
        key = config_key.upper()
        for pattern in blacklist:
            if pattern in key:
                abort(400, f"Configuration key {key} not available")
        return jsonify({key: current_app.config.get(key)})

    results = {}
    for key in current_app.config:
        matches = any(pattern for pattern in blacklist if pattern in key)
        if matches:
            continue
        results[key] = current_app.config.get(key)

    return jsonify(results)
