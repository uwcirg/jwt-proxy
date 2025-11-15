from flask import Blueprint, abort, current_app, jsonify, request, json as flask_json
import jwt
import requests
import json
from jwt_proxy.policy_engine import evaluate_policies, apply_request_transformers, apply_response_transformers

from jwt_proxy.audit import audit_HAPI_change

blueprint = Blueprint('auth', __name__)
SUPPORTED_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS')


def proxy_request(req, upstream_url, user_info=None):
    """Forward request to given url"""
    # Evaluate request against policy modules (if configured)
    decision, message = evaluate_policies(req=req, user_info=user_info)
    if decision is False:
        abort(403, description=message or "Request denied by policy")

    # Apply request transformers for POST/PUT requests
    # Flask's request.json now works for FHIR content types thanks to FHIRRequest class
    modified_request_body = None
    if req.method in ("POST", "PUT") and req.json:
        modified_request_body = apply_request_transformers(req, user_info)
    
    # Prepare request data
    request_json = modified_request_body if modified_request_body is not None else req.json
    request_data = req.data if not request_json else None

    response = requests.request(
        method=req.method,
        url=upstream_url,
        headers=req.headers,
        params=req.args,
        json=request_json,
        data=request_data,
    )
    
    # Parse response
    try:
        result = response.json()
    except json.decoder.JSONDecodeError:
        return response.text

    # Apply response transformers for GET requests
    if req.method == "GET" and isinstance(result, dict):
        original_result = result
        modified_result = apply_response_transformers(req, result, user_info)
        if modified_result is not None:
            # Transformer returned modified result
            result = modified_result
        elif isinstance(original_result, dict) and original_result.get("resourceType"):
            # Transformer returned None for a FHIR resource - it was filtered
            if original_result.get("resourceType") == "Bundle":
                # Bundle was filtered - return empty bundle
                result = {
                    "resourceType": "Bundle",
                    "type": original_result.get("type", "searchset"),
                    "total": 0,
                    "entry": []
                }
            else:
                # Single resource was filtered - return 401 Unauthorized
                abort(401, description="Access denied: Resource does not have a matching Keycloak security label")

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
