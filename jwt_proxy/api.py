from flask import Blueprint, abort, current_app, jsonify, request, json as flask_json
import jwt
import requests
import json
import re

from jwt_proxy.audit import audit_HAPI_change

blueprint = Blueprint('auth', __name__)
SUPPORTED_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS')

# TODO: to be pulled into its own module and loaded per config
def scope_filter(req, token):
    user_id = token.get("sub")
    pattern = rf"(.*?\|)?{user_id}"
    # Search params
    params = req.args
    id_param_value = params.get("identifier", params.get("_identifier", params.get("subject.identifier")))
    if id_param_value is not None and re.search(pattern, id_param_value):
        return True
    # Search body
    if req.is_json:
        try:
            data = req.get_json()
            parsed_data = json.loads(data)
        except (ValueError, TypeError):
            return False
        reference_string = parsed_data.get('subject', {}).get('reference')
        if reference_string is not None and re.search(pattern, reference_string):
            return True
    return False
    
    

def proxy_request(req, upstream_url, user_info=None):
    """Forward request to given url"""
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
                user_info=user_info,
                method=req.method,
                params=req.args,
                url=upstream_url,
            )
    except Exception as e:
        from flask import current_app
        current_app.logger.exception(e)
    return result


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
    
    # TODO: call new function here to dynamically load a filter call dependent on config; hardwired for now
    if scope_filter(request, decoded_token):
        response_content = proxy_request(
            req=request,
            upstream_url=f"{current_app.config['UPSTREAM_SERVER']}/{relative_path}",
            user_info=decoded_token.get("email") or decoded_token.get("preferred_username"),
        )
        return response_content
    return jsonify(message="invalid request"), 400


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
