from flask import Blueprint, abort, current_app, jsonify, request
import jwt
import requests

blueprint = Blueprint('auth', __name__)

@blueprint.route('/', defaults={'path': ''})
@blueprint.route('/<path:path>')
def validate_jwt(path):
    """Validate JWT and pass to upstream server"""
    token = request.headers.pop("authorization", "").split("Bearer ")[-1]
    if not token:
        return jsonify({"message":"token missing"}), 400

    jwks_client = jwt.PyJWKClient(current_app.config["JWKS_URL"])
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    try:
        decoded_token = jwt.decode(
            jwt=token,
            # TODO cache public key in redis
            key=signing_key.key,
            algorithms=("RS256"),
            audience=("account"),
            options={
                #"verify_signature": False,
                #"verify_aud": False
            }
        )
    except jwt.exceptions.ExpiredSignatureError:
        return jsonify({"message":"token expired"}), 401

    response = requests.get(
        url=f"{current_app.config['UPSTREAM_SERVER']}{path}",
        headers=request.headers,
        params=request.args,
    )
    return response.json()


@blueprint.route('/settings', defaults={'config_key': None})
@blueprint.route('/settings/<string:config_key>')
def config_settings(config_key):
    """Non-secret application settings"""

    # workaround no JSON representation for datetime.timedelta
    class CustomJSONEncoder(flask.json.JSONEncoder):
        def default(self, obj):
            return str(obj)
    current_app.json_encoder = CustomJSONEncoder

    # return selective keys - not all can be be viewed by users, e.g.secret key
    blacklist = ('SECRET', 'KEY')

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
