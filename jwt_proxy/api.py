from flask import Blueprint, abort, current_app, jsonify
from flask.json import JSONEncoder

blueprint = Blueprint('auth', __name__)

@blueprint.route('/', defaults={'path': ''})
@blueprint.route('/<path:path>')
def catchall(path):
    return 'You want path: %s' % path


@blueprint.route('/settings', defaults={'config_key': None})
@blueprint.route('/settings/<string:config_key>')
def config_settings(config_key):
    """Non-secret application settings"""

    # workaround no JSON representation for datetime.timedelta
    class CustomJSONEncoder(JSONEncoder):
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