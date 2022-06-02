from flask import Flask

from jwt_proxy import api


def create_app(testing=False, cli=False):
    """Application factory, used to create application"""
    app = Flask("jwt_proxy")
    register_blueprints(app)
    configure_app(app)

    return app


def register_blueprints(app):
    """register all blueprints for application"""
    app.register_blueprint(api.blueprint)


def configure_app(app):
    """Load successive configs - overriding defaults"""

    app.config.from_object("jwt_proxy.config")
