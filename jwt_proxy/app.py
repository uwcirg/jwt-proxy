from flask import Flask
import logging
from logging import config as logging_config

from jwt_proxy import api
from jwt_proxy.audit import audit_log_init, audit_entry
from jwt_proxy.api import CustomJSONProvider

def create_app(testing=False, cli=False):
    """Application factory, used to create application"""
    app = Flask("jwt_proxy")
    app.json = CustomJSONProvider(app)
    register_blueprints(app)
    configure_app(app)
    return app


def register_blueprints(app):
    """register all blueprints for application"""
    app.register_blueprint(api.blueprint)


def configure_app(app):
    """Load successive configs - overriding defaults"""
    app.config.from_object("jwt_proxy.config")
    configure_logging(app)


def configure_logging(app):
    app.logger  # must call to init prior to config or it'll replace
    logging_config.fileConfig("logging.ini", disable_existing_loggers=False)
    app.logger.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
    if app.config["LOGSERVER_URL"] and app.config["LOGSERVER_TOKEN"]:
        audit_log_init(app)
        audit_entry("jwt_proxy logging initialized")
