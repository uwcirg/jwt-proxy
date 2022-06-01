"""Default configuration

Use environment variable to override
"""
import os


# $KEYCLOAK_FQDN/auth/realms/$REALM/protocol/openid-connect/certs
OIDC_AUTHORIZE_URL = os.getenv("OIDC_AUTHORIZE_URL")
OIDC_TOKEN_URI = os.getenv("OIDC_TOKEN_URI")
OIDC_TOKEN_INTROSPECTION_URI = os.getenv("OIDC_TOKEN_INTROSPECTION_URI")
JWKS_URL = os.getenv("JWKS_URL")
UPSTREAM_SERVER = os.getenv("UPSTREAM_SERVER")
PATH_WHITELIST = os.getenv("PATH_WHITELIST", "/hapi-fhir-jpaserver/fhir/metadata").split(",")
