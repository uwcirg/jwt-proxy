"""Default configuration

Use environment variable to override
"""
import os


# $KEYCLOAK_FQDN/auth/realms/$REALM/protocol/openid-connect/certs
JWKS_URL = os.getenv("JWKS_URL")

