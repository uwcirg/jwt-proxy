import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify, request
import jwt
from jwt_proxy.api import validate_jwt, proxy_request  # Adjust the import path based on your actual module structure

class TestValidateJWT(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["PATH_WHITELIST"] = ["/allowed_path"]
        self.app.config["UPSTREAM_SERVER"] = "http://upstream-server"
        self.app.config["JWKS_URL"] = "http://jwks-url"
        
        # Register the route using the validate_jwt function
        @self.app.route("/", defaults={"relative_path": ""}, methods=["GET", "POST"])
        @self.app.route("/<path:relative_path>", methods=["GET", "POST"])
        def validate_jwt_route(relative_path):
            return validate_jwt(relative_path)

        self.client = self.app.test_client()

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    def test_path_whitelist(self, mock_proxy_request):
        # Mock response
        mock_proxy_request.return_value = jsonify(message="request proxied")
        response = self.client.get("/allowed_path")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_valid_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        mock_proxy_request.return_value = jsonify(message="request proxied")
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value.key = "test-key"
        mock_decode.return_value = {"email": "test@example.com"}

        headers = {"Authorization": "Bearer valid-token"}
        response = self.client.get("/some_path", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_missing_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        response = self.client.get("/some_path")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {"message": "token missing"})

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_expired_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value.key = "test-key"
        mock_decode.side_effect = jwt.exceptions.ExpiredSignatureError("token expired")

        headers = {"Authorization": "Bearer expired-token"}
        response = self.client.get("/some_path", headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json, {"message": "token expired"})

if __name__ == '__main__':
    unittest.main()
