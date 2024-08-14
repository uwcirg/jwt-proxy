import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify, request
import jwt

# Assume blueprint and validate_jwt function are defined in your application
# For testing purposes, we'll use a simple Flask app
app = Flask(__name__)
app.config["PATH_WHITELIST"] = ["/allowed_path"]
app.config["UPSTREAM_SERVER"] = "http://upstream-server"
app.config["JWKS_URL"] = "http://jwks-url"


class TestValidateJWT(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    @patch('jwt_proxy.api.proxy_request')
    def test_path_whitelist(self, mock_proxy_request):
        # Mock response as a Flask Response object directly
        mock_proxy_request.return_value = self.client.get('/allowed_path')
        response = self.client.get("/allowed_path")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_valid_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        mock_proxy_request.return_value = self.client.get('/some_path')
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value.key = "test-key"
        mock_decode.return_value = {"email": "test@example.com"}

        headers = {"Authorization": "Bearer valid-token"}
        response = self.client.get("/some_path", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_missing_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        response = self.client.get("/some_path")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {"message": "token missing"})

    @patch('jwt_proxy.api.proxy_request')
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
