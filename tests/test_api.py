import unittest
from unittest.mock import patch, MagicMock
from flask import Flask
import json
import jwt
from jwt_proxy.api import blueprint, proxy_request, CustomJSONProvider, validate_jwt

class TestAuthBlueprint(unittest.TestCase):
    def setUp(self):
        """Set up a test Flask app and client"""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['UPSTREAM_SERVER'] = 'http://example.com'
        self.app.config['JWKS_URL'] = 'http://jwks.example.com'
        self.app.config['PATH_WHITELIST'] = ['/whitelisted']
        self.app.config['OIDC_AUTHORIZE_URL'] = 'http://authorize.example.com'
        self.app.config['OIDC_TOKEN_URI'] = 'http://token.example.com'
        self.app.config['OIDC_TOKEN_INTROSPECTION_URI'] = 'http://introspection.example.com'
        self.app.json = CustomJSONProvider(self.app)
        self.app.register_blueprint(blueprint)
        self.client = self.app.test_client()

    @patch('requests.request')
    def test_proxy_request(self, mock_request):
        """Test proxy_request function"""
        mock_response = MagicMock()
        mock_response.json.return_value = {'key': 'value'}
        mock_request.return_value = mock_response

        req = MagicMock()
        req.method = 'GET'
        req.headers = {'Authorization': 'Bearer token'}
        req.args = {'param': 'value'}
        req.json = None
        req.data = None

        response = proxy_request(req, 'http://example.com/api')
        self.assertEqual(response, {'key': 'value'})

        # Test JSONDecodeError handling
        mock_response.json.side_effect = json.decoder.JSONDecodeError("Expecting value", "", 0)
        mock_response.text = "Plain text response"

        response = proxy_request(req, 'http://example.com/api')
        self.assertEqual(response, "Plain text response")

    def test_smart_configuration(self):
        """Test /fhir/.well-known/smart-configuration endpoint"""
        response = self.client.get('/fhir/.well-known/smart-configuration')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {
            'authorization_endpoint': 'http://authorize.example.com',
            'token_endpoint': 'http://token.example.com',
            'introspection_endpoint': 'http://introspection.example.com'
        })

    def test_config_settings(self):
        """Test /settings endpoint"""
        # Test retrieving non-sensitive config
        response = self.client.get('/settings')
        self.assertEqual(response.status_code, 200)
        self.assertIn('UPSTREAM_SERVER', response.json)
        self.assertNotIn('SECRET', response.json)

        # Test retrieving specific config
        response = self.client.get('/settings/UPSTREAM_SERVER')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['UPSTREAM_SERVER'], 'http://example.com')

        # Test accessing sensitive config
        response = self.client.get('/settings/SECRET_KEY')
        self.assertEqual(response.status_code, 400)

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
        # Mock response directly without using jsonify
        mock_proxy_request.return_value = {"message": "request proxied"}
        
        with self.app.app_context():
            response = self.client.get("/allowed_path")
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_valid_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        mock_proxy_request.return_value = {"message": "request proxied"}
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value.key = "test-key"
        mock_decode.return_value = {"email": "test@example.com"}

        headers = {"Authorization": "Bearer valid-token"}
        
        with self.app.app_context():
            response = self.client.get("/some_path", headers=headers)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"message": "request proxied"})

    @patch('jwt_proxy.api.proxy_request')  # Adjust the import path based on where proxy_request is defined
    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_missing_token(self, mock_decode, mock_jwks_client, mock_proxy_request):
        with self.app.app_context():
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
        
        with self.app.app_context():
            response = self.client.get("/some_path", headers=headers)
        
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json, {"message": "token expired"})

if __name__ == '__main__':
    unittest.main()
