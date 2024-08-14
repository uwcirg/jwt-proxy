import unittest
from flask import Flask
from jwt_proxy.api import blueprint, proxy_request
import json
from unittest.mock import patch, MagicMock
import jwt
from jwt_proxy.api import CustomJSONProvider

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

    @patch('jwt.PyJWKClient')
    @patch('jwt.decode')
    def test_validate_jwt(self, mock_decode, mock_jwk_client):
        """Test JWT validation and proxying"""
        # Set up mock JWKClient
        mock_key = MagicMock()
        mock_jwk_client_instance = MagicMock()
        mock_jwk_client_instance.get_signing_key_from_jwt.return_value = mock_key
        mock_jwk_client.return_value = mock_jwk_client_instance

        # Set up mock JWT decoding
        mock_decode.return_value = {'email': 'user@example.com'}
        self.app.json = CustomJSONProvider(self.app)

        # Test valid token
        response = self.client.get('/', headers={'Authorization': 'Bearer valid_token'})
        print(f'Status Code: {response.status_code}')
        print(f'Response Data: {response.data.decode()}')
        print(f'Response JSON: {response.json}')
        self.assertEqual(response.status_code, 200)

        # Test missing token
        response = self.client.get('/')
        print(f'Status Code: {response.status_code}')
        print(f'Response Data: {response.data.decode()}')
        print(f'Response JSON: {response.json}')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json.get('message'), "token missing")

        # Test expired token
        mock_decode.side_effect = jwt.exceptions.ExpiredSignatureError()
        response = self.client.get('/', headers={'Authorization': 'Bearer expired_token'})
        print(f'Status Code: {response.status_code}')
        print(f'Response Data: {response.data.decode()}')
        print(f'Response JSON: {response.json}')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json.get('message'), "token expired")

        # Test whitelisted path without token
        response = self.client.get('/whitelisted', content_type='application/json')
        print(f'Status Code: {response.status_code}')
        print(f'Response Data: {response.data.decode()}')
        print(f'Response JSON: {response.json}')
        self.assertEqual(response.status_code, 200)

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

if __name__ == '__main__':
    unittest.main()
