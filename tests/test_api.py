import unittest
from unittest.mock import patch, MagicMock
import json
import jwt
from jwt_proxy.api import proxy_request
from jwt_proxy.app import create_app

class TestAuthBlueprint(unittest.TestCase):
    def setUp(self):
        """Set up a test Flask app and client"""
        self.app = create_app()
        self.app.config['TESTING'] = True
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

        # Test whitelisted path without token
        response = self.client.get('/whitelisted')
        self.assertEqual(response.status_code, 200)

        # Test valid token
        response = self.client.get('/', headers={'Authorization': 'Bearer valid_token'})
        self.assertEqual(response.status_code, 200)

        # Test missing token
        response = self.client.get('/')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['message'], "token missing")

        # Test expired token
        mock_decode.side_effect = jwt.exceptions.ExpiredSignatureError()
        response = self.client.get('/', headers={'Authorization': 'Bearer expired_token'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json['message'], "token expired")

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
