import unittest
from flask import Flask, json
from datetime import datetime, timedelta
from jwt_proxy.api import CustomJSONProvider, blueprint

class TestCustomJSONProvider(unittest.TestCase):
    def setUp(self):
        # Create a Flask app and set the custom JSON provider
        self.app = Flask(__name__)
        self.app.json = CustomJSONProvider(self.app)
        self.app.config["OIDC_AUTHORIZE_URL"] = "http://authorize.example.com"
        self.app.config["OIDC_TOKEN_URI"] = "http://token.example.com"
        self.app.config["OIDC_TOKEN_INTROSPECTION_URI"] = "http://introspection.example.com"
        self.app.register_blueprint(blueprint)
        self.client = self.app.test_client()

    def test_smart_configuration(self):
        """Test /fhir/.well-known/smart-configuration endpoint"""
        response = self.client.get('/fhir/.well-known/smart-configuration')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {
            'authorization_endpoint': 'http://authorize.example.com',
            'token_endpoint': 'http://token.example.com',
            'introspection_endpoint': 'http://introspection.example.com'
        })

    def test_json_encoding_date(self):
        """Test that CustomJSONProvider correctly serializes a datetime object"""
        test_date = datetime(2024, 8, 15, 12, 30)
        with self.app.test_request_context('/'):
            response = self.client.get('/settings')
            json_data = json.dumps({"test_date": test_date}, default=self.app.json.default)
            self.assertEqual(json_data, '{"test_date": "2024-08-15 12:30:00"}')

    def test_json_encoding_timedelta(self):
        """Test that CustomJSONProvider correctly serializes a timedelta object"""
        test_timedelta = timedelta(days=5, hours=10, minutes=30)
        with self.app.test_request_context('/'):
            response = self.client.get('/settings')
            json_data = json.dumps({"test_timedelta": test_timedelta}, default=self.app.json.default)
            self.assertEqual(json_data, '{"test_timedelta": "5 days, 10:30:00"}')

if __name__ == '__main__':
    unittest.main()
