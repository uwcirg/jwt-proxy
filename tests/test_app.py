import unittest

from jwt_proxy.app import create_app

class TestConfig:
    TESTING = True


class TestIsaccJWTProxyApp(unittest.TestCase):
    def setUp(self):
        self.app = create_app(testing=True)
        self.app.config.from_object(TestConfig)
        self.client = self.app.test_client()

    def test_app_exists(self):
        self.assertIsNotNone(self.app)

    def test_blueprints_registered(self):
        self.assertIn('api', self.app.blueprints)


if __name__ == '__main__':
    unittest.main()
