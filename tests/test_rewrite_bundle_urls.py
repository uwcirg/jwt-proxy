import importlib

from flask import Flask


class FakeRequest:
    def __init__(self, path: str, method: str = "GET"):
        self.path = path
        self.method = method


UPSTREAM = "http://hapi.internal:8080/hapi-fhir-jpaserver"
PUBLIC = "https://proxy.example.org"


def _make_app(upstream=UPSTREAM + "/", public=PUBLIC):
    app = Flask(__name__)
    app.config["UPSTREAM_SERVER"] = upstream
    app.config["PUBLIC_URL"] = public
    return app


def _make_bundle():
    return {
        "resourceType": "Bundle",
        "type": "searchset",
        "link": [
            {
                "relation": "self",
                "url": f"{UPSTREAM}/fhir/Patient?_count=1"
            },
            {
                "relation": "next",
                "url": f"{UPSTREAM}/fhir?_getpages=abc&_getpagesoffset=1"
            },
            {
                "relation": "other",
                "url": "http://elsewhere.example/x"
            }
        ],
        "entry": [
            {
                "fullUrl": f"{UPSTREAM}/fhir/Patient/1",
                "resource": {
                    "resourceType": "Patient",
                    "id": "1"
                }
            }
        ]
    }


def test_rewrites_bundle_links_and_full_urls():
    """Test that upstream URLs in bundle links and entry fullUrls are rewritten to the public URL."""
    module = importlib.import_module("jwt_proxy.policies.90_rewrite_bundle_urls")

    bundle = _make_bundle()

    req = FakeRequest(path="/fhir/Patient", method="GET")
    with _make_app().app_context():
        result = module.transform_response(req, bundle)

    assert result["link"][0]["url"] == f"{PUBLIC}/fhir/Patient?_count=1"
    assert result["link"][1]["url"] == f"{PUBLIC}/fhir?_getpages=abc&_getpagesoffset=1"
    assert result["link"][2]["url"] == "http://elsewhere.example/x"
    assert result["entry"][0]["fullUrl"] == f"{PUBLIC}/fhir/Patient/1"


def test_does_not_rewrite_lookalike_host():
    """Test that a URL which merely starts with the upstream URL text is not rewritten."""
    module = importlib.import_module("jwt_proxy.policies.90_rewrite_bundle_urls")

    bundle = _make_bundle()
    bundle["link"][0]["url"] = UPSTREAM + "-external/fhir/Patient"

    req = FakeRequest(path="/fhir/Patient", method="GET")
    with _make_app().app_context():
        result = module.transform_response(req, bundle)

    assert result["link"][0]["url"] == UPSTREAM + "-external/fhir/Patient"


def test_returns_bundle_unchanged_when_public_url_not_configured():
    """Test that the bundle is returned unchanged when PUBLIC_URL is not set."""
    module = importlib.import_module("jwt_proxy.policies.90_rewrite_bundle_urls")

    bundle = _make_bundle()

    req = FakeRequest(path="/fhir/Patient", method="GET")
    with _make_app(public=None).app_context():
        result = module.transform_response(req, bundle)

    assert result == _make_bundle()


def test_returns_non_bundle_unchanged():
    """Test that a non-bundle resource is returned unchanged, not None (i.e. filtered)."""
    module = importlib.import_module("jwt_proxy.policies.90_rewrite_bundle_urls")

    fhir_resource = {
        "resourceType": "Patient",
        "id": "1"
    }

    req = FakeRequest(path="/fhir/Patient/1", method="GET")
    with _make_app().app_context():
        result = module.transform_response(req, fhir_resource)

    assert result is not None
    assert result == fhir_resource
