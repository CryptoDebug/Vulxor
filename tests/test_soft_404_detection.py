import unittest

import requests

from config.settings import Settings
from core.results import ScanResults
from modules.auth import AuthModule
from modules.graphql import GraphqlModule
from modules.jwt import JwtModule
from modules.race import RaceModule
from modules.ratelimit import RatelimitModule
from modules.recon import ReconModule
from modules.twofa import TwofaModule
from modules.upload import UploadModule


class SilentLog:
    def __getattr__(self, _name):
        return lambda *_args, **_kwargs: None


def response(body="", status=200, content_type="text/html", headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = body if isinstance(body, bytes) else body.encode("utf-8")
    result.encoding = "utf-8"
    result.url = "https://example.test/missing"
    result.headers["Content-Type"] = content_type
    result.headers.update(headers or {})
    return result


def make_module(results=None, filter_soft_404=True, module_class=ReconModule):
    target = "https://example.test"
    results = results or ScanResults(target)
    return module_class(
        Settings(target=target, filter_soft_404=filter_soft_404),
        SilentLog(),
        results,
    )


class Soft404Tests(unittest.TestCase):
    def test_real_404_is_missing_even_though_requests_marks_it_false(self):
        module = make_module()

        self.assertTrue(module.is_probable_not_found(response("missing", status=404)))


class ModuleSoft404FilteringTests(unittest.TestCase):
    def _module(self, module_class):
        module = make_module(module_class=module_class)
        module.is_probable_not_found = lambda _response: True
        return module

    def test_auth_and_rate_limit_ignore_password_form_on_custom_404(self):
        page = response(
            '<form><input name="email"><input type="password" name="password"></form>'
        )
        auth = self._module(AuthModule)
        auth.get = lambda *_args, **_kwargs: page
        rate_limit = self._module(RatelimitModule)
        rate_limit.get = lambda *_args, **_kwargs: page

        self.assertIsNone(auth._find_login())
        self.assertIsNone(rate_limit._find_login())

    def test_two_factor_ignores_otp_form_on_custom_404(self):
        module = self._module(TwofaModule)
        page = response(
            '<label>Authenticator verification code</label>'
            '<input name="otp" autocomplete="one-time-code">'
        )

        self.assertFalse(module._looks_challenge(page))

    def test_graphql_ignores_schema_json_on_custom_404(self):
        module = self._module(GraphqlModule)
        page = response('{"data":{"__schema":{"types":[]}}}', content_type="application/json")
        module.post = lambda *_args, **_kwargs: page

        module.run()

        self.assertEqual([], module.results.all_findings())

    def test_upload_ignores_file_form_on_custom_404(self):
        module = self._module(UploadModule)
        module.get = lambda *_args, **_kwargs: response('<input type="file" name="file">')

        self.assertIsNone(module._find_upload())

    def test_jwt_admin_probe_ignores_custom_404(self):
        module = self._module(JwtModule)
        module.get = lambda *_args, **_kwargs: response("Admin dashboard")

        self.assertFalse(module._test_with_token("header.payload.signature"))

    def test_race_probe_stops_before_parallel_requests_on_custom_404(self):
        module = self._module(RaceModule)
        calls = []
        module.post = lambda *_args, **_kwargs: calls.append(1) or response("Discount applied")

        module._race_test("https://example.test/voucher", n=3)

        self.assertEqual(1, len(calls))


class Soft404ComparisonTests(unittest.TestCase):
    def test_similar_custom_200_page_is_missing(self):
        module = make_module()
        baseline = response(
            "<h1>Page not found</h1><p>Request 981726 at /__vulxor_missing_deadbeef</p>"
        )
        module.results._missing_baselines = [module._response_signature(baseline)]
        candidate = response(
            "<h1>Page not found</h1><p>Request 445566 at /__vulxor_missing_cafebabe</p>"
        )

        self.assertTrue(module.is_probable_not_found(candidate))

    def test_redirect_to_shared_fallback_is_missing(self):
        module = make_module()
        baseline = response("", status=302, headers={"Location": "/"})
        module.results._missing_baselines = [module._response_signature(baseline)]

        self.assertTrue(module.is_probable_not_found(
            response("", status=302, headers={"Location": "/"})
        ))
        self.assertFalse(module.is_probable_not_found(
            response("", status=302, headers={"Location": "/login"})
        ))

    def test_different_binary_content_is_not_missing_based_on_length(self):
        module = make_module()
        baseline = response(b"A" * 256, content_type="application/octet-stream")
        module.results._missing_baselines = [module._response_signature(baseline)]
        candidate = response(b"B" * 256, content_type="application/octet-stream")

        self.assertFalse(module.is_probable_not_found(candidate))

    def test_missing_baselines_are_shared_between_modules(self):
        results = ScanResults("https://example.test")
        first = make_module(results)
        second = make_module(results)
        calls = []
        fallback = response("<h1>Page not found</h1>")
        first._request = lambda *_args, **_kwargs: calls.append(1) or fallback
        second._request = lambda *_args, **_kwargs: self.fail("baseline should be reused")

        self.assertTrue(first.is_probable_not_found(fallback))
        self.assertTrue(second.is_probable_not_found(fallback))
        self.assertEqual(4, len(calls))

    def test_custom_filter_can_be_disabled_without_accepting_real_404s(self):
        module = make_module(filter_soft_404=False)
        module.results._missing_baselines = [
            module._response_signature(response("<h1>Not found</h1>"))
        ]

        self.assertFalse(module.is_probable_not_found(response("<h1>Not found</h1>")))
        self.assertTrue(module.is_probable_not_found(response("missing", status=404)))


if __name__ == "__main__":
    unittest.main()
