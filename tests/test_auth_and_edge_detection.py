import unittest

import requests

from config.settings import Settings
from core.results import ScanResults
from modules.auth import AuthModule
from modules.desync import DesyncModule
from modules.ratelimit import RatelimitModule
from modules.recon import ReconModule
from modules.twofa import TwofaModule
from modules.waf import WafModule


class SilentLog:
    def __getattr__(self, _name):
        return lambda *_args, **_kwargs: None


def make_module(module_class, target="https://example.test"):
    return module_class(
        Settings(target=target),
        SilentLog(),
        ScanResults(target),
    )


def response(body="", status=200, headers=None, url="https://example.test/"):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode("utf-8")
    result.encoding = "utf-8"
    result.url = url
    result.headers.update(headers or {})
    return result


class WafTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(WafModule)

    def test_short_f5_text_in_page_is_not_a_vendor_signature(self):
        page = response("asset chunk f5 appears in this application page")

        self.assertIsNone(self.module._vendor(page))

    def test_bigip_cookie_is_a_vendor_signature(self):
        page = response(headers={"Set-Cookie": "BIGipServer_pool=123456; Path=/"})

        self.assertEqual("F5 BIG-IP", self.module._vendor(page))

    def test_evasion_is_not_tested_without_an_initial_block(self):
        calls = []
        self.module.get = lambda *args, **kwargs: calls.append((args, kwargs)) or response()

        self.module.run()

        self.assertEqual(2, len(calls))
        titles = [finding.title for finding in self.module.results.all_findings()]
        self.assertNotIn("WAF evasion successful", titles)

    def test_attack_only_403_is_an_unknown_filter_signal(self):
        baseline = response()
        attack = response(status=403)

        self.assertEqual("unknown", self.module._detect_waf(baseline, attack))


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(AuthModule)

    def test_account_words_are_not_login_success_evidence(self):
        page = response("Welcome to your account and profile dashboard")

        self.assertFalse(self.module._success(page))

    def test_new_logout_control_is_login_success_evidence(self):
        login_page = response('<form action="/login">Sign in</form>')
        account_page = response('<a href="/logout">Log out</a>')

        self.assertTrue(self.module._success(account_page, login_page))

    def test_pre_existing_authenticated_session_is_not_attributed_to_credentials(self):
        account_page = response('<a href="/logout">Log out</a>')

        self.assertFalse(self.module._success(account_page, account_page))


class DesyncTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(DesyncModule)

    def test_normal_400_rejection_is_not_a_desync_indicator(self):
        raw = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"

        self.assertFalse(self.module._is_desync_indicator(raw))

    def test_multiple_responses_with_method_error_are_an_indicator(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid method GPOST"
        )

        self.assertTrue(self.module._is_desync_indicator(raw))


class TwoFactorTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(TwofaModule)

    def test_public_account_copy_is_not_a_two_factor_challenge(self):
        page = response("Create an account and edit your profile")

        self.assertFalse(self.module._looks_challenge(page))
        self.assertFalse(self.module._is_authed(page))

    def test_otp_form_is_a_two_factor_challenge(self):
        page = response(
            '<form><label>Authenticator verification code</label>'
            '<input name="otp" autocomplete="one-time-code"></form>'
        )

        self.assertTrue(self.module._looks_challenge(page))

    def test_logout_link_is_strong_authenticated_evidence(self):
        page = response('<nav><a href="/logout">Log out</a></nav>')

        self.assertTrue(self.module._is_authed(page))


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(RatelimitModule)

    def test_missing_login_routes_do_not_produce_a_finding(self):
        self.module.get = lambda *_args, **_kwargs: response(status=404)
        self.module.post = lambda *_args, **_kwargs: self.fail("POST should not be called")

        self.module.run()

        self.assertEqual([], self.module.results.all_findings())

    def test_password_form_fields_and_action_are_discovered(self):
        page = response(
            '<form action="/api/login"><input name="email">'
            '<input type="password" name="passwd"></form>',
            url="https://example.test/account",
        )
        self.module.get = lambda *_args, **_kwargs: page

        self.assertEqual(
            ("https://example.test/api/login", "email", "passwd"),
            self.module._find_login(),
        )

    def test_unauthorized_login_responses_are_still_measured(self):
        self.module._find_login = lambda: (
            "https://example.test/api/login",
            "email",
            "password",
        )
        self.module.post = lambda *_args, **_kwargs: response(status=401)

        self.module.run()

        titles = [finding.title for finding in self.module.results.all_findings()]
        self.assertIn("No observable authentication throttling", titles)


class HeaderTests(unittest.TestCase):
    def test_hsts_is_not_required_on_plain_http(self):
        module = make_module(ReconModule, target="http://example.test")
        module.get = lambda *_args, **_kwargs: response(url="http://example.test/")

        module._check_headers()

        titles = [finding.title for finding in module.results.all_findings()]
        self.assertNotIn("Missing security header: Strict-Transport-Security", titles)

    def test_hsts_is_checked_on_https(self):
        module = make_module(ReconModule)
        module.get = lambda *_args, **_kwargs: response()

        module._check_headers()

        titles = [finding.title for finding in module.results.all_findings()]
        self.assertIn("Missing security header: Strict-Transport-Security", titles)


if __name__ == "__main__":
    unittest.main()
