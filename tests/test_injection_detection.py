import unittest

import requests

from config.settings import Settings
from core.results import ScanResults
from modules.evidence import new_regex_evidence
from modules.sqli import SqliModule
from modules.ssrf import SsrfModule
from modules.ssti import SstiModule
from modules.xss import XssModule


class SilentLog:
    def __getattr__(self, _name):
        return lambda *_args, **_kwargs: None


def make_module(module_class):
    target = "https://example.test"
    return module_class(
        Settings(target=target),
        SilentLog(),
        ScanResults(target),
    )


def response(body, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode("utf-8")
    result.encoding = "utf-8"
    result.url = "https://example.test/"
    return result


class EvidenceTests(unittest.TestCase):
    def test_existing_signature_is_not_new_evidence(self):
        pattern = [r"(?m)^root:[^\r\n]*:0:0:[^\r\n]*$"]
        page = "documentation\nroot:x:0:0:example only\n"

        self.assertIsNone(new_regex_evidence(page, page, pattern))

    def test_an_additional_signature_is_new_evidence(self):
        pattern = [r"(?m)^root:[^\r\n]*:0:0:[^\r\n]*$"]
        baseline = "documentation\nroot:x:0:0:example only\n"
        candidate = baseline + "root:x:0:0:root:/root:/bin/bash\n"

        self.assertIn("/bin/bash", new_regex_evidence(baseline, candidate, pattern))


class SqlInjectionTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(SqliModule)

    def test_translated_database_message_is_not_a_sql_error(self):
        body = (
            "Database unavailable. Start Docker Desktop and PostgreSQL, then try "
            "again. genericError: The request could not be completed."
        )

        self.assertFalse(self.module._is_error(body))

    def test_real_postgresql_error_is_detected_only_when_introduced(self):
        normal = "Sign in to continue"
        error = normal + "\nPostgreSQL ERROR: unterminated quoted string"

        self.assertIn("PostgreSQL ERROR:", self.module._new_error(normal, error))
        self.assertIsNone(self.module._new_error(error, error))


class SsrfTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(SsrfModule)
        self.baseline = response("<html>Normal page</html>")

    def test_reflected_gcp_url_is_not_ssrf_evidence(self):
        payload = "http://metadata.google.internal/computeMetadata/v1/"
        reflected = response(f'<script>route={{"url":"{payload}"}}</script>')

        self.assertIsNone(self.module._ssrf_evidence(self.baseline, reflected, payload))

    def test_cloud_metadata_listing_is_ssrf_evidence(self):
        payload = "http://169.254.169.254/latest/meta-data/"
        metadata = response("ami-id\ninstance-id\nlocal-ipv4\n")

        self.assertEqual(
            "ami-id",
            self.module._ssrf_evidence(self.baseline, metadata, payload).strip(),
        )


class SstiTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(SstiModule)

    def test_number_already_on_page_is_not_evaluation(self):
        baseline = response("Products 9359")
        candidate = response("Products 9359; query={{1337*7}}")

        self.assertFalse(self.module._evaluated(baseline, candidate, "9359"))

    def test_new_exact_result_is_evaluation_signal(self):
        baseline = response("Products")
        candidate = response("Hello 9359")

        self.assertTrue(self.module._evaluated(baseline, candidate, "9359"))


class XssTests(unittest.TestCase):
    def setUp(self):
        self.module = make_module(XssModule)

    def test_nextjs_serialized_javascript_url_is_inert(self):
        payload = "javascript:window.vulxor_xss_7f3a=1"
        body = (
            '<script>self.__next_f.push(["__PAGE__?'
            f'{{\\"q\\":\\"{payload}\\"}}"])</script>'
        )

        self.assertEqual("inert", self.module._reflection_state(body, payload))

    def test_javascript_url_in_href_is_executable(self):
        payload = "javascript:window.vulxor_xss_7f3a=1"
        body = f'<a href="{payload}">continue</a>'

        self.assertEqual("executable", self.module._reflection_state(body, payload))

    def test_event_handler_payload_is_executable(self):
        payload = '\"><img src=x onerror=window.vulxor_xss_7f3a=1>'
        body = f'<div data-value="safe{payload}</div>'

        self.assertEqual("executable", self.module._reflection_state(body, payload))


if __name__ == "__main__":
    unittest.main()
