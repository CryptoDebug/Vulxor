import re

from modules.base import BaseModule
from modules.auth_signals import has_authenticated_marker


class TwofaModule(BaseModule):
    NAME = "2fa"
    DESCRIPTION = "2FA bypass - direct page access, cookie manipulation, brute-force OTP"

    PROTECTED_PATHS = ["/dashboard", "/admin", "/profile", "/settings", "/account"]
    TWO_FA_PATHS    = ["/verify", "/2fa", "/otp", "/verify-otp", "/mfa"]
    OTP_PARAMS      = ["code", "token", "otp", "totp", "2fa_code", "verification_code"]
    COMMON_OTPS     = ["000000", "111111", "123456", "654321", "999999", "123123"]

    def run(self):
        self.log.info("[2fa] Testing 2FA bypass vectors")
        challenge = self._find_challenge()
        if not challenge:
            self.log.debug("[2fa] No active OTP challenge detected; skipping bypass probes")
            return
        self._challenge_url, self._challenge_response = challenge
        self._protected_baselines = {
            path: self.get(self.url(path)) for path in self.PROTECTED_PATHS
        }
        self._gated_paths = {
            path for path, response in self._protected_baselines.items()
            if self._is_gated(response)
        }
        self._test_direct_access()
        self._test_otp_bruteforce()
        self._test_param_bypass()

    def _find_challenge(self):
        crawl = self.results.meta.get("crawl", {})
        for form in crawl.get("forms", []):
            inputs = form.get("inputs", [])
            if self._has_otp_field(inputs):
                url = form.get("action") or self.target
                response = self.get(url)
                if self._looks_challenge(response):
                    return url, response

        for path in self.TWO_FA_PATHS:
            url = self.url(path)
            response = self.get(url)
            if self._looks_challenge(response):
                return url, response
        return None

    def _looks_challenge(self, resp) -> bool:
        if not resp or resp.status_code != 200 or self.is_probable_not_found(resp):
            return False
        low = resp.text.lower()
        fields = re.findall(r'<input\b[^>]*\bname=["\']([^"\']+)["\']', resp.text, re.I)
        has_one_time_autocomplete = bool(re.search(
            r'<input\b[^>]*\bautocomplete=["\']one-time-code["\']',
            resp.text,
            re.I,
        ))
        has_challenge_copy = bool(re.search(
            r"\b(?:one[- ]time|verification code|authenticator|otp|totp|2fa|mfa)\b",
            low,
        ))
        return has_challenge_copy and (self._has_otp_field(fields) or has_one_time_autocomplete)

    def _has_otp_field(self, fields) -> bool:
        names = {str(field).casefold() for field in fields}
        return bool(names.intersection(name.casefold() for name in self.OTP_PARAMS))

    def _is_authed(self, resp) -> bool:
        if not resp or not 200 <= resp.status_code < 400 or \
                self.is_probable_not_found(resp) or self._looks_challenge(resp):
            return False
        return has_authenticated_marker(resp.text)

    def _is_gated(self, resp) -> bool:
        if not resp:
            return True
        return resp.status_code in (401, 403) or self._looks_challenge(resp)

    def _test_direct_access(self):
        if not self._gated_paths:
            return
        for path in self.PROTECTED_PATHS:
            if path in self._gated_paths:
                continue
            r = self._protected_baselines.get(path)
            if self._is_authed(r):
                self.add_finding(
                    severity="HIGH",
                    title="2FA bypass - direct page access",
                    url=self.url(path),
                    detail=f"Page '{path}' accessible without completing 2FA step.",
                    remediation="Enforce 2FA gate on every request to protected resources.",
                )
                return

    def _test_otp_bruteforce(self):
        url = self._challenge_url
        baseline = self.post(url, data={"otp": "837204"})
        for param in self.OTP_PARAMS:
            for otp in self.COMMON_OTPS:
                response = self.post(url, data={param: otp})
                if self._is_authed(response) and not self._is_authed(baseline):
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"Predictable 2FA OTP accepted: '{otp}'",
                        url=url,
                        detail=f"OTP '{otp}' via parameter '{param}' completed the active challenge.",
                        payload=otp,
                        remediation=(
                            "Generate unpredictable OTPs, expire them promptly, and rate-limit attempts."
                        ),
                    )
                    return

    def _test_param_bypass(self):
        for path in self.PROTECTED_PATHS:
            baseline = self._protected_baselines.get(path)
            if not self._is_gated(baseline):
                continue
            for bypass in ["skip_2fa=1", "bypass=true", "no_mfa=1", "admin=true"]:
                r = self.get(self.url(path) + "?" + bypass)
                if self._is_authed(r):
                    self.add_finding(
                        severity="HIGH",
                        title=f"2FA bypass via query parameter: {bypass}",
                        url=self.url(path) + "?" + bypass,
                        detail=f"Adding '{bypass}' skipped the 2FA check.",
                        remediation="Never use client-supplied parameters to skip security checks.",
                    )
                    return
