import re
from modules.base import BaseModule


class CaptchaModule(BaseModule):
    NAME = "captcha"
    DESCRIPTION = "CAPTCHA bypass - omission, empty value, fixed values, header tricks"

    def run(self):
        self.log.info("[captcha] Testing CAPTCHA bypass vectors")
        login_url = self._find_form_with_captcha()
        if not login_url:
            self.log.debug("[captcha] No CAPTCHA-protected form detected")
            return
        self._test_bypass(login_url)

    def _find_form_with_captcha(self):
        resp = self.get(self.target)
        if not resp:
            return None
        has_captcha = bool(re.search(
            r"recaptcha|captcha|g-recaptcha|hcaptcha|turnstile",
            resp.text, re.I
        ))
        if has_captcha:
            return self.target
        r2 = self.get(self.url("/login"))
        if r2 and re.search(r"captcha", r2.text, re.I):
            return self.url("/login")
        return None

    def _test_bypass(self, url: str):
        resp0 = self.get(url)
        if not resp0:
            return
        csrf = None
        m = re.search(
            r'<input[^>]+name=["\'](?:csrf[_-]?token|_token)["\'][^>]+value=["\']([^"\']+)["\']',
            resp0.text, re.I
        )
        if m:
            csrf = m.group(1)

        base_data = {"username": "admin", "password": "password"}
        if csrf:
            base_data["csrf_token"] = csrf

        def success(r):
            return bool(r and any(
                kw in r.text.lower() for kw in ["dashboard", "logout", "welcome"]
            ))

        if success(self.post(url, data=base_data)):
            self.add_finding(
                severity="MEDIUM",
                title="CAPTCHA bypass - field omitted",
                url=url,
                detail="Login succeeded without sending any CAPTCHA parameter.",
                remediation="Reject requests that do not include a valid CAPTCHA token.",
            )
            return

        data = {**base_data, "g-recaptcha-response": ""}
        if success(self.post(url, data=data)):
            self.add_finding(
                severity="MEDIUM",
                title="CAPTCHA bypass - empty token accepted",
                url=url,
                detail="Login succeeded with empty 'g-recaptcha-response'.",
                remediation="Validate CAPTCHA token server-side on every submission.",
            )
            return

        for val in ["test", "bypass", "1", "true", "AAAA"]:
            data = {**base_data, "g-recaptcha-response": val}
            if success(self.post(url, data=data)):
                self.add_finding(
                    severity="HIGH",
                    title=f"CAPTCHA bypass - fixed value '{val}' accepted",
                    url=url,
                    detail="CAPTCHA validation appears to be client-side only.",
                    remediation="Always verify CAPTCHA tokens with the provider's server-side API.",
                )
                return

        r = self.post(url, data=base_data, headers={"X-Forwarded-For": "127.0.0.1"})
        if success(r):
            self.add_finding(
                severity="MEDIUM",
                title="CAPTCHA bypass via X-Forwarded-For: 127.0.0.1",
                url=url,
                detail="Forging a local IP in X-Forwarded-For skipped CAPTCHA.",
                remediation="Do not skip CAPTCHA based on IP address or trusted headers.",
            )
