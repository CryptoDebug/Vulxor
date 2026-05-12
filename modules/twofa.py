from modules.base import BaseModule


class TwofaModule(BaseModule):
    NAME = "2fa"
    DESCRIPTION = "2FA bypass - direct page access, cookie manipulation, brute-force OTP"

    PROTECTED_PATHS = ["/dashboard", "/admin", "/profile", "/settings", "/account"]
    TWO_FA_PATHS    = ["/verify", "/2fa", "/otp", "/verify-otp", "/mfa"]
    OTP_PARAMS      = ["code", "token", "otp", "totp", "2fa_code", "verification_code"]
    COMMON_OTPS     = ["000000", "111111", "123456", "654321", "999999", "123123"]

    def run(self):
        self.log.info("[2fa] Testing 2FA bypass vectors")
        self.post(self.url("/login"),
                  data={"username": "admin", "password": "password"})

        self._test_direct_access()
        self._test_otp_bruteforce()
        self._test_param_bypass()

    def _is_protected(self, resp) -> bool:
        """Returns True if response looks like it's behind 2FA (not fully authed)."""
        if not resp:
            return True
        low = resp.text.lower()
        return any(kw in low for kw in ["verify", "otp", "two-factor", "2fa", "mfa"])

    def _is_authed(self, resp) -> bool:
        if not resp:
            return False
        low = resp.text.lower()
        return any(kw in low for kw in ["dashboard", "logout", "welcome", "profile"])

    def _test_direct_access(self):
        for path in self.PROTECTED_PATHS:
            r = self.get(self.url(path))
            if self._is_authed(r) and not self._is_protected(r):
                self.add_finding(
                    severity="HIGH",
                    title="2FA bypass - direct page access",
                    url=self.url(path),
                    detail=f"Page '{path}' accessible without completing 2FA step.",
                    remediation="Enforce 2FA gate on every request to protected resources.",
                )

    def _test_otp_bruteforce(self):
        for path in self.TWO_FA_PATHS:
            url = self.url(path)
            r = self.get(url)
            if not r or r.status_code != 200:
                continue
            for param in self.OTP_PARAMS:
                for otp in self.COMMON_OTPS:
                    r2 = self.post(url, data={param: otp})
                    if self._is_authed(r2):
                        self.add_finding(
                            severity="CRITICAL",
                            title=f"2FA OTP accepted without rate-limit: '{otp}'",
                            url=url,
                            detail=f"OTP '{otp}' via param '{param}' was accepted.",
                            payload=otp,
                            remediation=(
                                "Rate-limit OTP attempts. Expire codes after 5 minutes. "
                                "Lock account after N failed attempts."
                            ),
                        )
                        return

    def _test_param_bypass(self):
        for path in self.PROTECTED_PATHS:
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
