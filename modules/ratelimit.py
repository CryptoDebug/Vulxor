import threading
import re
from urllib.parse import urljoin

from modules.base import BaseModule


class RatelimitModule(BaseModule):
    NAME = "ratelimit"
    DESCRIPTION = "Rate-limit testing - parallel requests, header bypass"
    LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/auth/login", "/account"]

    def run(self):
        self.log.info("[ratelimit] Testing rate limiting on login endpoint")
        login = self._find_login()
        if not login:
            self.log.debug("[ratelimit] No password form detected; skipping login rate-limit test")
            return
        login_url, user_field, password_field = login
        request_count = 30 if self.settings.is_aggressive() else 12
        preflight = self.post(login_url, data={
            user_field: "vulxor-rate-limit-test",
            password_field: "wrong-preflight",
        })
        if preflight is None or preflight.status_code in (404, 405, 501) or \
                preflight.status_code >= 500:
            self.log.debug("[ratelimit] Login submission endpoint did not produce a usable response")
            return
        if self.is_probable_not_found(preflight):
            self.log.debug("[ratelimit] Login submission endpoint is a probable soft 404")
            return
        results = [None] * request_count
        threads = []

        def req(i):
            r = self.post(login_url, data={
                user_field: "vulxor-rate-limit-test",
                password_field: f"wrong-{i}",
            })
            results[i] = r.status_code if r is not None else 0

        for i in range(request_count):
            t = threading.Thread(target=req, args=(i,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        meaningful = [
            status for status in results
            if 100 <= status < 500 and status not in (404, 405)
        ]
        if not meaningful:
            self.log.debug("[ratelimit] Discovered form action did not accept login submissions")
            return

        block_statuses = {423, 429}
        if preflight.status_code != 403:
            block_statuses.add(403)
        blocked = sum(1 for status in results if status in block_statuses)
        if blocked == 0:
            self.add_finding(
                severity="LOW",
                title="No observable authentication throttling",
                url=login_url,
                detail=(f"{request_count} consecutive failed submissions produced no "
                        "HTTP 429, 423, or 403 response. Application-level controls may still exist."),
                remediation=(
                    "Implement account lockout or exponential backoff. "
                    "Add CAPTCHA after N failures."
                ),
            )

            return

        control = self.post(login_url, data={
            user_field: "vulxor-rate-limit-test",
            password_field: "wrong-control",
        })
        if control is None or control.status_code not in block_statuses:
            return

        for hdr, val in [("X-Forwarded-For", "192.0.2.10"), ("X-Real-IP", "192.0.2.10")]:
            r = self.post(login_url,
                          data={user_field: "vulxor-rate-limit-test",
                                password_field: "wrong-header"},
                          headers={hdr: val})
            if r is not None and r.status_code not in block_statuses:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"Rate-limit bypass via {hdr}",
                    url=login_url,
                    detail=f"Forging '{hdr}: {val}' resets the rate counter.",
                    remediation="Do not trust proxy headers for rate-limit key calculation.",
                )
                break

    def _find_login(self):
        for form in self.results.meta.get("crawl", {}).get("forms", []):
            if not form.get("has_password"):
                continue
            action = form.get("action") or self.target
            url = action if action.startswith("http") else urljoin(self.target + "/", action)
            user_field, password_field = self._field_names(form.get("inputs", []))
            return url, user_field, password_field

        for path in self.LOGIN_PATHS:
            response = self.get(path)
            if response is None or response.status_code != 200:
                continue
            if self.is_probable_not_found(response):
                continue
            if not re.search(r'<input\b[^>]*\btype=["\']password["\']', response.text, re.I):
                continue
            action = re.search(r'<form\b[^>]*\baction=["\']([^"\']*)["\']', response.text, re.I)
            inputs = re.findall(r'<input\b[^>]*\bname=["\']([^"\']+)["\']', response.text, re.I)
            login_url = urljoin(response.url or self.url(path), action.group(1)) \
                if action else (response.url or self.url(path))
            user_field, password_field = self._field_names(inputs)
            return login_url, user_field, password_field
        return None

    def _field_names(self, inputs):
        user_field = "username"
        password_field = "password"
        for name in inputs:
            low = name.casefold()
            if low in ("user", "username", "email", "login", "userid"):
                user_field = name
            if "pass" in low or low in ("pwd", "password"):
                password_field = name
        return user_field, password_field
