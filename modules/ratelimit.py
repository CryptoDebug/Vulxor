import threading
import time
from modules.base import BaseModule


class RatelimitModule(BaseModule):
    NAME = "ratelimit"
    DESCRIPTION = "Rate-limit testing - parallel requests, header bypass"

    def run(self):
        self.log.info("[ratelimit] Testing rate limiting on login endpoint")
        login_url = self.url("/login")
        results = [None] * 30
        threads = []

        def req(i):
            r = self.post(login_url, data={"username": "admin", "password": f"wrong{i}"})
            results[i] = r.status_code if r else 0

        for i in range(30):
            t = threading.Thread(target=req, args=(i,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        blocked = sum(1 for s in results if s in (429, 403))
        if blocked == 0:
            self.add_finding(
                severity="MEDIUM",
                title="No rate limiting on authentication endpoint",
                url=login_url,
                detail=f"30 consecutive failed logins - zero blocked (HTTP 429/403).",
                remediation=(
                    "Implement account lockout or exponential backoff. "
                    "Add CAPTCHA after N failures."
                ),
            )

        for hdr, val in [("X-Forwarded-For", "1.2.3.4"), ("X-Real-IP", "1.2.3.4")]:
            r = self.post(login_url,
                          data={"username": "admin", "password": "wrongpass"},
                          headers={hdr: val})
            if r and r.status_code == 200:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"Rate-limit bypass via {hdr}",
                    url=login_url,
                    detail=f"Forging '{hdr}: {val}' resets the rate counter.",
                    remediation="Do not trust proxy headers for rate-limit key calculation.",
                )
                break
