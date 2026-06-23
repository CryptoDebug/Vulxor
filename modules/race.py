import threading
from modules.base import BaseModule


class RaceModule(BaseModule):
    NAME = "race"
    DESCRIPTION = "Race condition testing on discount/voucher endpoints"

    RACE_PATHS = ["/voucher", "/coupon", "/promo", "/discount",
                  "/redeem", "/api/voucher", "/api/redeem"]

    def run(self):
        self.log.info("[race] Testing for race conditions")
        for path in self.RACE_PATHS:
            self._race_test(self.url(path))

    def _race_test(self, url: str, n: int = 15):
        preflight = self.post(url, data={"code": "VULXOR-NOT-A-REAL-CODE"})
        if preflight is None or self.is_probable_not_found(preflight):
            self.log.debug(f"[race] filtered probable soft 404: {url}")
            return
        results = [None] * n
        threads = []

        def req(i):
            r = self.post(url, data={"code": "TESTCODE"})
            results[i] = (r.status_code, r.text[:80]) if r else (0, "")

        for i in range(n):
            threads.append(threading.Thread(target=req, args=(i,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r and r[0] == 200 and
                     any(kw in r[1].lower() for kw in ["success", "applied", "discount"])]
        if len(successes) > 1:
            self.add_finding(
                severity="HIGH",
                title="Race condition - double spend",
                url=url,
                detail=f"{len(successes)}/{n} parallel requests succeeded on the same voucher.",
                remediation=(
                    "Use database-level atomic operations (SELECT ... FOR UPDATE) "
                    "or idempotency keys to prevent double-spend."
                ),
            )
