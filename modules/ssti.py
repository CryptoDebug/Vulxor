from modules.base import BaseModule
from modules.evidence import new_regex_evidence


class SstiModule(BaseModule):
    NAME = "ssti"
    DESCRIPTION = "SSTI testing - Jinja2, Twig, Smarty, FreeMarker, Pebble"
    PROBES = [
        ("Jinja2/Twig",       ("{{1337*7}}", "9359"), ("{{7331*3}}", "21993")),
        ("FreeMarker/Pebble", ("${1337*7}", "9359"),  ("${7331*3}", "21993")),
        ("Ruby ERB / Pebble", ("#{1337*7}", "9359"),  ("#{7331*3}", "21993")),
        ("Smarty",            ("{1337*7}", "9359"),   ("{7331*3}", "21993")),
        ("ERB",               ("<%= 1337*7 %>", "9359"), ("<%= 7331*3 %>", "21993")),
        ("Razor",             ("@(1337*7)", "9359"),  ("@(7331*3)", "21993")),
        ("Thymeleaf",         ("[[${1337*7}]]", "9359"), ("[[${7331*3}]]", "21993")),
        ("Thymeleaf",         ("*{1337*7}", "9359"),  ("*{7331*3}", "21993")),
    ]

    PARAMS = ["name", "search", "q", "query", "template", "content",
              "message", "title", "subject", "lang", "page"]

    def run(self):
        self.log.info("[ssti] Testing for template injection")
        for param in self.PARAMS:
            baseline = self.get(self.target, params={param: "vulxor_ssti_baseline"})
            if not baseline:
                continue
            for engine, first, second in self.PROBES:
                first_resp = self.get(self.target, params={param: first[0]})
                second_resp = self.get(self.target, params={param: second[0]})
                if self._evaluated(baseline, first_resp, first[1]) and \
                        self._evaluated(baseline, second_resp, second[1]):
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"Server-Side Template Injection ({engine})",
                        url=self.target,
                        detail=(f"Parameter '{param}' evaluated two independent "
                                f"expressions as {first[1]} and {second[1]}."),
                        payload=f"{first[0]} / {second[0]}",
                        evidence=f"Observed results: {first[1]}, {second[1]}",
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxed environments or strict output escaping."
                        ),
                    )
                    return

    def _evaluated(self, baseline, response, expected: str) -> bool:
        if not response or response.status_code >= 400:
            return False
        return bool(new_regex_evidence(
            baseline.text,
            response.text,
            [rf"(?<!\d){expected}(?!\d)"],
            flags=0,
        ))
