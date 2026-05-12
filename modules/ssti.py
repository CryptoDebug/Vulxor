from modules.base import BaseModule


class SstiModule(BaseModule):
    NAME = "ssti"
    DESCRIPTION = "SSTI testing - Jinja2, Twig, Smarty, FreeMarker, Pebble"
    PROBES = [
        ("{{7*7}}",          "49",  "Jinja2/Twig"),
        ("${7*7}",           "49",  "FreeMarker/Pebble"),
        ("#{7*7}",           "49",  "Ruby ERB / Pebble"),
        ("{7*7}",            "49",  "Smarty"),
        ("<%= 7*7 %>",       "49",  "ERB"),
        ("@(7*7)",           "49",  "Razor"),
        ("[[${7*7}]]",       "49",  "Thymeleaf"),
        ("*{7*7}",           "49",  "Thymeleaf"),
    ]

    PARAMS = ["name", "search", "q", "query", "template", "content",
              "message", "title", "subject", "lang", "page"]

    def run(self):
        self.log.info("[ssti] Testing for template injection")
        for param in self.PARAMS:
            for payload, expected, engine in self.PROBES:
                resp = self.get(self.target, params={param: payload})
                if resp and expected in resp.text:
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"Server-Side Template Injection ({engine})",
                        url=self.target,
                        detail=f"Parameter '{param}' evaluated '{payload}' → '{expected}'.",
                        payload=payload,
                        evidence=resp.text[:300],
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxed environments or strict output escaping."
                        ),
                    )
                    return
