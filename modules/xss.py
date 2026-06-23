import html
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse
from modules.base import BaseModule


class _XssEvidenceParser(HTMLParser):
    URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href"}

    def __init__(self, marker: str, detect_script_body: bool):
        super().__init__(convert_charrefs=True)
        self.marker = marker.casefold()
        self.detect_script_body = detect_script_body
        self.in_script = False
        self.executable = False

    def handle_starttag(self, tag, attrs):
        if tag.casefold() == "script":
            self.in_script = True
        for name, value in attrs:
            name = (name or "").casefold()
            value = (value or "").casefold()
            if self.marker not in value:
                continue
            if name.startswith("on") or (
                name in self.URL_ATTRIBUTES and value.lstrip().startswith("javascript:")
            ):
                self.executable = True

    def handle_endtag(self, tag):
        if tag.casefold() == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.detect_script_body and self.in_script and self.marker in data.casefold():
            self.executable = True


class XssModule(BaseModule):
    NAME = "xss"
    DESCRIPTION = "XSS testing - reflected, stored indicators, DOM-based patterns"

    MARKER = "vulxor_xss_7f3a"
    PAYLOADS = [
        "</script><script>window.vulxor_xss_7f3a=1</script>",
        "\"><img src=x onerror=window.vulxor_xss_7f3a=1>",
        "\"><svg onload=window.vulxor_xss_7f3a=1>",
        "javascript:window.vulxor_xss_7f3a=1",
        "\"><iframe src=javascript:window.vulxor_xss_7f3a=1>",
        "\"><input autofocus onfocus=window.vulxor_xss_7f3a=1>",
        "';window.vulxor_xss_7f3a=1;//",
        "\"><details open ontoggle=window.vulxor_xss_7f3a=1>",
        "\"><video><source onerror=window.vulxor_xss_7f3a=1>",
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
            for param in self._param_candidates(url):
                for payload in self._payloads():
                    resp = self.get(url, params={param: payload})
                    if not resp:
                        continue
                    reflection = self._reflection_state(resp.text, payload)
                    if reflection == "executable":
                        self.add_finding(
                            severity="HIGH",
                            title="Reflected XSS",
                            url=url,
                            detail=f"Parameter '{param}' created an executable HTML/JavaScript context.",
                            payload=payload,
                            evidence=self._extract_context(resp.text, payload),
                            remediation="Escape all user-supplied output; implement a strict CSP.",
                        )
                        break

    def _test_forms(self):
        for form in self._crawl_forms():
            for payload in self._payloads(forms=True):
                data = {field: payload for field in form["inputs"]}
                target_url = form["action"]
                r = self.post(target_url, data=data) if form["method"] == "post" \
                    else self.get(target_url, params=data)
                if r and self._reflection_state(r.text, payload) == "executable":
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
            for payload in self._payloads(forms=True):
                data = {field: payload for field in form["inputs"]}
                target_url = self.url(form["action"])
                r = self.post(target_url, data=data) if form["method"] == "post" \
                    else self.get(target_url, params=data)
                if r and self._reflection_state(r.text, payload) == "executable":
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
        return out[:30 if self.settings.is_aggressive() else 12]

    def _param_candidates(self, url):
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        crawl = self.results.meta.get("crawl", {})
        for page in crawl.get("pages", []):
            if page.get("url") == url:
                params.extend(page.get("params", []))
        params.extend(self.COMMON_PARAMS)
        out = []
        seen = set()
        for param in params:
            if param and param not in seen:
                seen.add(param)
                out.append(param)
        return out[:24 if self.settings.is_aggressive() else 12]

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
        return forms[:20 if self.settings.is_aggressive() else 8]

    def _reflection_state(self, body, payload):
        if payload in body:
            parser = _XssEvidenceParser(
                marker=self.MARKER,
                detect_script_body=payload.casefold().startswith("</script>"),
            )
            try:
                parser.feed(body)
            except (AssertionError, ValueError):
                return "inert"
            return "executable" if parser.executable else "inert"
        escaped = html.escape(payload, quote=False)
        if escaped in body or html.escape(payload, quote=True) in body:
            return "escaped"
        return ""

    def _payloads(self, forms=False):
        if self.settings.is_aggressive():
            return self.PAYLOADS if not forms else self.PAYLOADS[:10]
        return self.PAYLOADS[:4]
