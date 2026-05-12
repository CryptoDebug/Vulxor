import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from modules.base import BaseModule


class IdorModule(BaseModule):
    NAME = "idor"
    DESCRIPTION = "IDOR - parameter ID brute-forcing for unauthorised access"

    ENDPOINTS = [
        "/profile?id=", "/user?id=", "/account?id=",
        "/order?id=", "/invoice?id=", "/document?id=",
        "/api/user/", "/api/account/", "/api/order/",
        "/admin/user?id=", "/admin/account?id=",
    ]

    def run(self):
        self.log.info("[idor] Testing for IDOR vulnerabilities")
        self._probe_numeric_ids()

    def _probe_numeric_ids(self):
        for endpoint in self._candidate_endpoints():
            base = self.get(self._object_url(endpoint, 0))
            if not base or base.status_code not in (403, 404):
                continue
            base_len = len(base.text)
            miss = self.get(self._object_url(endpoint, 999999))
            miss_len = len(miss.text) if miss else base_len
            for obj_id in range(1, 21):
                resp = self.get(self._object_url(endpoint, obj_id))
                if not resp:
                    continue
                differs_from_missing = abs(len(resp.text) - base_len) > 50 and abs(len(resp.text) - miss_len) > 50
                if resp.status_code == 200 and differs_from_missing:
                    self.add_finding(
                        severity="HIGH",
                        title="Potential IDOR",
                        url=self._object_url(endpoint, obj_id),
                        detail=f"Object ID {obj_id} returned HTTP 200 "
                               f"({len(resp.text)} bytes).",
                        payload=str(obj_id),
                        remediation=(
                            "Validate that the authenticated user owns the requested "
                            "object before returning data."
                        ),
                    )
                    break

    def _candidate_endpoints(self):
        candidates = [{"kind": "prefix", "value": endpoint} for endpoint in self.ENDPOINTS]
        crawl = self.results.meta.get("crawl", {})
        for page in crawl.get("pages", []):
            url = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for key in params:
                if self._looks_object_param(key):
                    candidates.append({"kind": "query", "url": url, "param": key})
            if re.search(r"/\d+(?:/)?$", parsed.path):
                candidates.append({"kind": "path", "url": url})

        seen = set()
        out = []
        for item in candidates:
            key = tuple(sorted(item.items()))
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out[:30]

    def _object_url(self, endpoint, obj_id):
        if endpoint["kind"] == "prefix":
            return self.url(endpoint["value"] + str(obj_id))

        parsed = urlparse(endpoint["url"])
        if endpoint["kind"] == "query":
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[endpoint["param"]] = [str(obj_id)]
            return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        path = re.sub(r"/\d+(?:/)?$", f"/{obj_id}", parsed.path)
        return urlunparse(parsed._replace(path=path, query=""))

    def _looks_object_param(self, name):
        return name.lower() in {"id", "user", "user_id", "uid", "account", "order", "invoice", "document", "file"}
