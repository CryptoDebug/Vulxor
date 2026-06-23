import hashlib
import os
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urldefrag, urljoin, urlparse

from modules.base import BaseModule


class CrawlModule(BaseModule):
    NAME = "crawl"
    DESCRIPTION = "Site mapping - scoped crawling, forms, links, and wordlist path discovery"

    DEFAULT_WORDLIST = [
        "admin", "login", "logout", "dashboard", "account", "profile",
        "api", "api/v1", "api/v2", "graphql", "uploads", "files",
        "backup", "backups", "config", "private", "dev", "staging",
        ".env", ".git/HEAD", "robots.txt", "sitemap.xml",
        "swagger.json", "openapi.json", "api-docs", "phpinfo.php",
    ]
    INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
    SENSITIVE_HINTS = (
        ".env", ".git", "backup", "config", "dump", "db", "database",
        "secret", "private", "phpinfo", "swagger", "openapi",
    )

    def run(self):
        self.log.info("[crawl] Mapping in-scope pages and paths")
        pages, forms = self._crawl_pages()
        paths = self._discover_paths()
        stats = self._scan_stats(pages, forms, paths)

        self.results.meta["crawl"] = {
            "pages": pages,
            "forms": forms,
            "paths": paths,
            "stats": stats,
        }

        if pages:
            self.add_finding(
                severity="INFO",
                title=f"Crawl completed ({len(pages)} pages)",
                url=self.target,
                detail="Mapped pages: " + ", ".join(p["url"] for p in pages[:20]),
            )

        if forms:
            self.add_finding(
                severity="INFO",
                title=f"Forms discovered ({len(forms)})",
                url=self.target,
                detail="Form endpoints: " + ", ".join(f["action"] for f in forms[:20]),
            )

        if paths:
            self.add_finding(
                severity="INFO",
                title=f"Interesting paths discovered ({len(paths)})",
                url=self.target,
                detail=", ".join(f"{p['status']} {p['url']}" for p in paths[:20]),
                remediation="Review discovered paths and restrict anything outside the intended public surface.",
            )

    def _crawl_pages(self):
        max_pages = max(1, self.settings.max_pages)
        max_depth = max(0, self.settings.crawl_depth)
        queue = deque([(self.target, 0)])
        seen = set()
        pages = []
        forms = []

        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            url = self._clean_url(url)
            if not url or url in seen or not self._in_scope(url):
                continue
            seen.add(url)

            resp = self.get(url)
            if not resp:
                continue
            if self.is_probable_not_found(resp):
                self.log.debug(f"[crawl] filtered probable soft 404: {url}")
                continue

            content_type = resp.headers.get("Content-Type", "")
            page = {
                "url": url,
                "status": resp.status_code,
                "title": self._title(resp.text),
                "content_type": content_type.split(";")[0],
                "bytes": len(resp.content or b""),
                "fingerprint": self._fingerprint(resp),
                "params": self._query_params(url),
            }
            pages.append(page)

            if resp.status_code >= 400 or "html" not in content_type.lower():
                continue

            page_forms = self._parse_forms(resp.text, url)
            forms.extend(page_forms)

            if depth >= max_depth:
                continue

            for link in self._parse_links(resp.text, url):
                if link not in seen and self._in_scope(link):
                    queue.append((link, depth + 1))

        return pages, self._dedupe_forms(forms)

    def _discover_paths(self):
        words = self._load_wordlist()
        if not words:
            return []
        limit = 2000 if self.settings.is_aggressive() else 300
        words = words[:limit]

        max_workers = max(1, self.settings.threads)
        found = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(self._probe_path, word) for word in words]
            for future in as_completed(futures):
                item = future.result()
                if item:
                    found.append(item)

        found.sort(key=lambda item: (item["status"], item["url"]))
        for item in found:
            if item["status"] == 200 and self._looks_sensitive(item["url"]):
                self.add_finding(
                    severity="HIGH",
                    title="Sensitive path exposed",
                    url=item["url"],
                    detail=f"Wordlist discovery found an exposed path ({item['status']}, {item['bytes']} bytes).",
                    remediation="Remove the file from the web root or enforce strict access controls.",
                )
        return found

    def _probe_path(self, word):
        path = "/" + word.strip().lstrip("/")
        if not path or path == "/":
            return None
        resp = self.get(path, allow_redirects=False)
        if not resp or resp.status_code not in self.INTERESTING_STATUSES:
            return None
        if self.is_probable_not_found(resp):
            self.log.debug(f"[crawl] filtered probable soft 404: {self.url(path)}")
            return None
        return {
            "url": self.url(path),
            "status": resp.status_code,
            "bytes": len(resp.content or b""),
            "content_type": resp.headers.get("Content-Type", "").split(";")[0],
            "fingerprint": self._fingerprint(resp),
        }

    def _load_wordlist(self):
        path = self.settings.wordlist
        if not path:
            return self.DEFAULT_WORDLIST
        if not os.path.exists(path):
            self.log.warn(f"[crawl] Wordlist not found: {path}; using defaults")
            return self.DEFAULT_WORDLIST
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
        return words

    def _parse_links(self, html, base_url):
        links = set()
        for value in re.findall(r'\b(?:href|src)=["\']([^"\']+)["\']', html, re.I):
            if value.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            link = self._clean_url(urljoin(base_url, value))
            if link:
                links.add(link)
        return sorted(links)

    def _parse_forms(self, html, base_url):
        forms = []
        for form_html in re.findall(r"<form[^>]*>.*?</form>", html, re.I | re.S):
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I)
            forms.append({
                "page": base_url,
                "action": urljoin(base_url, action.group(1) if action else base_url),
                "method": (method.group(1) if method else "get").lower(),
                "inputs": sorted(set(inputs)),
                "has_password": bool(re.search(r'<input[^>]+type=["\']password["\']', form_html, re.I)),
                "has_csrf": bool(re.search(r'name=["\'](?:csrf[_-]?token|_token)["\']', form_html, re.I)),
            })
        return forms

    def _dedupe_forms(self, forms):
        seen = set()
        out = []
        for form in forms:
            key = (form["action"], form["method"], tuple(form["inputs"]))
            if key not in seen:
                seen.add(key)
                out.append(form)
        return out

    def _clean_url(self, url):
        url, _fragment = urldefrag(url)
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return parsed.geturl().rstrip("/")

    def _in_scope(self, url):
        target_host = urlparse(self.target).hostname
        candidate_host = urlparse(url).hostname
        return bool(target_host and candidate_host and candidate_host == target_host)

    def _title(self, html):
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if not match:
            return ""
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120]

    def _looks_sensitive(self, url):
        low = url.lower()
        return any(hint in low for hint in self.SENSITIVE_HINTS)

    def _scan_stats(self, pages, forms, paths):
        return {
            "pages_crawled": len(pages),
            "forms_discovered": len(forms),
            "paths_discovered": len(paths),
            "login_forms": len([f for f in forms if f.get("has_password")]),
            "protected_paths": len([p for p in paths if p.get("status") in (401, 403)]),
        }

    def _query_params(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return []
        return sorted({
            part.split("=", 1)[0]
            for part in parsed.query.split("&")
            if part.split("=", 1)[0]
        })

    def _fingerprint(self, resp):
        marker = "\n".join([
            str(resp.status_code),
            resp.headers.get("Content-Type", ""),
            str(len(resp.content or b"")),
            resp.text[:500] if hasattr(resp, "text") else "",
        ])
        return hashlib.sha256(marker.encode("utf-8", errors="ignore")).hexdigest()[:16]
