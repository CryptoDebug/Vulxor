import re
import socket
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule


class ReconModule(BaseModule):
    NAME = "recon"
    DESCRIPTION = "Reconnaissance - headers, tech detection, robots.txt, sitemap, subdomains"

    TECH_SIGNATURES = {
        "WordPress":   [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal":      [r"Drupal", r"/sites/default/"],
        "Joomla":      [r"Joomla", r"/components/com_"],
        "Laravel":     [r"laravel_session", r"XSRF-TOKEN"],
        "Django":      [r"csrfmiddlewaretoken", r"Django"],
        "Rails":       [r"_session_id", r"X-Powered-By: Phusion Passenger"],
        "ASP.NET":     [r"__VIEWSTATE", r"ASP.NET", r"X-AspNet-Version"],
        "PHP":         [r"X-Powered-By: PHP", r"PHPSESSID"],
        "React":       [r"react", r"__NEXT_DATA__"],
        "Angular":     [r"ng-version", r"angular"],
        "jQuery":      [r"jquery"],
        "Bootstrap":   [r"bootstrap"],
        "Cloudflare":  [r"cf-ray", r"cloudflare"],
        "nginx":       [r"nginx"],
        "Apache":      [r"Apache"],
        "IIS":         [r"Microsoft-IIS", r"X-Powered-By: ASP.NET"],
    }

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "app", "blog", "shop", "cdn", "static", "assets", "portal",
        "login", "auth", "dashboard", "docs", "help", "support",
        "vpn", "remote", "intranet", "internal", "secure", "beta",
    ]

    def run(self):
        self.log.info(f"[recon] Starting reconnaissance on {self.target}")
        self._check_whois()
        self._check_headers()
        self._detect_tech()
        self._check_robots()
        self._check_sitemap()
        self._check_security_txt()
        self._enumerate_subdomains()
        self._check_common_files()

    def _check_whois(self):
        from urllib.parse import urlparse
        host = urlparse(self.target).hostname
        if not host:
            return

        try:
            import whois
            w = whois.whois(host)
            if w:
                registrar = w.get('registrar', 'Unknown')
                creation_date = w.get('creation_date', 'Unknown')
                expiration_date = w.get('expiration_date', 'Unknown')
                name_servers = w.get('name_servers', [])

                detail = f"Registrar: {registrar}\nCreated: {creation_date}\nExpires: {expiration_date}"
                if name_servers:
                    detail += f"\nName servers: {', '.join(name_servers)}"

                self.add_finding(
                    severity="INFO",
                    title="WHOIS information",
                    url=self.target,
                    detail=detail,
                    remediation="Review domain registration details for potential social engineering targets."
                )
        except ImportError:
            self.log.debug("[recon] python-whois not installed, skipping WHOIS")
        except Exception as e:
            self.log.debug(f"[recon] WHOIS lookup failed: {e}")
    def _check_headers(self):
        resp = self.get(self.target)
        if not resp:
            return

        security_headers = {
            "Content-Security-Policy":   "CSP missing - XSS risk increased",
            "X-Frame-Options":           "Clickjacking protection missing",
            "X-Content-Type-Options":    "MIME-sniffing protection missing",
            "Referrer-Policy":           "Referrer policy not set",
            "Permissions-Policy":        "Permissions policy not set",
        }
        if urlparse(self.target).scheme == "https":
            security_headers["Strict-Transport-Security"] = (
                "HSTS missing - susceptible to protocol downgrade"
            )
        for header, detail in security_headers.items():
            if header not in resp.headers:
                self.add_finding(
                    severity="LOW",
                    title=f"Missing security header: {header}",
                    url=self.target,
                    detail=detail,
                    remediation=f"Add '{header}' to all HTTP responses.",
                )

        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = resp.headers.get(hdr)
            if val:
                self.add_finding(
                    severity="INFO",
                    title=f"Server version disclosed: {hdr}",
                    url=self.target,
                    detail=f"{hdr}: {val}",
                    remediation="Remove or obscure version disclosure headers.",
                )

    def _detect_tech(self):
        resp = self.get(self.target)
        if not resp:
            return
        body = resp.text
        all_headers = str(resp.headers)
        haystack = body + all_headers

        detected = []
        for tech, patterns in self.TECH_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, haystack, re.IGNORECASE):
                    detected.append(tech)
                    break

        if detected:
            self.add_finding(
                severity="INFO",
                title="Technology stack detected",
                url=self.target,
                detail=f"Detected: {', '.join(detected)}",
                remediation="Minimise version information in responses.",
            )
            self.results.meta["technologies"] = detected

    def _check_robots(self):
        resp = self.get("/robots.txt")
        if not resp or resp.status_code != 200 or self.is_probable_not_found(resp):
            return

        disallowed = re.findall(r"Disallow:\s*(.+)", resp.text)
        interesting = [p.strip() for p in disallowed if any(
            kw in p.lower() for kw in ["admin", "backup", "config", "api", "secret", "private", "db"]
        )]
        if interesting:
            self.add_finding(
                severity="INFO",
                title="Sensitive paths in robots.txt",
                url=self.url("/robots.txt"),
                detail=f"Interesting disallowed paths: {', '.join(interesting)}",
                remediation="Do not rely on robots.txt to hide sensitive paths.",
            )

    def _check_sitemap(self):
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            resp = self.get(path)
            if resp and resp.status_code == 200 and not self.is_probable_not_found(resp) and "<url" in resp.text:
                urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
                self.add_finding(
                    severity="INFO",
                    title=f"Sitemap found ({len(urls)} URLs)",
                    url=self.url(path),
                    detail=f"Sitemap contains {len(urls)} URLs.",
                )
                self.results.meta["sitemap_urls"] = urls[:50]
                break

    def _check_security_txt(self):
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = self.get(path)
            if resp and resp.status_code == 200 and not self.is_probable_not_found(resp):
                self.add_finding(
                    severity="INFO",
                    title="security.txt found",
                    url=self.url(path),
                    detail="Disclosure policy or contacts may be available.",
                )
                break

    def _enumerate_subdomains(self):
        from urllib.parse import urlparse
        host = urlparse(self.target).hostname
        if not host:
            return

        base_domain = host.lstrip("www.")
        found = []
        for sub in self.COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{base_domain}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
                self.log.debug(f"[recon] subdomain alive: {fqdn}")
            except socket.gaierror:
                pass

        if found:
            self.add_finding(
                severity="INFO",
                title=f"Subdomains discovered ({len(found)})",
                url=self.target,
                detail=f"Live subdomains: {', '.join(found)}",
            )
            self.results.meta["subdomains"] = found

    def _check_common_files(self):
        sensitive_paths = [
            "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
            "/backup.zip", "/backup.sql", "/db.sql", "/database.sql",
            "/.htaccess", "/.htpasswd", "/phpinfo.php", "/info.php",
            "/composer.json", "/package.json", "/.DS_Store",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/api/swagger.json", "/swagger.json", "/openapi.json",
            "/api-docs", "/.well-known/openid-configuration",
        ]
        for path in sensitive_paths:
            resp = self.get(path)
            if resp and resp.status_code == 200 and resp.content and not self.is_probable_not_found(resp):
                self.add_finding(
                    severity="HIGH",
                    title=f"Sensitive file exposed: {path}",
                    url=self.url(path),
                    detail=f"File accessible (HTTP 200, {len(resp.content)} bytes).",
                    evidence=resp.text[:300],
                    remediation=f"Restrict access to {path} via web server configuration.",
                )
