import time
import requests
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlparse

from config.settings import Settings
from core.logger import Logger
from core.results import ScanResults, Finding


class BaseModule(ABC):
    NAME: str = "base"
    DESCRIPTION: str = ""

    def __init__(self, settings: Settings, log: Logger, results: ScanResults):
        self.settings = settings
        self.log = log
        self.results = results
        self.target = settings.target.rstrip("/")
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.cookies.update(self.settings.parsed_cookies())
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        session.headers.update(self.settings.parsed_headers())
        if self.settings.auth:
            user, passwd = self.settings.auth.split(":", 1)
            session.auth = (user, passwd)
        return session

    def get(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Optional[requests.Response]:
        return self._request("POST", path, **kwargs)

    def _request(
        self,
        method: str,
        url: str,
        params: Dict = None,
        data: Dict = None,
        json: Any = None,
        headers: Dict = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        if not url.startswith("http"):
            url = urljoin(self.target + "/", url.lstrip("/"))
        try:
            if self.settings.delay > 0:
                time.sleep(self.settings.delay)
            response = self.session.request(
                method,
                url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                timeout=self.settings.timeout,
                proxies=self.settings.proxies(),
                verify=False,
                allow_redirects=allow_redirects,
            )
            self.log.debug(f"{method} {url} → {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            self.log.debug(f"{method} {url} → ERROR: {e}")
            return None

    def add_finding(
        self,
        severity: str,
        title: str,
        url: str,
        detail: str,
        payload: str = None,
        evidence: str = None,
        remediation: str = None,
    ):
        f = Finding(
            module=self.NAME,
            severity=severity,
            title=title,
            url=url,
            detail=detail,
            payload=payload,
            evidence=evidence,
            remediation=remediation,
        )
        self.results.add(f)
        self.log.finding(severity, title, detail)

    def url(self, path: str = "") -> str:
        return self.target + ("/" + path.lstrip("/") if path else "")

    @abstractmethod
    def run(self):
        ...
