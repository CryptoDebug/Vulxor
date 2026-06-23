import hashlib
import re
import threading
import time
import uuid
import requests
from abc import ABC, abstractmethod
from difflib import SequenceMatcher
from typing import Optional, Dict, Any
from urllib.parse import urljoin

from config.settings import Settings
from core.logger import Logger
from core.results import ScanResults, Finding


class BaseModule(ABC):
    NAME: str = "base"
    DESCRIPTION: str = ""
    MISSING_PAGE_MARKERS = (
        "404",
        "not found",
        "page not found",
        "does not exist",
        "doesn't exist",
        "introuvable",
        "non trouve",
        "non trouvé",
        "page inexistante",
    )

    def __init__(self, settings: Settings, log: Logger, results: ScanResults):
        self.settings = settings
        self.log = log
        self.results = results
        self.target = settings.target.rstrip("/")
        self.session = self._build_session()
        self._missing_baselines = None
        self._missing_baselines_lock = threading.Lock()

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

    def is_probable_not_found(self, response: requests.Response) -> bool:
        if not response:
            return False
        if response.status_code in (404, 410):
            return True
        if response.status_code != 200 or not self.settings.filter_soft_404:
            return False

        candidate = self._response_signature(response)
        for baseline in self._get_missing_baselines():
            if baseline["status"] != 200:
                continue
            if candidate["content_type"] and baseline["content_type"]:
                if candidate["content_type"] != baseline["content_type"]:
                    continue
            if not self._similar_length(candidate["length"], baseline["length"]):
                continue
            if candidate["digest"] == baseline["digest"]:
                return True
            if not candidate["normalized"] or not baseline["normalized"]:
                continue

            ratio = SequenceMatcher(
                None,
                candidate["normalized"],
                baseline["normalized"],
                autojunk=False,
            ).ratio()
            if ratio >= 0.96:
                return True
            if ratio >= 0.90 and candidate["has_missing_marker"] and baseline["has_missing_marker"]:
                return True
        return False

    def _get_missing_baselines(self):
        if self._missing_baselines is not None:
            return self._missing_baselines

        with self._missing_baselines_lock:
            if self._missing_baselines is not None:
                return self._missing_baselines

            probes = [
                f"/__vulxor_missing_{uuid.uuid4().hex}",
                f"/__vulxor_missing_{uuid.uuid4().hex}.html",
                f"/{uuid.uuid4().hex}/__vulxor_missing",
            ]
            baselines = []
            for path in probes:
                response = self._request("GET", path, allow_redirects=False)
                if response:
                    baselines.append(self._response_signature(response))
            self._missing_baselines = baselines
            return self._missing_baselines

    def _response_signature(self, response: requests.Response) -> Dict[str, Any]:
        text = response.text if self._is_text_response(response) else ""
        normalized = self._normalize_for_soft_404(text)
        return {
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type", "").split(";")[0].lower(),
            "length": len(response.content or b""),
            "normalized": normalized,
            "digest": hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest(),
            "has_missing_marker": self._has_missing_marker(normalized),
        }

    def _normalize_for_soft_404(self, text: str) -> str:
        text = text[:20000].lower()
        text = re.sub(r"__vulxor[_a-z0-9/-]+", "__vulxor_token", text)
        text = re.sub(r"https?://\S+", "url", text)
        text = re.sub(r"\b[a-f0-9]{12,}\b", "token", text)
        text = re.sub(r"\b\d+\b", "number", text)
        return re.sub(r"\s+", " ", text).strip()

    def _has_missing_marker(self, normalized: str) -> bool:
        return any(marker in normalized for marker in self.MISSING_PAGE_MARKERS)

    def _is_text_response(self, response: requests.Response) -> bool:
        content_type = response.headers.get("Content-Type", "").lower()
        return (
            content_type.startswith("text/")
            or "html" in content_type
            or "json" in content_type
            or "xml" in content_type
        )

    def _similar_length(self, candidate_length: int, baseline_length: int) -> bool:
        delta = abs(candidate_length - baseline_length)
        tolerance = max(120, int(max(candidate_length, baseline_length) * 0.20))
        return delta <= tolerance

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
