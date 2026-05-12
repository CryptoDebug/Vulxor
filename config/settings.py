from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class Settings:
    target: str
    modules: List[str] = field(default_factory=lambda: ["all"])
    threads: int = 10
    timeout: int = 10
    proxy: Optional[str] = None
    cookies: Optional[str] = None
    headers: Optional[str] = None
    auth: Optional[str] = None
    wordlist: Optional[str] = None
    delay: float = 0.0
    verbose: bool = False
    output_dir: str = "reports"
    report_format: str = "all"

    # Derived Attriubtes
    def parsed_cookies(self) -> Dict[str, str]:
        if not self.cookies:
            return {}
        return dict(
            pair.strip().split("=", 1)
            for pair in self.cookies.split(";")
            if "=" in pair
        )

    def parsed_headers(self) -> Dict[str, str]:
        if not self.headers:
            return {}
        result = {}
        for pair in self.headers.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                result[k.strip()] = v.strip()
        return result

    def proxies(self):
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}
