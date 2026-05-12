import importlib
from typing import List

from config.settings import Settings
from core.logger import Logger
from core.results import ScanResults
from modules.base import BaseModule


MODULE_MAP = {
    "recon":      ("modules.recon", "ReconModule"),
    "sqli":       ("modules.sqli", "SqliModule"),
    "xss":        ("modules.xss", "XssModule"),
    "auth":       ("modules.auth", "AuthModule"),
    "idor":       ("modules.idor", "IdorModule"),
    "crawl":      ("modules.crawl", "CrawlModule"),
    "tools":      ("modules.tools", "ToolsModule"),
    "upload":     ("modules.upload", "UploadModule"),
    "lfi":        ("modules.lfi", "LfiModule"),
    "ssrf":       ("modules.ssrf", "SsrfModule"),
    "xxe":        ("modules.xxe", "XxeModule"),
    "ssti":       ("modules.ssti", "SstiModule"),
    "nosql":      ("modules.nosql", "NosqlModule"),
    "cors":       ("modules.cors", "CorsModule"),
    "jwt":        ("modules.jwt", "JwtModule"),
    "waf":        ("modules.waf", "WafModule"),
    "csrf":       ("modules.csrf", "CsrfModule"),
    "desync":     ("modules.desync", "DesyncModule"),
    "race":       ("modules.race", "RaceModule"),
    "ratelimit":  ("modules.ratelimit", "RatelimitModule"),
    "websocket":  ("modules.websocket", "WebsocketModule"),
    "graphql":    ("modules.graphql", "GraphqlModule"),
    "2fa":        ("modules.twofa", "TwofaModule"),
    "captcha":    ("modules.captcha", "CaptchaModule"),
}


class Engine:
    def __init__(self, settings: Settings, log: Logger):
        self.settings = settings
        self.log = log
        self.results = ScanResults(target=settings.target)

    def _resolve_modules(self) -> List[str]:
        if "all" in self.settings.modules:
            return list(MODULE_MAP.keys())
        return self.settings.modules

    def _load_module(self, name: str) -> BaseModule:
        mod_path, cls_name = MODULE_MAP[name]
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, cls_name)
        return cls(self.settings, self.log, self.results)

    def run(self) -> ScanResults:
        module_names = self._resolve_modules()
        total = len(module_names)

        for i, name in enumerate(module_names, 1):
            self.log.progress(i, total, name)
            try:
                module = self._load_module(name)
                module.run()
            except ImportError as e:
                self.log.warn(f"Module '{name}' not found: {e}")
            except Exception as e:
                self.log.error(f"Module '{name}' crashed: {e}")
                if self.settings.verbose:
                    import traceback
                    traceback.print_exc()

        return self.results
