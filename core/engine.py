import importlib
from typing import List

from config.settings import Settings
from core.logger import Logger
from core.results import ScanResults
from modules.base import BaseModule


MODULE_MAP = {
    "recon":      "modules.recon",
    "sqli":       "modules.sqli",
    "xss":        "modules.xss",
    "auth":       "modules.auth",
    "idor":       "modules.idor",
    "upload":     "modules.upload",
    "lfi":        "modules.lfi",
    "ssrf":       "modules.ssrf",
    "xxe":        "modules.xxe",
    "ssti":       "modules.ssti",
    "nosql":      "modules.nosql",
    "cors":       "modules.cors",
    "jwt":        "modules.jwt",
    "waf":        "modules.waf",
    "csrf":       "modules.csrf",
    "desync":     "modules.desync",
    "race":       "modules.race",
    "ratelimit":  "modules.ratelimit",
    "websocket":  "modules.websocket",
    "graphql":    "modules.graphql",
    "2fa":        "modules.twofa",
    "captcha":    "modules.captcha",
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
        mod_path = MODULE_MAP[name]
        mod = importlib.import_module(mod_path)
        cls_name = "".join(part.capitalize() for part in name.split("_")) + "Module"
        cls_name = cls_name.replace("2fa", "Twofa").replace("Twofa", "TwofaModule")
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
