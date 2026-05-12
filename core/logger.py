import sys
from datetime import datetime


class Colors:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GREY   = "\033[90m"
    WHITE  = "\033[97m"


class Logger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._use_color = sys.stdout.isatty()

    def _color(self, text: str, color: str) -> str:
        if self._use_color:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _print(self, prefix: str, color: str, msg: str):
        ts = self._color(self._ts(), Colors.GREY)
        label = self._color(prefix, color)
        print(f"{ts} {label} {msg}")

    def info(self, msg: str):
        self._print("[*]", Colors.CYAN, msg)

    def success(self, msg: str):
        self._print("[+]", Colors.GREEN, msg)

    def warn(self, msg: str):
        self._print("[!]", Colors.YELLOW, msg)

    def error(self, msg: str):
        self._print("[-]", Colors.RED, msg)

    def debug(self, msg: str):
        if self.verbose:
            self._print("[~]", Colors.GREY, msg)

    def finding(self, severity: str, title: str, detail: str):
        sev_colors = {
            "CRITICAL": Colors.RED,
            "HIGH":     Colors.RED,
            "MEDIUM":   Colors.YELLOW,
            "LOW":      Colors.BLUE,
            "INFO":     Colors.CYAN,
        }
        color = sev_colors.get(severity.upper(), Colors.WHITE)
        sev_label = self._color(f"[{severity.upper()}]", color)
        print(f"  {sev_label} {self._color(title, Colors.BOLD)}")
        print(f"           {detail}")

    def progress(self, current: int, total: int, name: str):
        pct = int(current / total * 100)
        bar_len = 20
        filled = int(bar_len * current / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        bar_col = self._color(bar, Colors.BLUE)
        pct_str = self._color(f"{pct:3d}%", Colors.CYAN)
        name_str = self._color(name, Colors.WHITE)
        print(f"\r  {bar_col} {pct_str}  Running: {name_str:<20}", end="", flush=True)
        if current == total:
            print()

    def separator(self):
        print(self._color("  " + "─" * 60, Colors.GREY))
