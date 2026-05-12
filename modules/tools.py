import shutil
import subprocess
from urllib.parse import urlparse

from modules.base import BaseModule


class ToolsModule(BaseModule):
    NAME = "tools"
    DESCRIPTION = "Optional external tool integrations - nmap, nikto, whatweb, wafw00f, sqlmap, zap-baseline"

    DEFAULT_TOOLS = ["nmap", "nikto", "whatweb", "wafw00f", "sqlmap", "zap-baseline"]

    def run(self):
        self.log.info("[tools] Checking optional external integrations")
        if not self.settings.external_tools:
            self.add_finding(
                severity="INFO",
                title="External tool execution disabled",
                url=self.target,
                detail="Run with --external-tools and --modules tools to execute installed integrations.",
            )
            return

        requested = self.settings.parsed_tools() or self.DEFAULT_TOOLS
        unavailable = []
        skipped = []
        executed = []

        for name in requested:
            command = self._command_for(name)
            if not command:
                skipped.append(name)
                continue
            if not shutil.which(command[0]):
                unavailable.append(name)
                continue
            result = self._run_tool(name, command)
            executed.append(name)
            self._record_result(name, result)

        self.results.meta["external_tools"] = {
            "requested": requested,
            "executed": executed,
            "unavailable": unavailable,
            "skipped": skipped,
        }

        if unavailable:
            self.add_finding(
                severity="INFO",
                title="External tools unavailable",
                url=self.target,
                detail=", ".join(sorted(unavailable)),
                remediation="Install the missing tools or remove them from --tools.",
            )

        if skipped:
            self.add_finding(
                severity="INFO",
                title="External tools skipped",
                url=self.target,
                detail=", ".join(sorted(skipped)),
            )

    def _command_for(self, name):
        parsed = urlparse(self.target)
        host = parsed.hostname
        if name == "nmap" and host:
            return [
                "nmap", "-sV", "--version-light", "--top-ports", "100",
                "--host-timeout", f"{self.settings.tool_timeout}s", host,
            ]
        if name == "nikto":
            return ["nikto", "-h", self.target, "-nointeractive"]
        if name == "whatweb":
            return ["whatweb", "--no-errors", self.target]
        if name == "wafw00f":
            return ["wafw00f", self.target]
        if name == "sqlmap":
            if not parsed.query:
                return None
            return [
                "sqlmap", "-u", self.target, "--batch",
                "--risk=1", "--level=1", "--smart",
            ]
        if name == "zap-baseline":
            return ["zap-baseline.py", "-t", self.target, "-J", "-"]
        return None

    def _run_tool(self, name, command):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.tool_timeout,
                check=False,
            )
            output = "\n".join(
                part for part in (completed.stdout, completed.stderr) if part
            ).strip()
            return {
                "returncode": completed.returncode,
                "output": output[:5000],
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "returncode": -1,
                "output": f"{name} timed out after {exc.timeout} seconds.",
            }
        except OSError as exc:
            return {
                "returncode": -1,
                "output": str(exc),
            }

    def _record_result(self, name, result):
        severity = "INFO" if result["returncode"] == 0 else "LOW"
        self.add_finding(
            severity=severity,
            title=f"External tool result: {name}",
            url=self.target,
            detail=f"{name} finished with exit code {result['returncode']}.",
            evidence=result["output"][:1200],
            remediation="Review the external tool output and validate any reported issue manually.",
        )
