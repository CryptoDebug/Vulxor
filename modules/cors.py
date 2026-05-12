from modules.base import BaseModule


class CorsModule(BaseModule):
    NAME = "cors"
    DESCRIPTION = "CORS misconfiguration - wildcard, origin reflection, credentials"

    EVIL_ORIGIN = "https://evil.example.com"

    def run(self):
        self.log.info("[cors] Checking CORS configuration")
        headers = {"Origin": self.EVIL_ORIGIN}
        resp = self.get(self.target, headers=headers)
        if not resp:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self.add_finding(
                severity="MEDIUM",
                title="CORS wildcard (Access-Control-Allow-Origin: *)",
                url=self.target,
                detail="Any origin may read responses.",
                remediation="Restrict ACAO to explicit trusted origins.",
            )
        elif acao == self.EVIL_ORIGIN:
            sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
            self.add_finding(
                severity=sev,
                title="CORS origin reflection" + (" with credentials" if sev == "HIGH" else ""),
                url=self.target,
                detail=f"Server mirrors arbitrary Origin header. Credentials: {acac}.",
                remediation=(
                    "Validate Origin against a static allowlist. "
                    "Never combine Allow-Credentials: true with dynamic origin mirroring."
                ),
            )
