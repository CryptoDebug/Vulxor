import re
from modules.base import BaseModule


class CsrfModule(BaseModule):
    NAME = "csrf"
    DESCRIPTION = "CSRF - detect forms lacking anti-CSRF tokens"

    CSRF_TOKEN_NAMES = re.compile(
        r"csrf|xsrf|token|nonce|authenticity", re.I
    )

    def run(self):
        self.log.info("[csrf] Checking for missing CSRF protections")
        resp = self.get(self.target)
        if not resp:
            return

        forms = re.findall(r"<form[^>]*>.*?</form>", resp.text, re.I | re.S)
        for form_html in forms:
            method = re.search(r'method=["\']([^"\']+)["\']', form_html, re.I)
            if not method or method.group(1).lower() == "get":
                continue

            has_token = bool(re.search(
                r'<input[^>]+name=["\'][^"\']*(?:csrf|xsrf|token|nonce)[^"\']*["\']',
                form_html, re.I
            ))
            if not has_token:
                action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                action_url = action.group(1) if action else "unknown"
                self.add_finding(
                    severity="MEDIUM",
                    title="CSRF token missing on POST form",
                    url=self.url(action_url),
                    detail=f"POST form at '{action_url}' has no detectable CSRF token.",
                    remediation=(
                        "Add a synchronised CSRF token to every state-changing form. "
                        "Consider SameSite=Strict cookie attribute."
                    ),
                )
