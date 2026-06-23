import re


def has_authenticated_marker(body: str) -> bool:
    """Look for structural session controls, not generic account-related words."""
    return bool(re.search(
        r'(?:href|action)=["\'][^"\']*/(?:logout|signout|sign-out)(?:[/?#"\'])'
        r'|data-authenticated=["\']true["\']',
        body or "",
        re.IGNORECASE,
    ))
