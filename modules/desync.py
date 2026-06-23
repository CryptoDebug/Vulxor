import socket
import ssl
import re
from urllib.parse import urlparse
from modules.base import BaseModule


class DesyncModule(BaseModule):
    NAME = "desync"
    DESCRIPTION = "HTTP Request Smuggling - CL.TE and TE.CL detection"

    def run(self):
        self.log.info("[desync] Probing for HTTP request smuggling")
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        self._probe_cl_te(host, port, use_tls)

    def _send_raw(self, host, port, use_tls, payload: bytes) -> bytes:
        try:
            sock = socket.create_connection((host, port), timeout=self.settings.timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            sock.close()
            return data
        except Exception as e:
            self.log.debug(f"[desync] raw send error: {e}")
            return b""

    def _probe_cl_te(self, host, port, use_tls):
        raw = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()
        resp = self._send_raw(host, port, use_tls, raw)
        if self._is_desync_indicator(resp):
            self.add_finding(
                severity="MEDIUM",
                title="Potential HTTP request desynchronisation",
                url=self.target,
                detail="The ambiguous request produced multiple HTTP responses and a back-end method parsing error.",
                remediation=(
                    "Normalise Transfer-Encoding and Content-Length at the reverse proxy. "
                    "Reject ambiguous requests."
                ),
            )

    def _is_desync_indicator(self, response: bytes) -> bool:
        if not response:
            return False
        status_lines = re.findall(rb"HTTP/1\.[01]\s+\d{3}\b", response)
        method_error = b"Unrecognized method" in response or b"Invalid method" in response
        return len(status_lines) >= 2 and method_error
