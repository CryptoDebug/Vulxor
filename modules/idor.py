from modules.base import BaseModule


class IdorModule(BaseModule):
    NAME = "idor"
    DESCRIPTION = "IDOR - parameter ID brute-forcing for unauthorised access"

    ENDPOINTS = [
        "/profile?id=", "/user?id=", "/account?id=",
        "/order?id=", "/invoice?id=", "/document?id=",
        "/api/user/", "/api/account/", "/api/order/",
        "/admin/user?id=", "/admin/account?id=",
    ]

    def run(self):
        self.log.info("[idor] Testing for IDOR vulnerabilities")
        self._probe_numeric_ids()

    def _probe_numeric_ids(self):
        for endpoint in self.ENDPOINTS:
            base = self.get(self.url(endpoint + "0"))
            if not base or base.status_code not in (403, 404):
                continue
            base_len = len(base.text)
            for obj_id in range(1, 21):
                resp = self.get(self.url(endpoint + str(obj_id)))
                if not resp:
                    continue
                if resp.status_code == 200 and abs(len(resp.text) - base_len) > 50:
                    self.add_finding(
                        severity="HIGH",
                        title="Potential IDOR",
                        url=self.url(endpoint + str(obj_id)),
                        detail=f"Object ID {obj_id} returned HTTP 200 "
                               f"({len(resp.text)} bytes).",
                        payload=str(obj_id),
                        remediation=(
                            "Validate that the authenticated user owns the requested "
                            "object before returning data."
                        ),
                    )
                    break
