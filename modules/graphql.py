import json
from modules.base import BaseModule


class GraphqlModule(BaseModule):
    NAME = "graphql"
    DESCRIPTION = "GraphQL - introspection, injection, field suggestion disclosure"

    ENDPOINTS = ["/graphql", "/api/graphql", "/gql", "/query"]

    INTROSPECTION = {"query": "{__schema{types{name}}}"}

    INJECTION_QUERIES = [
        {"query": '{users(where:{id:"1 OR 1=1"}){id email}}'},
        {"query": '{users{id email password}}'},
        {"query": '{user(id:1){id email password}}'},
    ]

    def run(self):
        self.log.info("[graphql] Probing GraphQL endpoints")
        hdrs = {"Content-Type": "application/json"}
        for path in self.ENDPOINTS:
            url = self.url(path)
            r = self.post(url, json=self.INTROSPECTION, headers=hdrs)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if "__schema" in str(data):
                self.add_finding(
                    severity="MEDIUM",
                    title="GraphQL introspection enabled",
                    url=url,
                    detail="Full schema disclosed via __schema query.",
                    remediation="Disable introspection in production.",
                )
            for query in self.INJECTION_QUERIES:
                r2 = self.post(url, json=query, headers=hdrs)
                if r2 and "password" in r2.text and "errors" not in r2.text:
                    self.add_finding(
                        severity="HIGH",
                        title="GraphQL sensitive field exposure",
                        url=url,
                        detail="Query returned password or sensitive field without error.",
                        payload=query["query"],
                        evidence=r2.text[:200],
                        remediation=(
                            "Implement field-level authorisation. "
                            "Remove sensitive fields from unauthenticated queries."
                        ),
                    )
            break
