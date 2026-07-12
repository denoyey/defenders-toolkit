# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
from urllib.parse import urljoin
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class GraphQLScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "GraphQL Introspection Scanner"

    @property
    def description(self) -> str:
        return "Mendeteksi endpoint GraphQL dan menguji kebocoran skema via Introspection"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai GraphQL Scan pada: {target}")
        base_url = target if target.endswith('/') else f"{target}/"
        endpoints = ['graphql', 'api/graphql', 'v1/graphql', 'v2/graphql', 'gql']
        headers = self.get_headers()
        headers['Content-Type'] = 'application/json'
        
        introspection_query = {
            "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n      }\n    }\n  "
        }

        print("-" * 55)
        
        async def check_endpoint(client, endpoint):
            test_url = urljoin(base_url, endpoint)
            try:
                async with client.session.post(test_url, json=introspection_query, allow_redirects=False, timeout=10) as response:
                    if response.status == 200:
                        json_data = await response.json()
                        if 'data' in json_data and '__schema' in json_data['data']:
                            schema_data = json_data['data']['__schema']
                            types_count = len(schema_data.get('types', []))
                            print(f"[!] [KRITIS] Introspection terbuka di: {test_url}")
                            print(f"    └─ Berhasil mengekstrak {types_count} skema tipe data!")
                            
                            self.add_finding(
                                "KRITIS", 
                                "GraphQL Introspection Terbuka", 
                                f"Endpoint: {test_url} membocorkan {types_count} skema"
                            )
            except:
                pass

        async with AsyncResilientClient(headers=headers, limit=10, max_retries=2) as client:
            tasks = [check_endpoint(client, ep) for ep in endpoints]
            await asyncio.gather(*tasks)

        if not self.findings:
            print("[+] Target aman. Tidak ditemukan endpoint GraphQL yang terekspos.")
        print("-" * 55)