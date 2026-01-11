#!/usr/bin/env python3
"""
HydraRecon GraphQL Security Scanner
Specialized security testing for GraphQL APIs.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import aiohttp


class GraphQLVulnType(Enum):
    """GraphQL-specific vulnerability types."""
    INTROSPECTION_ENABLED = "Introspection Enabled"
    EXCESSIVE_DEPTH = "Query Depth Limit Missing"
    BATCHING_ATTACK = "Query Batching Attack"
    FIELD_SUGGESTION = "Field Suggestion Enabled"
    IDOR = "GraphQL IDOR"
    INJECTION = "GraphQL Injection"
    DOS_COMPLEXITY = "Query Complexity DoS"
    ALIAS_OVERLOADING = "Alias Overloading"
    CIRCULAR_FRAGMENT = "Circular Fragment"
    DIRECTIVE_OVERLOADING = "Directive Overloading"
    SSRF = "GraphQL SSRF"
    SQL_INJECTION = "SQL Injection via GraphQL"
    AUTH_BYPASS = "Authorization Bypass"
    INFORMATION_DISCLOSURE = "Schema Information Disclosure"
    RATE_LIMIT_BYPASS = "Rate Limit Bypass"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class GraphQLField:
    """Represents a GraphQL field."""
    name: str
    type: str
    args: List[Dict] = field(default_factory=list)
    is_deprecated: bool = False
    description: Optional[str] = None


@dataclass
class GraphQLType:
    """Represents a GraphQL type."""
    name: str
    kind: str  # OBJECT, SCALAR, ENUM, INPUT_OBJECT, etc.
    fields: List[GraphQLField] = field(default_factory=list)
    description: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)


@dataclass
class GraphQLSchema:
    """Parsed GraphQL schema."""
    types: Dict[str, GraphQLType] = field(default_factory=dict)
    queries: List[GraphQLField] = field(default_factory=list)
    mutations: List[GraphQLField] = field(default_factory=list)
    subscriptions: List[GraphQLField] = field(default_factory=list)
    directives: List[str] = field(default_factory=list)


@dataclass
class GraphQLFinding:
    """Security finding for GraphQL."""
    id: str
    vuln_type: GraphQLVulnType
    severity: Severity
    title: str
    description: str
    endpoint: str
    query: str
    response: Optional[str] = None
    remediation: str = ""
    cvss_score: float = 0.0
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)


class GraphQLScanner:
    """Advanced GraphQL security scanner."""
    
    # Introspection query for schema extraction
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    
    # Simple introspection for quick check
    SIMPLE_INTROSPECTION = '{"query": "{ __schema { types { name } } }"}'
    
    # Field suggestion probe
    FIELD_SUGGESTION_QUERY = '{"query": "{ __typ }"}'
    
    def __init__(self):
        self.findings: List[GraphQLFinding] = []
        self.schema: Optional[GraphQLSchema] = None
        self.endpoint: str = ""
        self.headers: Dict[str, str] = {}
        self.finding_count = 0
    
    def generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self.finding_count += 1
        return f"GQL-{datetime.now().strftime('%Y%m%d')}-{self.finding_count:04d}"
    
    async def send_query(self, endpoint: str, query: str, 
                         variables: Dict = None, 
                         operation_name: str = None) -> Dict:
        """Send a GraphQL query and return the response."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.headers
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False  # For testing purposes
                ) as response:
                    return await response.json()
        except Exception as e:
            return {"errors": [{"message": str(e)}]}
    
    async def test_introspection(self, endpoint: str) -> Optional[GraphQLFinding]:
        """Test if introspection is enabled."""
        query = "{ __schema { types { name } } }"
        response = await self.send_query(endpoint, query)
        
        if "data" in response and "__schema" in response.get("data", {}):
            finding = GraphQLFinding(
                id=self.generate_finding_id(),
                vuln_type=GraphQLVulnType.INTROSPECTION_ENABLED,
                severity=Severity.MEDIUM,
                title="GraphQL Introspection Enabled",
                description="""GraphQL introspection is enabled on this endpoint, allowing anyone to 
discover the complete API schema including all types, queries, mutations, and their arguments.
This significantly reduces the attacker's reconnaissance effort.""",
                endpoint=endpoint,
                query=query,
                response=json.dumps(response, indent=2)[:500],
                remediation="""1. Disable introspection in production environments
2. If introspection is needed, restrict it to authenticated admin users
3. Apollo Server: Use ApolloServerPluginDisableIntrospection
4. graphql-yoga: Set introspection: false
5. Implement field-level permissions""",
                cvss_score=5.3,
                proof_of_concept=f"""curl -X POST {endpoint} \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{{ __schema {{ types {{ name }} }} }}"}}'""",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/graphql"
                ]
            )
            self.findings.append(finding)
            return finding
        
        return None
    
    async def test_field_suggestions(self, endpoint: str) -> Optional[GraphQLFinding]:
        """Test if field suggestions are enabled."""
        query = "{ __typ }"  # Intentional typo
        response = await self.send_query(endpoint, query)
        
        errors = response.get("errors", [])
        for error in errors:
            message = error.get("message", "").lower()
            if "did you mean" in message or "suggest" in message:
                finding = GraphQLFinding(
                    id=self.generate_finding_id(),
                    vuln_type=GraphQLVulnType.FIELD_SUGGESTION,
                    severity=Severity.LOW,
                    title="GraphQL Field Suggestions Enabled",
                    description="""Field suggestions are enabled, allowing attackers to enumerate 
valid field names even when introspection is disabled. By sending invalid field names,
the server suggests valid alternatives.""",
                    endpoint=endpoint,
                    query=query,
                    response=json.dumps(response, indent=2)[:500],
                    remediation="""1. Disable field suggestions in production
2. Use generic error messages that don't reveal schema details
3. Implement rate limiting to slow enumeration attempts""",
                    cvss_score=3.1,
                    proof_of_concept=f"""curl -X POST {endpoint} \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{{ __typ }}"}}'"""
                )
                self.findings.append(finding)
                return finding
        
        return None
    
    async def test_query_depth(self, endpoint: str, max_depth: int = 10) -> Optional[GraphQLFinding]:
        """Test for query depth limiting."""
        # Build a deeply nested query
        nested_query = "{ "
        for i in range(max_depth):
            nested_query += "__typename "
            if i < max_depth - 1:
                nested_query += "__schema { types { "
        
        for i in range(max_depth - 1):
            nested_query += " } }"
        nested_query += " }"
        
        response = await self.send_query(endpoint, nested_query)
        
        # If no depth error, vulnerability exists
        errors = response.get("errors", [])
        depth_error = any("depth" in str(e).lower() or "complexity" in str(e).lower() for e in errors)
        
        if not depth_error and "data" in response:
            finding = GraphQLFinding(
                id=self.generate_finding_id(),
                vuln_type=GraphQLVulnType.EXCESSIVE_DEPTH,
                severity=Severity.MEDIUM,
                title="No Query Depth Limit",
                description=f"""The GraphQL endpoint accepts queries with depth of {max_depth}+ levels.
This allows attackers to craft deeply nested queries that consume excessive server resources,
potentially causing Denial of Service.""",
                endpoint=endpoint,
                query=nested_query[:500],
                remediation="""1. Implement query depth limiting (recommended max: 5-7 levels)
2. Use query complexity analysis
3. Set maximum query cost limits
4. Implement request timeouts
5. Use persisted queries to prevent arbitrary query execution""",
                cvss_score=5.3,
                references=[
                    "https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b/"
                ]
            )
            self.findings.append(finding)
            return finding
        
        return None
    
    async def test_batching_attack(self, endpoint: str) -> Optional[GraphQLFinding]:
        """Test for query batching attack vulnerability."""
        # Test with batched queries
        batch_queries = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]
        
        headers = {
            "Content-Type": "application/json",
            **self.headers
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json=batch_queries,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False
                ) as response:
                    result = await response.json()
                    
                    if isinstance(result, list) and len(result) == 3:
                        finding = GraphQLFinding(
                            id=self.generate_finding_id(),
                            vuln_type=GraphQLVulnType.BATCHING_ATTACK,
                            severity=Severity.MEDIUM,
                            title="Query Batching Enabled",
                            description="""The endpoint accepts batched GraphQL queries. This can be 
exploited to bypass rate limiting (sending many queries in one request) or perform 
brute force attacks more efficiently.""",
                            endpoint=endpoint,
                            query=json.dumps(batch_queries),
                            response=json.dumps(result, indent=2)[:500],
                            remediation="""1. Disable query batching if not needed
2. Implement per-query rate limiting within batches
3. Limit the maximum number of queries per batch
4. Apply the same security controls to each batched query""",
                            cvss_score=5.3
                        )
                        self.findings.append(finding)
                        return finding
        except Exception:
            pass
        
        return None
    
    async def test_alias_overloading(self, endpoint: str, alias_count: int = 100) -> Optional[GraphQLFinding]:
        """Test for alias overloading attack."""
        # Build query with many aliases
        aliases = " ".join([f"a{i}: __typename" for i in range(alias_count)])
        query = f"{{ {aliases} }}"
        
        response = await self.send_query(endpoint, query)
        
        if "data" in response and len(response.get("data", {})) >= alias_count:
            finding = GraphQLFinding(
                id=self.generate_finding_id(),
                vuln_type=GraphQLVulnType.ALIAS_OVERLOADING,
                severity=Severity.MEDIUM,
                title="Alias Overloading Possible",
                description=f"""The endpoint accepts queries with {alias_count}+ aliases.
Attackers can use alias overloading to:
- Bypass rate limiting
- Amplify query execution
- Perform credential stuffing/brute force attacks""",
                endpoint=endpoint,
                query=query[:500],
                remediation="""1. Limit the number of aliases per query
2. Implement query complexity analysis
3. Count aliases against rate limits
4. Use query cost analysis""",
                cvss_score=5.3
            )
            self.findings.append(finding)
            return finding
        
        return None
    
    async def test_sql_injection(self, endpoint: str, schema: GraphQLSchema = None) -> List[GraphQLFinding]:
        """Test for SQL injection via GraphQL arguments."""
        findings = []
        
        # Common SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1' AND SLEEP(5)--",
            "1 UNION SELECT NULL,NULL,NULL--"
        ]
        
        # Test with a common query pattern
        test_queries = [
            ('query {{ user(id: "{payload}") {{ id }} }}', "id"),
            ('query {{ users(filter: "{payload}") {{ id }} }}', "filter"),
            ('query {{ search(query: "{payload}") {{ id }} }}', "query"),
        ]
        
        for query_template, param in test_queries:
            for payload in sql_payloads:
                query = query_template.format(payload=payload)
                response = await self.send_query(endpoint, query)
                
                # Check for SQL error indicators
                response_str = json.dumps(response).lower()
                sql_errors = ["sql", "syntax", "mysql", "postgresql", "sqlite", "ora-", "mssql"]
                
                if any(err in response_str for err in sql_errors):
                    finding = GraphQLFinding(
                        id=self.generate_finding_id(),
                        vuln_type=GraphQLVulnType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        title=f"SQL Injection via '{param}' Parameter",
                        description=f"""SQL injection vulnerability detected in the '{param}' parameter.
The server returned database error messages indicating vulnerable SQL query construction.""",
                        endpoint=endpoint,
                        query=query,
                        response=response_str[:500],
                        remediation="""1. Use parameterized queries/prepared statements
2. Implement input validation and sanitization
3. Apply least privilege database permissions
4. Use ORM with proper escaping
5. Enable WAF rules for SQL injection""",
                        cvss_score=9.8
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    break  # Found vulnerability, move to next parameter
        
        return findings
    
    async def extract_schema(self, endpoint: str) -> Optional[GraphQLSchema]:
        """Extract and parse the GraphQL schema."""
        response = await self.send_query(endpoint, self.INTROSPECTION_QUERY)
        
        if "data" not in response or "__schema" not in response.get("data", {}):
            return None
        
        schema_data = response["data"]["__schema"]
        schema = GraphQLSchema()
        
        # Parse types
        for type_data in schema_data.get("types", []):
            if type_data["name"].startswith("__"):
                continue  # Skip introspection types
            
            gql_type = GraphQLType(
                name=type_data["name"],
                kind=type_data["kind"],
                description=type_data.get("description")
            )
            
            # Parse fields
            for field_data in type_data.get("fields") or []:
                field = GraphQLField(
                    name=field_data["name"],
                    type=self._get_type_name(field_data.get("type", {})),
                    args=[{
                        "name": arg["name"],
                        "type": self._get_type_name(arg.get("type", {}))
                    } for arg in field_data.get("args", [])],
                    is_deprecated=field_data.get("isDeprecated", False),
                    description=field_data.get("description")
                )
                gql_type.fields.append(field)
            
            schema.types[type_data["name"]] = gql_type
        
        # Get query/mutation/subscription types
        query_type = schema_data.get("queryType", {}).get("name")
        mutation_type = schema_data.get("mutationType", {}).get("name")
        subscription_type = schema_data.get("subscriptionType", {}).get("name")
        
        if query_type and query_type in schema.types:
            schema.queries = schema.types[query_type].fields
        if mutation_type and mutation_type in schema.types:
            schema.mutations = schema.types[mutation_type].fields
        if subscription_type and subscription_type in schema.types:
            schema.subscriptions = schema.types[subscription_type].fields
        
        self.schema = schema
        return schema
    
    def _get_type_name(self, type_data: Dict) -> str:
        """Extract readable type name from GraphQL type object."""
        if not type_data:
            return "Unknown"
        
        kind = type_data.get("kind", "")
        name = type_data.get("name")
        of_type = type_data.get("ofType")
        
        if name:
            return name
        elif kind == "NON_NULL":
            return f"{self._get_type_name(of_type)}!"
        elif kind == "LIST":
            return f"[{self._get_type_name(of_type)}]"
        
        return "Unknown"
    
    def find_sensitive_fields(self, schema: GraphQLSchema) -> List[Dict]:
        """Find potentially sensitive fields in the schema."""
        sensitive_patterns = [
            r"password", r"secret", r"token", r"key", r"credential",
            r"ssn", r"social.?security", r"credit.?card", r"cvv",
            r"email", r"phone", r"address", r"dob", r"birth",
            r"private", r"internal", r"admin", r"role", r"permission"
        ]
        
        sensitive_fields = []
        
        for type_name, gql_type in schema.types.items():
            for field in gql_type.fields:
                field_name_lower = field.name.lower()
                for pattern in sensitive_patterns:
                    if re.search(pattern, field_name_lower):
                        sensitive_fields.append({
                            "type": type_name,
                            "field": field.name,
                            "field_type": field.type,
                            "pattern_matched": pattern
                        })
                        break
        
        return sensitive_fields
    
    def find_dangerous_mutations(self, schema: GraphQLSchema) -> List[Dict]:
        """Find potentially dangerous mutations."""
        dangerous_patterns = [
            (r"delete", "Data deletion"),
            (r"remove", "Data removal"),
            (r"drop", "Data dropping"),
            (r"update.?password", "Password modification"),
            (r"reset.?password", "Password reset"),
            (r"create.?admin", "Admin creation"),
            (r"grant", "Permission granting"),
            (r"execute", "Code execution"),
            (r"upload", "File upload"),
            (r"import", "Data import"),
        ]
        
        dangerous = []
        
        for mutation in schema.mutations:
            mutation_lower = mutation.name.lower()
            for pattern, risk in dangerous_patterns:
                if re.search(pattern, mutation_lower):
                    dangerous.append({
                        "mutation": mutation.name,
                        "risk": risk,
                        "args": [a["name"] for a in mutation.args]
                    })
                    break
        
        return dangerous
    
    async def full_scan(self, endpoint: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Perform a comprehensive GraphQL security scan."""
        self.endpoint = endpoint
        self.headers = headers or {}
        self.findings = []
        
        results = {
            "endpoint": endpoint,
            "scan_time": datetime.now().isoformat(),
            "findings": [],
            "schema_extracted": False,
            "sensitive_fields": [],
            "dangerous_mutations": [],
            "summary": {}
        }
        
        # Run all tests
        await self.test_introspection(endpoint)
        await self.test_field_suggestions(endpoint)
        await self.test_query_depth(endpoint)
        await self.test_batching_attack(endpoint)
        await self.test_alias_overloading(endpoint)
        await self.test_sql_injection(endpoint)
        
        # Extract and analyze schema
        schema = await self.extract_schema(endpoint)
        if schema:
            results["schema_extracted"] = True
            results["sensitive_fields"] = self.find_sensitive_fields(schema)
            results["dangerous_mutations"] = self.find_dangerous_mutations(schema)
            
            results["schema_stats"] = {
                "types": len(schema.types),
                "queries": len(schema.queries),
                "mutations": len(schema.mutations),
                "subscriptions": len(schema.subscriptions)
            }
        
        # Compile findings
        results["findings"] = [{
            "id": f.id,
            "type": f.vuln_type.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "remediation": f.remediation,
            "cvss_score": f.cvss_score
        } for f in self.findings]
        
        # Summary
        severity_counts = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        results["summary"] = {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "critical": severity_counts.get("Critical", 0),
            "high": severity_counts.get("High", 0)
        }
        
        return results
    
    def export_report(self, format: str = "json") -> str:
        """Export scan results."""
        if format == "json":
            return json.dumps({
                "endpoint": self.endpoint,
                "findings": [{
                    "id": f.id,
                    "type": f.vuln_type.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "query": f.query,
                    "remediation": f.remediation,
                    "poc": f.proof_of_concept
                } for f in self.findings]
            }, indent=2)
        
        elif format == "markdown":
            md = f"# GraphQL Security Scan Report\n\n"
            md += f"**Endpoint:** `{self.endpoint}`\n\n"
            md += f"## Findings ({len(self.findings)})\n\n"
            
            for f in self.findings:
                md += f"### {f.title}\n"
                md += f"- **Severity:** {f.severity.value}\n"
                md += f"- **Type:** {f.vuln_type.value}\n"
                md += f"- **CVSS:** {f.cvss_score}\n\n"
                md += f"**Description:**\n{f.description}\n\n"
                md += f"**Remediation:**\n{f.remediation}\n\n"
                md += "---\n\n"
            
            return md
        
        return ""
