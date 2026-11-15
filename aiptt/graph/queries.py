"""
Cypher query library for the AIPTT knowledge graph.

All queries are parameterised to prevent injection.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Host queries
# ---------------------------------------------------------------------------

UPSERT_HOST = """
MERGE (h:Host {ip: $ip})
SET h.hostname          = $hostname,
    h.os                = $os,
    h.udp_only          = $udp_only,
    h.suspected_honeypot = $honeypot,
    h.scan_incomplete   = $scan_incomplete,
    h.domain            = $domain,
    h.visit_count       = coalesce(h.visit_count, 0),
    h.last_seen         = datetime()
RETURN h
"""

INCREMENT_VISIT = """
MATCH (h:Host {ip: $ip})
SET h.visit_count = coalesce(h.visit_count, 0) + 1
"""

GET_HOST_METADATA = """
MATCH (h:Host {ip: $ip})
RETURN h
"""

# ---------------------------------------------------------------------------
# Vulnerability queries
# ---------------------------------------------------------------------------

UPSERT_VULNERABILITY = """
MATCH (h:Host {ip: $ip})
MERGE (v:Vulnerability {cve_id: $cve_id, ip: $ip, port: $port})
SET v.cvss     = $cvss,
    v.severity = $severity,
    v.service  = $service,
    v.description = $description
MERGE (h)-[:HAS_VULNERABILITY]->(v)
"""

MARK_EXPLOITED = """
MATCH (v:Vulnerability {cve_id: $cve_id, ip: $ip, port: $port})
MERGE (e:ExploitRecord {finding_id: $finding_id})
MERGE (v)-[:WAS_EXPLOITED]->(e)
"""

# ---------------------------------------------------------------------------
# Credential queries
# ---------------------------------------------------------------------------

UPSERT_CREDENTIAL = """
MERGE (c:Credential {ref: $ref})
SET c.username   = $username,
    c.type       = $cred_type,
    c.source_ip  = $source_ip,
    c.domain     = $domain
WITH c
MATCH (h:Host {ip: $source_ip})
MERGE (h)-[:EXPOSES_CREDENTIAL]->(c)
"""

# ---------------------------------------------------------------------------
# Attack path queries
# ---------------------------------------------------------------------------

UPSERT_ATTACK_PATH = """
MATCH (src:Host {ip: $from_ip})
MATCH (dst:Host {ip: $to_ip})
MERGE (src)-[r:CAN_REACH {technique: $technique}]->(dst)
SET r.via_credential  = $via_cred,
    r.success         = $success,
    r.discovered_at   = datetime()
"""

GET_ATTACK_PATHS_RANKED = """
MATCH (src:Host)-[r:CAN_REACH]->(dst:Host)
OPTIONAL MATCH (dst)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN src.ip       AS source,
       dst.ip       AS target,
       r.technique  AS technique,
       max(v.cvss)  AS max_cvss,
       count(v)     AS vuln_count
ORDER BY max_cvss DESC, vuln_count DESC
"""

# ---------------------------------------------------------------------------
# Unexhausted targets (for OPAV OBSERVE phase)
# ---------------------------------------------------------------------------

GET_UNEXHAUSTED_TARGETS = """
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE NOT (v)-[:WAS_EXPLOITED]->()
  AND h.suspected_honeypot = false
  AND h.scan_incomplete    IS NULL
  OR  h.scan_incomplete    = false
RETURN h.ip AS ip,
       collect({
           cve_id:      v.cve_id,
           cvss:        v.cvss,
           severity:    v.severity,
           port:        v.port,
           service:     v.service,
           description: v.description
       }) AS vulnerabilities
"""

# ---------------------------------------------------------------------------
# Circular pivot detection
# ---------------------------------------------------------------------------

GET_VISIT_COUNT = """
MATCH (h:Host {ip: $ip})
RETURN coalesce(h.visit_count, 0) AS visits
"""

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

GET_GRAPH_STATS = """
MATCH (h:Host)
WITH count(h) AS host_count
MATCH (v:Vulnerability)
WITH host_count, count(v) AS vuln_count
MATCH ()-[r:CAN_REACH]->()
RETURN host_count, vuln_count, count(r) AS path_count
"""
