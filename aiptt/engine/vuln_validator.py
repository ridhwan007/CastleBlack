"""
AI-powered vulnerability validation engine.

For each Nessus Critical/High finding, uses Claude to:
  1. Assess real-world exploitability (context check)
  2. Research known public exploits / Metasploit modules
  3. Generate a working PoC script or manual exploitation steps
  4. Re-score severity using attacker-reality logic (not raw CVSS)
  5. Provide specific remediation guidance

Rubric (from nessus_exploit_workflow.md):
  CRITICAL  — Unauth RCE, network-reachable, reliable public exploit
  HIGH      — Auth req + weak/default creds common, OR unauth but tricky
  MEDIUM    — Chained, conditional, or local-only
  LOW       — Hardening gap, no direct path
  INFO      — Version disclosure, no standalone impact
  FALSE_POSITIVE — Inference-only, version range too broad, wrong context
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from aiptt.core.config import get_config


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RawFinding:
    """A single Nessus ReportItem with all fields preserved from XML."""
    host_ip:             str
    host_fqdn:           str
    host_os:             str
    port:                int
    protocol:            str
    svc_name:            str
    plugin_id:           str
    plugin_name:         str
    plugin_family:       str
    nessus_severity:     int    # 0=Info 1=Low 2=Med 3=High 4=Critical
    nessus_severity_str: str    # INFO / LOW / MEDIUM / HIGH / CRITICAL
    cvss_v2:             float
    cvss_v3:             float
    cvss:                float  # best available
    cves:                list[str]
    synopsis:            str
    description:         str
    solution:            str
    plugin_output:       str    # raw banner / version evidence
    exploit_available:   bool
    exploitability_ease: str
    metasploit_name:     str
    see_also:            str


@dataclass
class ValidationResult:
    """Full AI validation result for one Nessus finding."""
    finding: RawFinding

    # ── Phase 2 analysis ────────────────────────────────────────────────
    context_notes:        str   # service context, auth requirement, evidence quality
    evidence_quality:     str   # confirmed | inference_only | partial
    exploit_research:     str   # known exploits, MSF modules, GitHub PoCs
    exploitation_outcome: str   # RCE | LPE | InfoDisc | DoS | AuthBypass | None

    # ── PoC artefact ────────────────────────────────────────────────────
    poc_type:        str   # A | B | C | D
    poc_code:        str   # actual script/commands (empty for C/D)
    poc_filename:    str   # e.g. poc_12345_CVE-2021-1234.py
    poc_language:    str   # python | bash | text
    poc_reliability: str   # high | medium | low
    poc_no_reason:   str   # why no viable PoC (type D only)

    # ── Re-scoring ──────────────────────────────────────────────────────
    realistic_severity:      str   # CRITICAL|HIGH|MEDIUM|LOW|INFO|FALSE_POSITIVE
    severity_changed:        bool
    severity_justification:  str

    # ── Remediation ─────────────────────────────────────────────────────
    remediation: str

    # ── Chains ──────────────────────────────────────────────────────────
    chain_hint: str = ""   # e.g. "CHAIN: this + CVE-X = RCE"


@dataclass
class ExploitChain:
    """An identified multi-vuln exploit chain."""
    label:       str   # "CHAIN: <vuln_a> + <vuln_b> = <impact>"
    vuln_a:      str
    vuln_b:      str
    impact:      str
    description: str


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior penetration tester and exploit developer.
You are reviewing Nessus scan findings for an authorised penetration test.

Your job is NOT to regurgitate Nessus data — Nessus is a scanner, not a
pentester. You must reason about actual exploitability in the context of
the specific version / service / network position reported.

For each finding you will:

1. CONTEXT CHECK
   - What service/version did Nessus actually fingerprint? (from plugin output)
   - Is this authenticated or unauthenticated?
   - Is exploitation network-accessible or local-only?
   - Does plugin_output contain REAL evidence or inference-only? Flag inference-only clearly.

2. EXPLOIT RESEARCH
   - List known public exploits: Metasploit modules, ExploitDB IDs, GitHub PoCs, nuclei templates
   - State exact prerequisites (auth, network position, OS version, config)
   - Describe what successful exploitation actually gives (RCE / LPE / InfoDisc / DoS / AuthBypass)

3. PoC ARTEFACT
   Produce the MOST SPECIFIC applicable type:

   Type A — Working PoC script (Python or Bash). Include:
     * Assign target using:  TARGET_HOST = "<HOST>"  and  TARGET_PORT = <PORT>
     * Clear comments explaining each step
     * Expected output on success vs failure
     * Standard header block (see format below)

   Type B — curl / nmap NSE / bash one-liner for detection/validation
     * Use <HOST> and <PORT> only inside quoted strings or as command arguments

   Type C — Metasploit resource script (.rc) with exact set RHOSTS/RPORT/payload commands

   Type D — "No viable PoC" with explicit explanation

4. REALISTIC SEVERITY (ignore CVSS theory, use attacker-reality logic):
   CRITICAL  — Unauthenticated RCE, network-reachable, reliable public exploit exists
   HIGH      — Auth required but weak/default creds common; OR unauth but complex to land; OR RCE but no reliable public exploit
   MEDIUM    — Specific conditions, chaining required, local-only, or useful only in a chain
   LOW       — Hardening gap, informational, no direct exploit path
   INFO      — Version disclosure, config observation, no security impact standalone
   FALSE_POSITIVE — Inference-only, version range too broad, service confirmed wrong

5. REMEDIATION
   Specific fix — NOT Nessus boilerplate. Name the exact version to patch to,
   the exact config to change, or the exact feature to disable.

PoC file header format (include this at the top of all Type A/B scripts):
# Target:      <HOST>:<PORT>
# CVE:         <cve>
# Vuln:        <plugin name>
# Prereqs:     <what you need>
# Expected:    <what success looks like>
# Reliability: <high/medium/low>
# Tested on:   <vulnerable versions>
# Source:      <ExploitDB/Metasploit/manual reconstruction/etc>

IMPORTANT RULES:
- Be sceptical. Nessus over-reports. Downgrade aggressively if evidence is weak.
- If plugin_output shows no real version string, treat as inference-only.
- Never produce DoS exploit code. For DoS findings, describe impact only.
- Never produce ransomware / wiper / destructive payload code.
- PoC goal: demonstrate compromise, not cause damage.

CRITICAL SYNTAX RULE — PoC placeholder usage:
  <HOST> and <PORT> are substituted at runtime with the real IP and port.
  They must ONLY appear inside quoted strings or as bare command arguments.
  NEVER use them as variable names (left side of an assignment).
  After substitution `<HOST> = ...` becomes `192.168.1.10 = ...` which is
  a SyntaxError in Python and a bad-substitution error in Bash.

  CORRECT Python:
    TARGET_HOST = "<HOST>"   # substituted to: TARGET_HOST = "192.168.1.10"
    TARGET_PORT = <PORT>     # substituted to: TARGET_PORT = 443

  WRONG Python (DO NOT DO THIS):
    <HOST> = "<HOST>"        # substituted to: 192.168.1.10 = "192.168.1.10" — SyntaxError!

  CORRECT Bash:
    TARGET_HOST="<HOST>"     # substituted to: TARGET_HOST="192.168.1.10"
    TARGET_PORT=<PORT>       # substituted to: TARGET_PORT=443
    curl "http://<HOST>:<PORT>/"  # placeholder inside a string argument — fine

  WRONG Bash (DO NOT DO THIS):
    <HOST>=<HOST>            # substituted to: 192.168.1.10=192.168.1.10 — bad substitution!
"""


_USER_TEMPLATE = """\
## Finding to analyse

**Host:**         {host_ip}  ({host_fqdn})
**OS:**           {host_os}
**Service:**      {svc_name} on port {port}/{protocol}

**Plugin ID:**    {plugin_id}
**Plugin Name:**  {plugin_name}
**Plugin Family:**{plugin_family}
**Nessus Severity:** {nessus_severity_str}
**CVSSv2:** {cvss_v2}   **CVSSv3:** {cvss_v3}
**CVE(s):**       {cves}

**Exploit Available (Nessus flag):** {exploit_available}
**Exploitability Ease:**             {exploitability_ease}
**Metasploit Module:**               {metasploit_name}

**Synopsis:**
{synopsis}

**Description:**
{description}

**Plugin Output (raw evidence from scan):**
{plugin_output}

**References:**
{see_also}

---

Respond with a single JSON object (no markdown fences) matching this exact schema:

{{
  "context_notes":        "<string — service/version context, auth req, network position>",
  "evidence_quality":     "<confirmed | inference_only | partial>",
  "exploit_research":     "<string — known exploits, MSF modules, PoC links, prerequisites>",
  "exploitation_outcome": "<RCE | LPE | InfoDisc | DoS | AuthBypass | Pivot | None>",
  "poc_type":             "<A | B | C | D>",
  "poc_language":         "<python | bash | text>",
  "poc_filename":         "<poc_{{plugin_id}}_{{first_cve}}.py or .sh or .txt>",
  "poc_code":             "<full PoC script/commands as a string, empty if type D>",
  "poc_reliability":      "<high | medium | low>",
  "poc_no_reason":        "<explanation if type D, else empty>",
  "realistic_severity":   "<CRITICAL | HIGH | MEDIUM | LOW | INFO | FALSE_POSITIVE>",
  "severity_changed":     <true | false>,
  "severity_justification": "<1-2 sentences justifying the re-score>",
  "remediation":          "<specific fix — version, config change, or feature to disable>",
  "chain_hint":           "<optional: CHAIN: this + <other_cve> = <impact>, or empty>"
}}
"""


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------

class VulnValidator:
    """
    Calls Claude once per finding to produce exploitability analysis,
    PoC artefact, severity re-score, and remediation guidance.
    """

    def __init__(self) -> None:
        cfg = get_config()
        try:
            from langchain_anthropic import ChatAnthropic
            self.llm = ChatAnthropic(
                model=cfg.core.ai_model,
                api_key=os.environ[cfg.core.ai_api_key_env],
                max_tokens=4096,
                temperature=0,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialise ChatAnthropic: {exc}\n"
                "Ensure AIPTT_AI_API_KEY is set and langchain-anthropic is installed."
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_finding(self, finding: RawFinding) -> ValidationResult:
        """
        Send one finding to Claude for full exploitability analysis.
        Returns a ValidationResult. Never raises — returns an error result on failure.
        """
        cve_str = ", ".join(finding.cves) if finding.cves else "None"
        first_cve = finding.cves[0].replace("-", "_") if finding.cves else f"PLUGIN_{finding.plugin_id}"

        prompt = _USER_TEMPLATE.format(
            host_ip=finding.host_ip,
            host_fqdn=finding.host_fqdn or finding.host_ip,
            host_os=finding.host_os or "Unknown",
            svc_name=finding.svc_name,
            port=finding.port,
            protocol=finding.protocol,
            plugin_id=finding.plugin_id,
            plugin_name=finding.plugin_name,
            plugin_family=finding.plugin_family,
            nessus_severity_str=finding.nessus_severity_str,
            cvss_v2=finding.cvss_v2,
            cvss_v3=finding.cvss_v3,
            cves=cve_str,
            exploit_available=finding.exploit_available,
            exploitability_ease=finding.exploitability_ease or "Not rated",
            metasploit_name=finding.metasploit_name or "None",
            synopsis=finding.synopsis or "N/A",
            description=finding.description[:1500] if finding.description else "N/A",
            plugin_output=finding.plugin_output[:1200] if finding.plugin_output else "None provided",
            see_also=finding.see_also[:400] if finding.see_also else "None",
        )

        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            response = self.llm.invoke([
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
            raw_text = response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            return self._error_result(finding, f"LLM call failed: {exc}")

        data = self._parse_response(raw_text)
        if data is None:
            return self._error_result(finding, f"JSON parse failed. Raw:\n{raw_text[:500]}")

        # Determine poc_filename from data or build a sensible default
        poc_fname = data.get("poc_filename", "")
        if not poc_fname:
            ext = ".py" if data.get("poc_language", "python") == "python" else (
                  ".sh" if data.get("poc_language") == "bash" else ".txt")
            poc_fname = f"poc_{finding.plugin_id}_{first_cve}{ext}"

        original = finding.nessus_severity_str
        realistic = data.get("realistic_severity", original).upper()
        changed = data.get("severity_changed", realistic != original)

        return ValidationResult(
            finding=finding,
            context_notes=data.get("context_notes", ""),
            evidence_quality=data.get("evidence_quality", "partial"),
            exploit_research=data.get("exploit_research", ""),
            exploitation_outcome=data.get("exploitation_outcome", "Unknown"),
            poc_type=data.get("poc_type", "D"),
            poc_code=data.get("poc_code", ""),
            poc_filename=poc_fname,
            poc_language=data.get("poc_language", "text"),
            poc_reliability=data.get("poc_reliability", "low"),
            poc_no_reason=data.get("poc_no_reason", ""),
            realistic_severity=realistic,
            severity_changed=bool(changed),
            severity_justification=data.get("severity_justification", ""),
            remediation=data.get("remediation", ""),
            chain_hint=data.get("chain_hint", ""),
        )

    def detect_chains(
        self,
        results: list[ValidationResult],
    ) -> list[ExploitChain]:
        """
        Ask Claude to identify exploit chains across all validated findings.
        Returns a list of ExploitChain objects.
        """
        if not results:
            return []

        summaries = []
        for r in results:
            cves = ", ".join(r.finding.cves) or r.finding.plugin_id
            summaries.append(
                f"- {r.finding.host_ip}:{r.finding.port} | {r.finding.plugin_name} "
                f"| CVE: {cves} | Outcome: {r.exploitation_outcome} "
                f"| Severity: {r.realistic_severity}"
            )

        chain_prompt = f"""\
You are analysing validated penetration test findings for exploit chains.

Findings summary:
{chr(10).join(summaries)}

Identify any exploit chains where:
1. An info-disclosure feeds credentials into an auth-required RCE
2. A path traversal + file write enables RCE
3. A low-severity vuln combined with a medium gives high impact
4. Any other meaningful multi-step attack path

For each chain respond with a JSON array:
[
  {{
    "label": "CHAIN: <vuln_a_name> + <vuln_b_name> = <impact>",
    "vuln_a": "<plugin name or CVE>",
    "vuln_b": "<plugin name or CVE>",
    "impact": "<RCE | PrivEsc | DataBreach | etc>",
    "description": "<2-3 sentences describing the full attack path>"
  }}
]

If no meaningful chains exist, return an empty array: []
Respond with JSON only, no markdown fences.
"""
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            response = self.llm.invoke([
                SystemMessage(content="You are an expert penetration tester identifying exploit chains."),
                HumanMessage(content=chain_prompt),
            ])
            raw = response.content if hasattr(response, "content") else str(response)
        except Exception:
            return []

        try:
            items = json.loads(raw.strip())
            return [
                ExploitChain(
                    label=i.get("label", ""),
                    vuln_a=i.get("vuln_a", ""),
                    vuln_b=i.get("vuln_b", ""),
                    impact=i.get("impact", ""),
                    description=i.get("description", ""),
                )
                for i in items
            ]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Error-driven PoC fix (auto-retry loop)
    # ------------------------------------------------------------------

    def fix_poc_for_error(
        self,
        finding: "RawFinding",
        original_code: str,
        error_output: str,
        attempt: int = 1,
    ) -> tuple[str, str, str]:
        """
        Analyse a PoC execution error and return a corrected script.
        Returns (poc_code, poc_filename, poc_language).
        Returns ("", "", "") when the error is not fixable.
        """
        cves     = ", ".join(finding.cves) if finding.cves else finding.plugin_id
        first_cv = finding.cves[0].replace("-", "_") if finding.cves else f"PLUGIN_{finding.plugin_id}"

        prompt = f"""\
A PoC exploit script failed during execution (attempt {attempt}).
Analyse the error and return a corrected version that avoids the same problem.

**Finding:**   {finding.plugin_name}
**CVE(s):**    {cves}
**Target:**    {finding.host_ip}:{finding.port} ({finding.svc_name}/{finding.protocol})

**Original PoC code:**
```
{original_code[:2000]}
```

**Error output (stderr):**
```
{error_output[:800]}
```

FIXING GUIDELINES — apply whichever is relevant:

ModuleNotFoundError / ImportError:
  Rewrite the script to use ONLY these packages (guaranteed on Kali):
  stdlib (socket, ssl, struct, hashlib, hmac, base64, telnetlib, ftplib, http.client, subprocess),
  requests, paramiko, impacket, pycryptodome (Crypto.*), pysnmp, ldap3.
  For example, replace `import des` with a pure-Python DES via `from Crypto.Cipher import DES`.
  NEVER use pip install inside the script — just use available packages.

SyntaxError / NameError:
  Fix invalid placeholder usage. NEVER use <HOST> or <PORT> as variable names.
  CORRECT Python: TARGET_HOST = "<HOST>"   TARGET_PORT = <PORT>
  WRONG Python:   <HOST> = "<HOST>"   (becomes SyntaxError after substitution)

ConnectionRefused / ConnectionError:
  The port or protocol may be wrong. Try the correct transport for the service.

AttributeError / TypeError:
  Fix the API usage — check the correct method signatures.

Only set "fixable" to false if the error proves the host is genuinely not running
the vulnerable service (e.g. "Connection refused" after multiple port attempts),
or the protocol is fundamentally wrong with no alternative approach.
Default to fixable: true and provide corrected code.

CRITICAL SYNTAX RULE:
  NEVER use <HOST> or <PORT> as variable names (left side of assignment).
  CORRECT Python:   TARGET_HOST = "<HOST>"   TARGET_PORT = <PORT>
  CORRECT Bash:     TARGET_HOST="<HOST>"   TARGET_PORT=<PORT>
  WRONG (both):     <HOST>=... or <PORT>=...

Respond with a JSON object (no markdown fences):
{{
  "fixable":   true,
  "diagnosis": "<1-2 sentences — what caused the error and how you fixed it>",
  "language":  "<python | bash>",
  "filename":  "<poc_{finding.plugin_id}_{first_cv}_fix{attempt}.py or .sh>",
  "code":      "<full corrected script as a string>"
}}
"""
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            response = self.llm.invoke([
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
            raw  = response.content if hasattr(response, "content") else str(response)
            data = self._parse_response(raw)
            if data and data.get("code", "").strip():
                # Accept the fix as long as there's actual code, regardless of fixable flag
                fixable = data.get("fixable", True)
                if fixable is False or fixable == "false":
                    return "", "", ""
                lang  = data.get("language", "python")
                fname = data.get("filename", f"poc_{finding.plugin_id}_{first_cv}_fix{attempt}.py")
                return data["code"], fname, lang
        except Exception:
            pass
        return "", "", ""

    # ------------------------------------------------------------------
    # Manual PoC generation (fallback after MSF failure)
    # ------------------------------------------------------------------

    def generate_manual_poc(
        self,
        finding: "RawFinding",
        msf_output: str = "",
    ) -> tuple[str, str, str]:
        """
        Generate a standalone Python/Bash PoC for a finding where Metasploit
        failed or couldn't verify.

        Returns (poc_code, poc_filename, poc_language).
        Returns ("", "", "") on failure.
        """
        cves     = ", ".join(finding.cves) if finding.cves else finding.plugin_id
        first_cv = finding.cves[0].replace("-", "_") if finding.cves else f"PLUGIN_{finding.plugin_id}"

        msf_note = ""
        if msf_output.strip():
            msf_note = f"\n\nMetasploit output (for context — it failed):\n```\n{msf_output[:600]}\n```"

        prompt = f"""\
Metasploit was unable to verify the following vulnerability.
Write a standalone Python (or Bash) exploit script that directly implements
the attack logic WITHOUT relying on Metasploit.

**Finding:**      {finding.plugin_name}
**CVE(s):**       {cves}
**Host:**         {finding.host_ip}:{finding.port} ({finding.svc_name}/{finding.protocol})
**OS:**           {finding.host_os or 'Unknown'}
**CVSS:**         {finding.cvss}
**Synopsis:**     {finding.synopsis}
**Description:**  {finding.description[:800]}
**Plugin Output:**
```
{finding.plugin_output[:600] or 'None'}
```
{msf_note}

Requirements:
- Use <HOST> and <PORT> as placeholders (substituted before execution).
  CRITICAL SYNTAX RULE: NEVER use <HOST> or <PORT> as variable names.
  They must only appear inside quoted strings or as bare command arguments.
  CORRECT Python:   TARGET_HOST = "<HOST>"   TARGET_PORT = <PORT>
  WRONG Python:     <HOST> = "<HOST>"  (becomes SyntaxError after substitution!)
  CORRECT Bash:     TARGET_HOST="<HOST>"   TARGET_PORT=<PORT>
  WRONG Bash:       <HOST>=<HOST>  (becomes bad substitution error!)
- Include the standard header block:
  # Target:      <HOST>:<PORT>
  # CVE:         {cves}
  # Vuln:        {finding.plugin_name}
  # Prereqs:     <what you need>
  # Expected:    <what success looks like>
  # Reliability: <high/medium/low>
  # Tested on:   <versions>
  # Source:      manual reconstruction
- Clear comments explaining each step
- Print clear SUCCESS or FAILURE indication to stdout
- Prefer Python with only stdlib + requests/impacket/paramiko (common on Kali)
- Do NOT produce destructive payloads (no file deletion, encryption, DoS)

Respond with a JSON object (no markdown fences):
{{
  "language":  "<python | bash>",
  "filename":  "<poc_{finding.plugin_id}_{first_cv}_manual.py or .sh>",
  "code":      "<full script as a string>"
}}
"""
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            response = self.llm.invoke([
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
            raw  = response.content if hasattr(response, "content") else str(response)
            data = self._parse_response(raw)
            if data and data.get("code", "").strip():
                lang  = data.get("language", "python")
                fname = data.get("filename", f"poc_{finding.plugin_id}_{first_cv}_manual.py")
                return data["code"], fname, lang
        except Exception:
            pass
        return "", "", ""

    # ------------------------------------------------------------------
    # Execution interpretation
    # ------------------------------------------------------------------

    def interpret_execution(
        self,
        finding: "RawFinding",
        poc_filename: str,
        stdout: str,
        stderr: str,
        heuristic_outcome: str,
    ) -> tuple[str, str]:
        """
        Send PoC execution output to Claude and get back:
          (ai_interpretation: str, captured_data: str)

        captured_data contains any credentials, banners, hashes, flags
        extracted from the raw output.
        Falls back to heuristic_outcome on any error.
        """
        cves = ", ".join(finding.cves) if finding.cves else finding.plugin_id

        prompt = f"""\
You are a penetration tester reviewing the output of an exploit attempt.

**Finding:** {finding.plugin_name}
**CVE(s):** {cves}
**Target:** {finding.host_ip}:{finding.port} ({finding.svc_name})
**PoC Script:** {poc_filename}
**Heuristic Outcome:** {heuristic_outcome}

**STDOUT:**
```
{stdout[:3000] if stdout.strip() else "(empty)"}
```

**STDERR:**
```
{stderr[:1000] if stderr.strip() else "(empty)"}
```

Respond with a JSON object (no markdown fences):
{{
  "outcome":       "<SUCCESS | FAILURE | PARTIAL | ERROR>",
  "captured_data": "<any credentials/banners/hashes/flags/session info extracted from output, or empty string>",
  "interpretation":"<2-3 sentences: what happened, what access was obtained, what the output proves>"
}}

Rules:
- SUCCESS = evidence of access, credentials captured, command executed on target
- PARTIAL = connection established but full exploit failed, OR timed out after connecting
- FAILURE = clear rejection, auth failure, service unreachable
- ERROR   = script crashed, interpreter missing, network error before any contact
- captured_data: extract verbatim any passwords, hashes, session tokens, OS banners, usernames, flags
"""
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            response = self.llm.invoke([
                SystemMessage(content="You are an expert penetration tester interpreting exploit output."),
                HumanMessage(content=prompt),
            ])
            raw = response.content if hasattr(response, "content") else str(response)
            data = self._parse_response(raw)
            if data:
                return (
                    data.get("interpretation", heuristic_outcome),
                    data.get("captured_data", ""),
                )
        except Exception:
            pass

        return heuristic_outcome, ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any] | None:
        """
        Extract JSON from the LLM response.
        Tries direct parse first, then strips markdown fences, then regex.
        """
        text = raw.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
            text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
            text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to extract the first {...} block
        match = re.search(r"\{[\s\S]+\}", text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def _error_result(finding: RawFinding, error_msg: str) -> ValidationResult:
        return ValidationResult(
            finding=finding,
            context_notes=f"[ERROR] {error_msg}",
            evidence_quality="partial",
            exploit_research="Analysis failed — see context_notes",
            exploitation_outcome="Unknown",
            poc_type="D",
            poc_code="",
            poc_filename="",
            poc_language="text",
            poc_reliability="low",
            poc_no_reason=f"Validation error: {error_msg}",
            realistic_severity=finding.nessus_severity_str,
            severity_changed=False,
            severity_justification="Could not re-score due to error.",
            remediation="See official vendor advisory.",
            chain_hint="",
        )
