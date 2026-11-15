"""
PoC execution engine — runs generated exploit scripts and captures output.

Type A (Python)     — run with python3, full stdout/stderr capture
Type B (Bash)       — run with bash (curl / nmap one-liners)
Type C (Metasploit) — run via msfconsole -q -r <file.rc>, full capture
Type D              — skipped, no code to run

Only activated when the user passes --execute to `aiptt validate run`.
"""

from __future__ import annotations

import py_compile
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


def _poe_slug(plugin_name: str, max_len: int = 60) -> str:
    """Filesystem-safe slug from a vulnerability title."""
    s = re.sub(r"[^\w\s\-]", "", plugin_name).strip()
    s = re.sub(r"[\s_]+", "_", s)
    return s[:max_len].rstrip("_")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PoCExecutionResult:
    """Full record of one PoC execution attempt."""
    poc_filename:       str
    target_ip:          str
    target_port:        int

    # Raw execution data
    command_run:        str
    stdout:             str
    stderr:             str
    return_code:        int
    duration_s:         float
    timed_out:          bool

    # AI interpretation
    outcome:            str   # SUCCESS | FAILURE | PARTIAL | ERROR | SKIPPED
    captured_data:      str   # extracted creds, banners, flags, hashes
    ai_interpretation:  str   # 2-3 sentence summary

    # Saved artefact
    poe_artefact_path:  str   # path to the .txt PoE file


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

# Outcome detection is tiered and uses word-boundary / phrase regexes rather
# than naive substring matching. Naive matching caused two classes of bug:
#   1. Ambiguous single characters/words ("$", "#", "password", "connected")
#      scored noise as success.
#   2. Substring matching ignored boundaries, so "unsuccessful" matched the
#      success token "success", and failure phrases went undetected.
# The heuristic is a FAST PRE-PASS only; the AI validator (interpret_execution)
# is the real arbiter, so this errs toward PARTIAL rather than false SUCCESS.

# Decisive evidence of code execution or credential capture.
_STRONG_SUCCESS = [
    r"meterpreter session \d+ opened",
    r"command shell session \d+ opened",
    r"\bsession \d+ opened\b",
    r"\buid=\d+\b.*\bgid=\d+\b",          # id/whoami output, e.g. uid=0(root)
    r"nt authority\\system",
    r"\bflag\{",                           # CTF proof
    r"\broot@[\w.-]+:",                    # interactive root shell prompt
    r"\bhash(?:es)? (?:captured|dumped)\b",
    r"\bsecretsdump\b",
]

# Decisive evidence the exploit did NOT work.
_STRONG_FAILURE = [
    r"exploit completed, but no session was created",
    r"no session was created",
    r"\bexploit failed\b",
    r"\bhandler failed\b",
    r"authentication failed",
    r"\blogin failed\b",
    r"access denied",
    r"permission denied",
    r"connection refused",
    r"connection reset",
    r"no route to host",
    r"could not connect",
    r"\bunreachable\b",
    r"not vulnerable",
    r"\bunsuccessful\b",
    r"traceback \(most recent call last\)",
]

# Suggestive of success, but only trusted when the process also exited cleanly.
_WEAK_SUCCESS = [
    r"login successful",
    r"authentication successful",
    r"access granted",
    r"\blogged in\b",
]

_STRONG_SUCCESS_RE = re.compile("|".join(_STRONG_SUCCESS), re.IGNORECASE)
_STRONG_FAILURE_RE = re.compile("|".join(_STRONG_FAILURE), re.IGNORECASE)
_WEAK_SUCCESS_RE   = re.compile("|".join(_WEAK_SUCCESS), re.IGNORECASE)


# Metasploit-specific output indicators
_MSF_SUCCESS = frozenset({
    "meterpreter session", "command shell session", "session opened",
    "uid=0", "uid=root", "sessions opened", "shell session",
    "stage sent", "sending stage",
})
_MSF_FAILURE = frozenset({
    "exploit completed, but no session",
    "no session was created",
    "exploit failed",
    "handler failed",
})


class PoCExecutor:
    """
    Executes Type-A/B/C PoC scripts against a live target and captures output.
    Type-D findings are skipped.
    """

    def __init__(self, validator=None):
        """
        validator: optional VulnValidator instance for AI interpretation.
        If None, falls back to heuristic-only outcome detection.
        """
        self._validator = validator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        result,                         # ValidationResult from vuln_validator
        poc_dir: Path,
        poe_dir: Path,
        timeout: int = 45,
    ) -> PoCExecutionResult:
        """
        Run the PoC for *result* and return a PoCExecutionResult.
        Saves a plain-text PoE artefact to poe_dir.
        """
        from aiptt.engine.vuln_validator import ValidationResult

        finding = result.finding
        poe_dir.mkdir(parents=True, exist_ok=True)

        # Type C — run via msfconsole (or write .rc if not installed)
        if result.poc_type == "C":
            return self._handle_metasploit(result, poe_dir, timeout)

        # Type D — no PoC
        if result.poc_type == "D" or not result.poc_code.strip():
            return self._skipped(result)

        poc_path = poc_dir / result.poc_filename
        if not poc_path.exists():
            return self._error_result(
                result, f"PoC file not found: {poc_path}"
            )

        # Substitute placeholders
        code = poc_path.read_text(encoding="utf-8", errors="replace")
        code = self._substitute_placeholders(code, finding.host_ip, finding.port)

        # Write substituted copy to a temp file
        suffix = ".py" if result.poc_language == "python" else ".sh"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tf:
            tf.write(code)
            tmp_path = Path(tf.name)

        # Pre-execution syntax validation — catch bad substitutions before running
        syntax_error = self._validate_syntax(tmp_path, result.poc_language)
        if syntax_error:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            return self._error_result(result, f"Syntax validation failed: {syntax_error}")

        try:
            stdout, stderr, rc, duration, timed_out = self._run_script(
                tmp_path, result.poc_language, timeout
            )
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

        # Determine command string for the artefact
        if result.poc_language == "python":
            cmd = f"python3 {result.poc_filename} (target: {finding.host_ip}:{finding.port})"
        else:
            cmd = f"bash {result.poc_filename} (target: {finding.host_ip}:{finding.port})"

        # Heuristic outcome (fast, no AI call)
        outcome = self._heuristic_outcome(stdout, stderr, rc, timed_out)

        # AI interpretation
        ai_interp  = ""
        captured   = ""
        if self._validator is not None:
            ai_interp, captured = self._validator.interpret_execution(
                finding, result.poc_filename, stdout, stderr, outcome
            )
        else:
            ai_interp = f"Heuristic outcome: {outcome}. Return code: {rc}."

        # Build PoE artefact content
        cves         = ", ".join(finding.cves) or finding.plugin_id
        poe_filename = f"poe_{_poe_slug(finding.plugin_name)}.txt"
        poe_path     = poe_dir / poe_filename

        poe_content = _build_poe_artefact(
            plugin_name=finding.plugin_name,
            host_ip=finding.host_ip,
            port=finding.port,
            cves=cves,
            cmd=cmd,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            duration=duration,
            timed_out=timed_out,
            outcome=outcome,
            captured=captured,
            ai_interp=ai_interp,
        )
        poe_path.write_text(poe_content, encoding="utf-8")

        return PoCExecutionResult(
            poc_filename=result.poc_filename,
            target_ip=finding.host_ip,
            target_port=finding.port,
            command_run=cmd,
            stdout=stdout,
            stderr=stderr,
            return_code=rc,
            duration_s=duration,
            timed_out=timed_out,
            outcome=outcome,
            captured_data=captured,
            ai_interpretation=ai_interp,
            poe_artefact_path=str(poe_path),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _substitute_placeholders(code: str, ip: str, port: int) -> str:
        """Replace <HOST>, <PORT>, <HOST>:<PORT> placeholders with real values.

        NOTE: TARGET_HOST / TARGET_PORT are intentional variable *names* that
        Claude uses in assignments like `TARGET_HOST = "<HOST>"`. Do NOT replace
        them — the <HOST>/<PORT> inside the quoted string on the right will be
        replaced by the rules above, which is exactly what we want.
        """
        code = code.replace("<HOST>:<PORT>", f"{ip}:{port}")
        code = code.replace("<HOST>", ip)
        code = code.replace("<PORT>", str(port))
        code = code.replace('"RHOST"', f'"{ip}"')
        code = code.replace("'RHOST'", f"'{ip}'")
        return code

    @staticmethod
    def _run_script(
        script_path: Path,
        language: str,
        timeout: int,
    ) -> tuple[str, str, int, float, bool]:
        """Execute a Python or Bash script file."""
        cmd = ["python3", str(script_path)] if language == "python" else ["bash", str(script_path)]
        return PoCExecutor._run_cmd_list(cmd, timeout)

    @staticmethod
    def _run_cmd_list(
        cmd: list[str],
        timeout: int,
    ) -> tuple[str, str, int, float, bool]:
        """
        Run a command list and return (stdout, stderr, return_code, duration, timed_out).
        """
        start     = time.time()
        timed_out = False
        try:
            proc   = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            rc     = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout    = (exc.stdout or b"").decode("utf-8", errors="replace")
            stderr    = (exc.stderr or b"").decode("utf-8", errors="replace")
            rc        = -1
            timed_out = True
        except FileNotFoundError as exc:
            stdout, stderr, rc = "", f"Binary not found: {exc}", -2
        except Exception as exc:
            stdout, stderr, rc = "", f"Execution error: {exc}", -3

        duration = time.time() - start
        if len(stdout) > 8000:
            stdout = stdout[:8000] + "\n... [truncated]"
        if len(stderr) > 2000:
            stderr = stderr[:2000] + "\n... [truncated]"
        return stdout, stderr, rc, duration, timed_out

    @staticmethod
    def _heuristic_outcome(
        stdout: str, stderr: str, rc: int, timed_out: bool
    ) -> str:
        """
        Fast, conservative outcome pre-pass.

        Decisive signals win first. When the evidence is weak or conflicting we
        return PARTIAL so the AI validator (or a human) adjudicates, rather than
        guessing SUCCESS — a false SUCCESS is the costliest error for a report.
        """
        combined = f"{stdout}\n{stderr}"

        strong_success = bool(_STRONG_SUCCESS_RE.search(combined))
        strong_failure = bool(_STRONG_FAILURE_RE.search(combined))

        # Decisive, unambiguous evidence.
        if strong_success and not strong_failure:
            return "SUCCESS"
        if strong_failure and not strong_success:
            return "FAILURE"
        # Conflicting decisive signals — do not guess.
        if strong_success and strong_failure:
            return "PARTIAL"

        # No decisive signal below this point.
        if timed_out:
            return "PARTIAL"   # hung after connect — inconclusive, needs review

        # A weak success phrase only counts if the process also exited cleanly.
        if rc == 0 and _WEAK_SUCCESS_RE.search(combined):
            return "SUCCESS"
        if rc == 0:
            return "PARTIAL"   # ran cleanly but produced no proof of exploitation
        return "FAILURE"

    @staticmethod
    def _msf_heuristic_outcome(
        stdout: str, stderr: str, rc: int, timed_out: bool
    ) -> str:
        """MSF-specific outcome detection — MSF exit code is unreliable."""
        combined = (stdout + stderr).lower()
        if any(h in combined for h in _MSF_SUCCESS):
            return "SUCCESS"
        if any(h in combined for h in _MSF_FAILURE):
            return "FAILURE"
        if timed_out:
            return "PARTIAL"
        # MSF initialised but no clear result
        if "msf" in combined and rc == 0:
            return "PARTIAL"
        return "FAILURE"

    def _handle_metasploit(
        self, result, poe_dir: Path, timeout: int = 120
    ) -> PoCExecutionResult:
        """
        Write a Metasploit resource script and execute it via msfconsole.
        Uses MSF_TIMEOUT (default 120s) since msfconsole init takes ~20-30s.
        Falls back to writing .rc only if msfconsole is not in PATH.
        """
        finding = result.finding
        cves = ", ".join(finding.cves) or finding.plugin_id

        # Build rc filename
        stem = result.poc_filename
        for ext in (".py", ".sh", ".txt"):
            stem = stem.replace(ext, "")
        rc_filename = stem + ".rc"
        rc_path = poe_dir / rc_filename

        # Substitute placeholders, ensure script ends with 'exit'
        rc_code = self._substitute_placeholders(
            result.poc_code, finding.host_ip, finding.port
        ).rstrip()
        if not any(rc_code.lower().endswith(x) for x in ("exit", "exit\n")):
            rc_code += "\nexit\n"

        rc_path.write_text(
            f"# Metasploit resource script — auto-generated by AIPTT\n"
            f"# Finding: {finding.plugin_name}\n"
            f"# Target:  {finding.host_ip}:{finding.port}\n"
            f"# CVE(s):  {cves}\n\n"
            + rc_code,
            encoding="utf-8",
        )

        msf_bin = shutil.which("msfconsole")
        if not msf_bin:
            poe_path = poe_dir / f"poe_{_poe_slug(finding.plugin_name)}.txt"
            note = "msfconsole not found in PATH — resource script written, run manually."
            poe_path.write_text(
                _build_poe_artefact(
                    plugin_name=finding.plugin_name,
                    host_ip=finding.host_ip, port=finding.port, cves=cves,
                    cmd=f"msfconsole -q -r {rc_path}  [NOT EXECUTED — msfconsole not found]",
                    stdout="", stderr="", rc=0, duration=0,
                    timed_out=False, outcome="SKIPPED", captured="", ai_interp=note,
                ),
                encoding="utf-8",
            )
            return PoCExecutionResult(
                poc_filename=rc_filename, target_ip=finding.host_ip,
                target_port=finding.port,
                command_run=f"msfconsole -q -r {rc_path}",
                stdout="", stderr="", return_code=0, duration_s=0.0,
                timed_out=False, outcome="SKIPPED",
                captured_data="", ai_interpretation=note,
                poe_artefact_path=str(poe_path),
            )

        # Use higher timeout for MSF — init alone takes ~20-30s
        msf_timeout = max(timeout, 120)
        cmd_str = f"msfconsole -q -r {rc_path}"
        stdout, stderr, rc, duration, timed_out = self._run_cmd_list(
            [msf_bin, "-q", "-r", str(rc_path)], msf_timeout
        )

        outcome = self._msf_heuristic_outcome(stdout, stderr, rc, timed_out)

        ai_interp, captured = "", ""
        if self._validator is not None:
            ai_interp, captured = self._validator.interpret_execution(
                finding, rc_filename, stdout, stderr, outcome
            )
        else:
            ai_interp = f"Metasploit outcome: {outcome}. Return code: {rc}."

        poe_path = poe_dir / f"poe_{_poe_slug(finding.plugin_name)}.txt"
        poe_path.write_text(
            _build_poe_artefact(
                plugin_name=finding.plugin_name,
                host_ip=finding.host_ip, port=finding.port, cves=cves,
                cmd=cmd_str, stdout=stdout, stderr=stderr, rc=rc,
                duration=duration, timed_out=timed_out, outcome=outcome,
                captured=captured, ai_interp=ai_interp,
            ),
            encoding="utf-8",
        )

        return PoCExecutionResult(
            poc_filename=rc_filename,
            target_ip=finding.host_ip,
            target_port=finding.port,
            command_run=cmd_str,
            stdout=stdout, stderr=stderr,
            return_code=rc, duration_s=duration, timed_out=timed_out,
            outcome=outcome, captured_data=captured,
            ai_interpretation=ai_interp,
            poe_artefact_path=str(poe_path),
        )

    @staticmethod
    def _validate_syntax(script_path: Path, language: str) -> str:
        """
        Return an error string if the script has syntax errors, else empty string.
        Python: uses py_compile (no subprocess needed).
        Bash:   uses `bash -n` for a dry-run parse.
        """
        if language == "python":
            try:
                py_compile.compile(str(script_path), doraise=True)
                return ""
            except py_compile.PyCompileError as exc:
                return str(exc)
        elif language in ("bash", "sh"):
            bash_bin = shutil.which("bash")
            if bash_bin is None:
                return ""  # can't validate without bash — let it run and fail naturally
            try:
                proc = subprocess.run(
                    [bash_bin, "-n", str(script_path)],
                    capture_output=True, text=True, timeout=10,
                )
                if proc.returncode != 0:
                    return (proc.stderr or "bash syntax error").strip()
                return ""
            except Exception as exc:
                return f"bash -n check failed: {exc}"
        return ""

    @staticmethod
    def _skipped(result) -> PoCExecutionResult:
        return PoCExecutionResult(
            poc_filename=result.poc_filename or "—",
            target_ip=result.finding.host_ip,
            target_port=result.finding.port,
            command_run="—",
            stdout="",
            stderr="",
            return_code=0,
            duration_s=0.0,
            timed_out=False,
            outcome="SKIPPED",
            captured_data="",
            ai_interpretation="No viable PoC — skipped execution.",
            poe_artefact_path="",
        )

    @staticmethod
    def _error_result(result, msg: str) -> PoCExecutionResult:
        return PoCExecutionResult(
            poc_filename=result.poc_filename or "—",
            target_ip=result.finding.host_ip,
            target_port=result.finding.port,
            command_run="—",
            stdout="",
            stderr=msg,
            return_code=-1,
            duration_s=0.0,
            timed_out=False,
            outcome="ERROR",
            captured_data="",
            ai_interpretation=f"Execution error: {msg}",
            poe_artefact_path="",
        )


# ---------------------------------------------------------------------------
# PoE artefact file builder
# ---------------------------------------------------------------------------

def _build_poe_artefact(
    *,
    plugin_name: str,
    host_ip: str,
    port: int,
    cves: str,
    cmd: str,
    stdout: str,
    stderr: str,
    rc: int,
    duration: float,
    timed_out: bool,
    outcome: str,
    captured: str,
    ai_interp: str,
) -> str:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    timeout_note = "  [TIMED OUT]" if timed_out else ""
    lines = [
        "=" * 72,
        "PROOF OF EXPLOITATION ARTEFACT",
        "=" * 72,
        f"Finding:     {plugin_name}",
        f"Host:        {host_ip}:{port}",
        f"CVE(s):      {cves}",
        f"Executed:    {ts}",
        f"Duration:    {duration:.1f}s{timeout_note}",
        f"Return Code: {rc}",
        f"Outcome:     {outcome}",
        "",
        "-" * 72,
        "COMMAND RUN",
        "-" * 72,
        cmd,
        "",
        "-" * 72,
        "STDOUT",
        "-" * 72,
        stdout if stdout.strip() else "(no output)",
        "",
        "-" * 72,
        "STDERR",
        "-" * 72,
        stderr if stderr.strip() else "(no stderr)",
        "",
        "-" * 72,
        "CAPTURED DATA",
        "-" * 72,
        captured if captured.strip() else "(none)",
        "",
        "-" * 72,
        "AI INTERPRETATION",
        "-" * 72,
        ai_interp,
        "=" * 72,
    ]
    return "\n".join(lines) + "\n"
