#!/usr/bin/env python3
import sys
import os
import re
import json
import sqlite3
import unicodedata
import base64
import subprocess
import uuid
import hashlib
from datetime import datetime

class AgentSecurityEngine:
    def __init__(self, workspace_dir, session_id, raw_prompt=""):
        self.workspace_dir = workspace_dir
        self.session_id = session_id
        self.raw_prompt = raw_prompt
        self.db_path = "/tmp/agent_intel_state.db"
        self.explain_log = []

        # FIX #2 (Critical): historical velocity must be tracked per-repo, not per-session.
        # A session_id is unique per run by design, so filtering history on it always
        # returned zero prior rows. Derive a stable repo_id from the git remote (falling
        # back to the absolute workspace path) so history persists across sessions.
        self.repo_id = self._derive_repo_id()

        self._init_database()
        self.config = self._load_config()
        self.profile = self._determine_context_profile()

    def _derive_repo_id(self):
        try:
            remote = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"], text=True, cwd=self.workspace_dir
            ).strip()
            basis = remote if remote else self.workspace_dir
        except Exception:
            basis = self.workspace_dir
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def _init_database(self):
        """WAL mode for concurrent access, plus a session_state table replacing the
        fragile /tmp/pre_score_{session}.txt file (FIX #3)."""
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_history (
                    session_id TEXT,
                    repo_id TEXT,
                    timestamp DATETIME,
                    jri INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_state (
                    session_id TEXT PRIMARY KEY,
                    repo_id TEXT,
                    prompt_score REAL,
                    created_at DATETIME
                )
            """)

    def _load_config(self):
        config_path = os.path.join(self.workspace_dir, "config/security_profiles.json")
        with open(config_path, "r") as f:
            return json.load(f)

    def _determine_context_profile(self):
        sensitive_patterns = r"(auth|login|jwt|rbac|oauth|session|crypto|credential|privilege|permission|token)"
        refactor_patterns = r"(refactor|restructure|rename across|migrate|reorganize|large-scale rewrite)"

        if re.search(sensitive_patterns, self.raw_prompt, re.IGNORECASE):
            return "security_sensitive"
        # Makes the previously-dead "refactor_heavy" branch in evaluate_behavioral_risk
        # reachable via prompt intent detection, instead of being unreachable dead logic.
        if re.search(refactor_patterns, self.raw_prompt, re.IGNORECASE) and "refactor_heavy" in self.config.get("context_profiles", {}):
            return "refactor_heavy"
        return "default"

    # ==========================================================================
    # PHASE A: PRE-RUNTIME GATEWAY SCANNER
    # ==========================================================================
    def pre_runtime_scan(self):
        if not self.raw_prompt:
            return 0

        norm = unicodedata.normalize("NFKC", self.raw_prompt).lower()
        norm = re.sub(r"<!--.*?-->", "", norm, flags=re.DOTALL)
        norm = re.sub(r"```.*?```", "", norm, flags=re.DOTALL)

        b64_patterns = r"[a-zA-Z0-9+/]{40,}={0,2}"
        for match in re.findall(b64_patterns, norm):
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore").lower()
                norm += " " + decoded
            except Exception:
                pass

        score = 0
        if re.search(r"(ignore previous|system override|bypass restrictions|developer mode)", norm):
            base_risk = 85; confidence = 0.95
            score += (base_risk * confidence)
            self.explain_log.append(f"Prompt Normalizer: Override signature detected (Contribution: +{int(base_risk * confidence)})")
        if re.search(r"(reveal secrets|system prompt|read \.env)", norm):
            base_risk = 60; confidence = 0.90
            score += (base_risk * confidence)
            self.explain_log.append(f"Prompt Normalizer: Target vector probe signature detected (Contribution: +{int(base_risk * confidence)})")

        final_score = min(score, 100)

        thresholds = self.config["context_profiles"][self.profile]["thresholds"]
        if final_score >= thresholds["terminate_quarantine_branch"]:
            print(f"❌ PRE-RUNTIME ENFORCEMENT BLOCK: Prompt payload hazard score [{int(final_score)}] violates policy.")
            sys.exit(403)
        return final_score

    def save_pre_score(self, score):
        """FIX #3: persist pre-runtime score in SQLite instead of a /tmp text file,
        which was prone to stale leftovers, partial writes, and no cleanup path."""
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_state VALUES (?, ?, ?, ?)",
                (self.session_id, self.repo_id, score, datetime.utcnow()),
            )

    def load_pre_score(self):
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT prompt_score FROM session_state WHERE session_id = ?", (self.session_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else 0

    # ==========================================================================
    # PHASE C: POST-RUNTIME METRIC COMPILATION ENGINES
    # ==========================================================================
    def evaluate_dependency_risk(self):
        score = 0
        try:
            diff_files = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True).splitlines()
            manifests = [f for f in diff_files if any(x in f for x in ["package.json", "Cargo.toml", "requirements.txt"])]

            if manifests:
                diff_content = subprocess.check_output(["git", "diff", "--cached"], text=True)
                if re.search(r"^\+.*(http|https|git@):", diff_content, re.MULTILINE):
                    base_risk = 90; confidence = 0.98
                    score += (base_risk * confidence)
                    self.explain_log.append("Dependency Engine: Unapproved remote source fetch registry injection (+88)")
                else:
                    base_risk = 40; confidence = 0.85
                    score += (base_risk * confidence)
                    self.explain_log.append("Dependency Engine: Structural package manifest modification pattern (+34)")
        except Exception:
            pass
        return min(score, 100)

    def evaluate_behavioral_risk(self):
        try:
            files_changed = len(subprocess.check_output(["git", "status", "--porcelain"], text=True).splitlines())
            diff_stats = subprocess.check_output(["git", "diff", "--cached", "--numstat"], text=True).splitlines()
            lines_changed = sum(sum(int(x) for x in line.split()[:2] if x.isdigit()) for line in diff_stats)
        except Exception:
            return 0

        max_files = 12 if self.profile == "refactor_heavy" else 3
        max_lines = 700 if self.profile == "refactor_heavy" else 150

        score = 0
        if files_changed > max_files:
            score += (files_changed - max_files) * 15
            self.explain_log.append(f"Behavior Engine: Churn count drift across {files_changed} files")
        if lines_changed > max_lines:
            score += (lines_changed - max_lines) // 5
            self.explain_log.append(f"Behavior Engine: Volume block scale mutation of {lines_changed} lines")

        return min(score, 100)

    def evaluate_historical_velocity(self):
        """FIX #2 (Critical): now queries by repo_id so history actually accumulates
        across sessions instead of always looking up a session_id with zero prior rows."""
        half_life = self.config["system_settings"]["historical_decay_half_life_days"]
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT timestamp, jri FROM session_history WHERE repo_id = ? ORDER BY timestamp DESC LIMIT 50",
                (self.repo_id,),
            )
            rows = cursor.fetchall()

        if not rows:
            return 0

        decayed_sum = 0
        now = datetime.utcnow()
        for ts_str, past_jri in rows:
            ts = datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d %H:%M:%S")
            days_passed = (now - ts).total_seconds() / 86400.0
            decay_factor = 0.5 ** (days_passed / half_life)
            decayed_sum += past_jri * decay_factor

        score = int(decayed_sum / len(rows))
        if score > 20:
            self.explain_log.append(f"Temporal Memory: Sustained historical anomaly load flagged across repo (+{score})")
        return min(score, 100)

    def verify_clean_secrets(self):
        res = subprocess.run(["trufflehog", "filesystem", "--fail", ".", "--exclude-paths=.aiderignore"], capture_output=True)
        if res.returncode != 0:
            self.explain_log.append("Secret Guard: Active high-entropy match credential leak detected (+100)")
            return False
        return True

    def run_semgrep_ast_diff(self):
        """FIX #5 (Minor): batch all target files into a single semgrep invocation
        instead of spawning one process per file, which doesn't scale on monorepos."""
        try:
            changed_files = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True).splitlines()
            target_modules = [f for f in changed_files if re.search(r"\.(ts|js|py|rs|go)$", f) and os.path.exists(f)]

            if not target_modules:
                return 0

            res = json.loads(subprocess.check_output(
                ["semgrep", "--config=config/rules.semgrep.yml", "--json", *target_modules], text=True
            ))
            violations = len(res.get("results", []))

            if violations > 0:
                base_risk = 90; confidence = 0.95
                weighted_contribution = int(base_risk * confidence * violations)
                self.explain_log.append(f"Semgrep AST Analyzer: {violations} structural security rules violated (Contribution: +{min(weighted_contribution, 100)})")
                return min(weighted_contribution, 100)
        except Exception:
            pass
        return 0

    def compute_and_route_jri(self):
        """Executes full mathematical matrix normalization across all signals."""
        pre_runtime_prompt_score = self.load_pre_score()
        b_score = self.evaluate_behavioral_risk()
        s_score = 100 if not self.verify_clean_secrets() else 0
        d_score = self.run_semgrep_ast_diff()
        dep_score = self.evaluate_dependency_risk()
        h_score = self.evaluate_historical_velocity()

        w = self.config["context_profiles"][self.profile]["weights"]

        jri = (
            (pre_runtime_prompt_score * w["prompt"]) +
            (b_score * w["behavior"]) +
            (d_score * w["diff"]) +
            (s_score * w["secret"]) +
            (dep_score * w["dependency"]) +
            (h_score * w["historical"])
        )

        final_jri = int(min(jri, 100))

        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                "INSERT INTO session_history VALUES (?, ?, ?, ?)",
                (self.session_id, self.repo_id, datetime.utcnow(), final_jri),
            )

        thresholds = self.config["context_profiles"][self.profile]["thresholds"]

        print("\n" + "="*60)
        print(f"🛡️  AUTONOMOUS AGENT RUNTIME RISK ANALYSIS REPORT (JRI: {final_jri}/100)")
        print(f"    Profile Context: {self.profile} | Session: {self.session_id} | Repo: {self.repo_id}")
        print("="*60)
        for entry in self.explain_log:
            print(f"  {entry}")
        print("="*60)

        if final_jri <= thresholds["warn"]:
            print("✅ [POLICY: ALLOW] Workspace metrics normalized. Changes passed forward.")
            sys.exit(0)
        elif final_jri <= thresholds["quarantine"]:
            print("⚠️ [POLICY: WARN] Structural delta divergence flagged. Human gatekeeper override signature forced.")
            sys.exit(0)
        elif final_jri <= thresholds["terminate_quarantine_branch"]:
            print("🚫 [POLICY: QUARANTINE] Agent deviation metrics flagged. Stashing local adjustments...")
            subprocess.run(["git", "stash", "save", f"quarantine_{self.session_id}"])
            sys.exit(2)
        else:
            salt = str(uuid.uuid4())[:4]
            q_branch = f"quarantine/session_{self.session_id}_{salt}"
            print(f"❌ [POLICY: BLOCK & ISOLATE] Threat signatures confirmed.")
            print(f"    Action: Diverting local modifications into transaction quarantine branch: {q_branch}")
            subprocess.run(["git", "checkout", "-b", q_branch])
            subprocess.run(["git", "add", "."])
            subprocess.run(["git", "commit", "-m", "CRITICAL - Security Platform Intercepted Agent Exploit Pipeline", "--no-verify"])
            subprocess.run(["git", "checkout", "-"])
            sys.exit(1)

if __name__ == "__main__":
    mode = sys.argv[1]
    session = sys.argv[2]
    prompt_payload = sys.argv[3] if len(sys.argv) > 3 else ""

    engine = AgentSecurityEngine(workspace_dir=os.getcwd(), session_id=session, raw_prompt=prompt_payload)

    if mode == "pre":
        score = engine.pre_runtime_scan()
        engine.save_pre_score(score)
    elif mode == "post":
        engine.compute_and_route_jri()
