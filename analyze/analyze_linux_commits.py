#!/usr/bin/env python3
"""
analyze_linux_commits.py

Single-file script to:
1) Read COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_CWE from new_vulnerabilities table.
2) For each commit (assumed Linux kernel), fetch the vulnerable vs. patched code blocks.
3) Run all 10 LLMs from src.config.Config.MODELS on 4 prompts each.
4) Store partial-credit results in newly created tables named 2025_<MODEL>.

Place this file at: /users/azibaeir/Research/Benchmarking/project/analyze/analyze_linux_commits.py
"""

import os
import logging
import sqlite3
import subprocess
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# ----------------------------------------------------------------
# Import from your existing codebase
# Adjust these imports if your directory structure differs,
# e.g. from scripts.run_analysis import VulnerabilityAnalyzer, etc.
# or from your local "src" package:
# ----------------------------------------------------------------
from src.config import Config
from src.llm_interaction import LLMInteraction
from src.database import Database
from src.utils.model_manager import ModelManager
# If you need the vulnerability data structure:
from src.models import VulnerabilityData

# Configure more detailed logging
log_dir = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(log_dir, "logs"), exist_ok=True)
log_file = os.path.join(log_dir, "logs", f"linux_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Location of your main DB
DB_PATH = Config.DATABASE_PATH

# Where to clone or update the Linux kernel
LINUX_GIT_URL = "https://github.com/torvalds/linux.git"
LINUX_LOCAL_PATH = "/users/azibaeir/Research/Benchmarking/linux"

# 4 prompts
PROMPTS = ["baseline", "cot", "think", "think_verify"]


def ensure_linux_repo_cloned() -> None:
    """Clone or fetch the Linux kernel repo, if needed."""
    if not os.path.isdir(LINUX_LOCAL_PATH):
        logger.info(f"Cloning Linux kernel into {LINUX_LOCAL_PATH}")
        subprocess.run(["git", "clone", LINUX_GIT_URL, LINUX_LOCAL_PATH], check=True)
    else:
        logger.info("Linux repo already exists, fetching updates...")
        subprocess.run(["git", "-C", LINUX_LOCAL_PATH, "fetch", "origin"], check=True)


def checkout_commit_and_get_diff(commit_hash: str) -> str:
    """
    For the given commit hash, run `git diff <commit>^!` to retrieve the code changes
    introduced by that commit. Return the diff text.
    """
    # Make sure we're on 'master' or 'main' first, so we have a known reference
    subprocess.run(["git", "-C", LINUX_LOCAL_PATH, "checkout", "master"], check=True)
    # Then get the diff text
    cmd = ["git", "-C", LINUX_LOCAL_PATH, "diff", f"{commit_hash}^!"]
    diff_text = subprocess.check_output(cmd, encoding="utf-8")
    return diff_text


def extract_vulnerable_and_patched_code(diff_text: str) -> Tuple[str, str]:
    """
    Combine lines starting with '-' into one big 'vulnerable' code block,
    and lines starting with '+' into one big 'patched' code block.
    Skips lines that begin with --- or +++ which show file names, etc.
    """
    old_lines = []
    new_lines = []
    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            old_lines.append(line[1:])
        elif line.startswith("+"):
            new_lines.append(line[1:])
    vuln_code = "\n".join(old_lines)
    patch_code = "\n".join(new_lines)
    return (vuln_code, patch_code)


def fetch_linux_commits() -> List[Dict[str, str]]:
    """
    Query new_vulnerabilities for (commit_hash, VULNERABILITY_CVE, VULNERABILITY_CWE)
    where the project is presumably 'linux'.
    Return as a list of dicts.
    """
    results = []
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_CWE
            FROM new_vulnerabilities
            WHERE project='linux'
        """)
        rows = cursor.fetchall()
        for row in rows:
            results.append({
                "commit_hash": row[0],
                "cve": row[1],
                "cwe": row[2],
            })
    logger.info(f"Fetched {len(results)} Linux commits from new_vulnerabilities.")
    return results


def create_table_2025(model_name: str) -> None:
    """
    Create a table named 2025_<model> with columns for each prompt × (vuln, patch).
    E.g. 2025_deepseek_v2_16b => columns:
       baseline_vuln, baseline_patch,
       cot_vuln, cot_patch, cot_reasoning_vuln, cot_reasoning_patch, etc.
    """
    tbl = f"2025_{model_name.replace('-', '_').replace('.', '_')}"
    sql = f"""
    CREATE TABLE IF NOT EXISTS {tbl} (
        COMMIT_HASH TEXT PRIMARY KEY,
        BASELINE_VULN INT,
        BASELINE_PATCH INT,
        COT_VULN INT,
        COT_PATCH INT,
        COT_REASONING_VULN TEXT,
        COT_REASONING_PATCH TEXT,
        THINK_VULN INT,
        THINK_PATCH INT,
        THINK_REASONING_VULN TEXT,
        THINK_REASONING_PATCH TEXT,
        THINK_VERIFY_VULN INT,
        THINK_VERIFY_PATCH INT,
        THINK_VERIFY_REASONING_VULN TEXT,
        THINK_VERIFY_REASONING_PATCH TEXT
    )
    """
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    logger.info(f"Created or verified table: {tbl}")


def store_result(model_name: str, commit_hash: str, prompt: str, is_vuln: bool, decision: int, reasoning: str = None) -> None:
    """
    Insert or update an integer `decision` (0=no vuln, 1=vuln, 2=ambiguous) 
    and reasoning text in the 2025_<model> table.
    """
    tbl = f"2025_{model_name.replace('-', '_').replace('.', '_')}"
    col = f"{prompt.upper()}_{'VULN' if is_vuln else 'PATCH'}"
    
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        
        # For baseline, we only store the decision (no reasoning)
        if prompt == "baseline" or reasoning is None:
            cur.execute(f"""
                INSERT INTO {tbl} (COMMIT_HASH, {col})
                VALUES (?, ?)
                ON CONFLICT(COMMIT_HASH) DO UPDATE SET {col} = excluded.{col}
            """, (commit_hash, decision))
        else:
            # For other prompts, also store the reasoning
            reasoning_col = f"{prompt.upper()}_REASONING_{'VULN' if is_vuln else 'PATCH'}"
            cur.execute(f"""
                INSERT INTO {tbl} (COMMIT_HASH, {col}, {reasoning_col})
                VALUES (?, ?, ?)
                ON CONFLICT(COMMIT_HASH) DO UPDATE SET 
                    {col} = excluded.{col},
                    {reasoning_col} = excluded.{reasoning_col}
            """, (commit_hash, decision, reasoning))
        
        conn.commit()


def run_analysis_on_linux_commits():
    """
    Main driver:
    1) Ensure Linux repo is cloned.
    2) Read commits from new_vulnerabilities (Linux).
    3) For each of the 10 models in Config.MODELS, create table 2025_<model>, run 4 prompts (vuln+patch).
    """
    total_start_time = time.time()
    logger.info("Starting automated analysis of Linux commits with all LLMs")
    
    try:
        ensure_linux_repo_cloned()
        linux_records = fetch_linux_commits()
        if not linux_records:
            logger.warning("No Linux commits found in new_vulnerabilities. Exiting.")
            return

        total_models = len(Config.MODELS)
        total_commits = len(linux_records)
        logger.info(f"Will process {total_commits} commits with {total_models} models ({total_models * total_commits * len(PROMPTS) * 2} total LLM calls)")
        
        # The 10 models from your config
        for model_idx, (model_name, model_cmd) in enumerate(Config.MODELS.items(), 1):
            model_start_time = time.time()
            logger.info(f"\n=== Processing Model {model_idx}/{total_models}: {model_name} ===")
            create_table_2025(model_name)
            
            # For each commit
            for commit_idx, record in enumerate(linux_records, 1):
                commit_hash = record["commit_hash"]
                cve = record["cve"] or ""
                cwe = record["cwe"] or ""
                logger.info(f"Analyzing commit {commit_idx}/{total_commits}: hash={commit_hash[:8]}, CVE={cve}, CWE={cwe}")

                # Extract code from git
                try:
                    diff_text = checkout_commit_and_get_diff(commit_hash)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Could not diff commit {commit_hash}: {e}")
                    continue

                vuln_code, patch_code = extract_vulnerable_and_patched_code(diff_text)
                
                # Initialize LLM for this model
                try:
                    llm = LLMInteraction(DB_PATH, model_name)  # from your code
                except Exception as e:
                    logger.error(f"Failed to initialize LLM for {model_name}: {str(e)}")
                    continue

                # For each prompt
                for prompt_idx, prompt in enumerate(PROMPTS, 1):
                    logger.info(f"  Running prompt {prompt_idx}/{len(PROMPTS)}: {prompt}")
                    
                    # (1) Vulnerable code
                    try:
                        prompt_text_vuln = llm.strategies[prompt].create_prompt(vuln_code, cwe)
                        # Actually call the LLM
                        resp_vuln = llm.query_model(prompt_text_vuln)
                        if resp_vuln is None:
                            decision_vuln = 2  # ambiguous
                            store_result(model_name, commit_hash, prompt, True, decision_vuln)
                        else:
                            decision_vuln = llm.strategies[prompt].parse_response(resp_vuln)
                            if decision_vuln is None:
                                decision_vuln = 2
                            # Store both decision and reasoning (full response) for non-baseline prompts
                            store_result(model_name, commit_hash, prompt, True, decision_vuln, 
                                        reasoning=None if prompt == "baseline" else resp_vuln)
                        logger.info(f"    Vulnerable code analysis: decision={decision_vuln}")
                    except Exception as e:
                        logger.error(f"Error processing vulnerable code with {prompt}: {str(e)}")
                        store_result(model_name, commit_hash, prompt, True, 2)  # store as ambiguous

                    # (2) Patched code
                    try:
                        prompt_text_patch = llm.strategies[prompt].create_prompt(patch_code, cwe)
                        resp_patch = llm.query_model(prompt_text_patch)
                        if resp_patch is None:
                            decision_patch = 2
                            store_result(model_name, commit_hash, prompt, False, decision_patch)
                        else:
                            decision_patch = llm.strategies[prompt].parse_response(resp_patch)
                            if decision_patch is None:
                                decision_patch = 2
                            # Store both decision and reasoning (full response) for non-baseline prompts
                            store_result(model_name, commit_hash, prompt, False, decision_patch,
                                        reasoning=None if prompt == "baseline" else resp_patch)
                        logger.info(f"    Patched code analysis: decision={decision_patch}")
                    except Exception as e:
                        logger.error(f"Error processing patched code with {prompt}: {str(e)}")
                        store_result(model_name, commit_hash, prompt, False, 2)  # store as ambiguous

            model_elapsed_time = time.time() - model_start_time
            logger.info(f"Completed model {model_name}: Time taken: {model_elapsed_time:.2f}s ({model_elapsed_time/60:.2f}min)")

        total_elapsed_time = time.time() - total_start_time
        logger.info(f"All models done. Total time: {total_elapsed_time:.2f}s ({total_elapsed_time/60:.2f}min)")
    
    except Exception as e:
        import traceback
        logger.error(f"Unexpected error during analysis: {str(e)}")
        logger.error(traceback.format_exc())
        raise


def main():
    """Main entry point that runs the analysis without requiring any user input."""
    run_analysis_on_linux_commits()


if __name__ == "__main__":
    main()
