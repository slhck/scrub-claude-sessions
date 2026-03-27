#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "tqdm",
# ]
# ///
"""
Scan and redact secrets from Claude Code session logs using gitleaks.

Scans: ~/.claude/projects/  (session JSONL)
       ~/.claude/debug/     (debug logs)
       ~/.claude/tasks/     (task JSON files)
       ~/.claude/history.jsonl (prompt history)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from multiprocessing import Pool
from pathlib import Path

from tqdm import tqdm

HOME = Path.home()
CLAUDE_ROOT = Path(os.environ.get("CLAUDE_ROOT", HOME / ".claude"))

# ======================================================================================================================
# STYLING

IS_TTY = sys.stdout.isatty()


def style(code: str) -> str:
    return f"\033[{code}m" if IS_TTY else ""


BOLD = style("1")
DIM = style("2")
RED = style("0;31")
GREEN = style("0;32")
YELLOW = style("0;33")
CYAN = style("0;36")
RESET = style("0")


def mask_secret(secret: str) -> str:
    if len(secret) > 12:
        return secret[:4] + "\u00b7" * min(len(secret) - 8, 20) + secret[-4:]
    if len(secret) > 4:
        return secret[:2] + "\u00b7" * (len(secret) - 3) + secret[-1:]
    return "\u00b7\u00b7\u00b7\u00b7"


def short_path(p: str) -> str:
    return p.replace(str(HOME), "~")


def short_path_truncated(p: str, max_len: int = 70) -> str:
    rel = short_path(p)
    if len(rel) > max_len:
        parts = rel.split("/")
        rel = "~/" + "\u2026/" + "/".join(parts[-2:])
    return rel


def human_size(path: Path) -> str:
    try:
        result = subprocess.run(
            ["du", "-sh", str(path)], capture_output=True, text=True
        )
        return result.stdout.split()[0]
    except Exception:
        return "?"


# ======================================================================================================================
# SCAN


@dataclass
class ScanTarget:
    path: Path
    label: str


ALL_TARGET_TYPES = ("projects", "debug", "tasks", "history")


def get_scan_targets(types: list[str] | None = None) -> list[ScanTarget]:
    enabled = set(types) if types else set(ALL_TARGET_TYPES)
    targets = []
    if "projects" in enabled:
        p = CLAUDE_ROOT / "projects"
        if p.is_dir():
            targets.append(ScanTarget(p, "projects (session logs)"))
    if "debug" in enabled:
        p = CLAUDE_ROOT / "debug"
        if p.is_dir():
            targets.append(ScanTarget(p, "debug logs"))
    if "tasks" in enabled:
        p = CLAUDE_ROOT / "tasks"
        if p.is_dir():
            targets.append(ScanTarget(p, "task files"))
    if "history" in enabled:
        p = CLAUDE_ROOT / "history.jsonl"
        if p.is_file():
            targets.append(ScanTarget(p, "prompt history"))
    return targets


# ======================================================================================================================
# GITLEAKS


def scan_target(target_path: str) -> list[dict]:
    """Run gitleaks on a single target. Called in worker processes."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        subprocess.run(
            [
                "gitleaks",
                "dir",
                "--no-banner",
                "--no-color",
                "-r",
                report_path,
                "-f",
                "json",
                target_path,
            ],
            capture_output=True,
            text=True,
        )
        if os.path.getsize(report_path) > 0:
            with open(report_path) as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        return []
    except Exception:
        return []
    finally:
        os.unlink(report_path)


def redact_file(args: tuple[str, list[dict]]) -> tuple[int, bool]:
    """Redact secrets in a single file. Called in worker processes."""
    fpath, file_findings = args
    try:
        with open(fpath, "r", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return 0, False

    total = 0
    for finding in file_findings:
        secret = finding.get("Secret", "")
        if not secret or len(secret) < 4:
            continue
        rule_id = finding.get("RuleID", "unknown")
        replacement = f"[REDACTED-{rule_id}]"
        if secret in content:
            content = content.replace(secret, replacement)
            total += 1

    if total > 0:
        try:
            with open(fpath, "w") as fh:
                fh.write(content)
            return total, True
        except OSError:
            return 0, False
    return 0, False


# ======================================================================================================================
# DELETE


def delete_old_files(targets: list[ScanTarget], days: int) -> tuple[int, int]:
    cutoff = time.time() - days * 86400
    count = 0
    freed = 0
    for target in targets:
        if not target.path.is_dir():
            continue
        for f in target.path.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix not in (".jsonl", ".json", ".txt"):
                continue
            try:
                if f.stat().st_mtime < cutoff:
                    freed += f.stat().st_size
                    f.unlink()
                    count += 1
            except OSError:
                pass
    return count, freed


# ======================================================================================================================
# REPORT


def print_report(findings: list[dict]) -> None:
    by_rule = Counter(f["RuleID"] for f in findings)
    by_file = Counter(f["File"] for f in findings)

    print(f"\n  {RED}{BOLD}{len(findings)}{RESET} potential secret(s) found\n")

    print(f"  {BOLD}By type:{RESET}")
    for rule, count in by_rule.most_common():
        bar = "\u2588" * min(count // 2 + 1, 30)
        print(f"    {rule:35s} {count:4d}  {DIM}{bar}{RESET}")

    print(f"\n  {BOLD}Affected files:{RESET} {len(by_file)}")
    print(f"\n  {BOLD}Top files:{RESET}")
    for fpath, count in by_file.most_common(10):
        rel = short_path_truncated(fpath)
        print(f"    {count:4d}  {DIM}{rel}{RESET}")

    print(f"\n  {BOLD}Sample findings:{RESET}")
    seen_rules: set[str] = set()
    for f in findings:
        if f["RuleID"] in seen_rules:
            continue
        seen_rules.add(f["RuleID"])
        masked = mask_secret(f.get("Secret", ""))
        rel = short_path_truncated(f["File"])
        line = f.get("StartLine", "?")
        print(
            f"    {YELLOW}\u25b8{RESET} [{f['RuleID']}] L{line}: {DIM}{masked}{RESET}"
        )
        print(f"      {DIM}{rel}{RESET}")
        if len(seen_rules) >= 5:
            break


# ======================================================================================================================
# MAIN


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--redact", action="store_true", help="Replace secrets in-place"
    )
    parser.add_argument(
        "--delete", type=int, metavar="DAYS", help="Delete files older than N days"
    )
    parser.add_argument(
        "--report",
        type=str,
        metavar="PATH",
        help="Save JSON report to PATH",
    )
    parser.add_argument(
        "--type",
        "-t",
        action="append",
        metavar="TYPE",
        choices=ALL_TARGET_TYPES,
        help=f"Scan only specific targets (choices: {', '.join(ALL_TARGET_TYPES)}). "
        "Can be repeated. Defaults to all.",
    )
    parser.add_argument(
        "--workers",
        "-j",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )
    args = parser.parse_args()

    if not shutil.which("gitleaks"):
        print(
            f"  {RED}\u2717{RESET} gitleaks not found. Install with: {BOLD}brew install gitleaks{RESET}"
        )
        sys.exit(1)

    if not CLAUDE_ROOT.is_dir():
        print(f"  {RED}\u2717{RESET} {CLAUDE_ROOT} does not exist")
        sys.exit(1)

    targets = get_scan_targets(args.type)
    if not targets:
        print(f"  {YELLOW}!{RESET} No scannable files found in {CLAUDE_ROOT}")
        sys.exit(0)

    # Header
    try:
        version = subprocess.run(
            ["gitleaks", "version"], capture_output=True, text=True
        ).stdout.strip()
    except Exception:
        version = ""
    print()
    print(f"  {BOLD}Claude Code Session Log Scrubber{RESET}")
    print(f"  {DIM}powered by gitleaks {version}{RESET}")
    print()

    for t in targets:
        size = human_size(t.path)
        print(f"  {CYAN}\u25b8{RESET} {t.label}: {BOLD}{size}{RESET}")
    print()

    # Delete old files
    if args.delete is not None:
        print(
            f"  {YELLOW}!{RESET} Deleting files older than {BOLD}{args.delete}{RESET} days..."
        )
        count, freed = delete_old_files(targets, args.delete)
        mb = freed / 1048576
        print(
            f"  {GREEN}\u2713{RESET} Deleted {BOLD}{count}{RESET} files, freed {BOLD}{mb:.1f} MB{RESET}\n"
        )

    # Scan in parallel
    print(f"  {BOLD}Scanning for secrets...{RESET}\n")
    target_paths = [str(t.path) for t in targets]

    with Pool(min(args.workers, len(target_paths))) as pool:
        results = list(
            tqdm(
                pool.imap(scan_target, target_paths),
                total=len(target_paths),
                desc="  Scanning",
                bar_format="  {l_bar}{bar:40}{r_bar}",
                colour="cyan",
            )
        )

    findings: list[dict] = []
    for r in results:
        findings.extend(r)

    if not findings:
        print(f"\n  {GREEN}\u2713 No secrets found.{RESET}\n")
        sys.exit(0)

    print_report(findings)
    print()

    # Save report
    if args.report is not None:
        dest = Path(args.report)
        with open(dest, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"  {CYAN}\u25b8{RESET} Report saved to: {BOLD}{dest}{RESET}")
        print(f"    {DIM}(contains secret values \u2014 handle with care!){RESET}\n")

    # Redact
    if not args.redact:
        print(f"  {DIM}Dry run complete. To redact secrets in-place, run:{RESET}")
        print(f"  {BOLD}{sys.argv[0]} --redact{RESET}\n")
        sys.exit(0)

    print(f"  {BOLD}Redacting secrets...{RESET}\n")

    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["File"], []).append(f)

    work_items = list(by_file.items())

    with Pool(min(args.workers, len(work_items))) as pool:
        results = list(
            tqdm(
                pool.imap(redact_file, work_items),
                total=len(work_items),
                desc="  Redacting",
                bar_format="  {l_bar}{bar:40}{r_bar}",
                colour="green",
            )
        )

    total_redacted = sum(r[0] for r in results)
    files_modified = sum(1 for r in results if r[1])

    print(
        f"\n  {GREEN}\u2713{RESET} Redacted {BOLD}{total_redacted}{RESET} secret(s) across {BOLD}{files_modified}{RESET} file(s)"
    )
    print(f"\n  {DIM}Re-run without --redact to verify no secrets remain.{RESET}\n")


if __name__ == "__main__":
    main()
