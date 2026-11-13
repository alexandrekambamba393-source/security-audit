#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

CATEGORIES = [
    "injection", "access_control", "business_logic", "authentication",
    "client_side", "crypto_secrets", "misconfiguration", "other_suspicious",
]
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".next", "coverage", ".tox", ".gradle", "Pods", ".idea", ".vscode",
}
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".tar", ".jar", ".class", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov",
    ".lock", ".min.js", ".map", ".pyc", ".so", ".dll", ".exe", ".bin",
)
MAX_BYTES = 1_000_000
RISK_WORDS = (
    "auth", "login", "session", "token", "jwt", "oauth", "admin", "role", "perm",
    "route", "controller", "handler", "api", "middleware", "view", "endpoint",
    "db", "sql", "query", "repo", "model", "upload", "file", "download", "path",
    "webhook", "payment", "order", "invoice", "password", "reset", "crypto", "secret",
    "config", "setting", "env", "template", "render", "html", "exec", "shell", "proxy",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(target, exclude):
    files = {}
    for dirpath, dirnames, filenames in os.walk(target):
        here = pathlib.Path(dirpath)
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not (here / d).resolve().is_relative_to(exclude)
        ]
        for name in filenames:
            path = here / name
            if path.is_symlink() or name.lower().endswith(SKIP_SUFFIXES):
                continue
            try:
                if path.stat().st_size > MAX_BYTES or path.resolve().is_relative_to(exclude):
                    continue
                with open(path, "rb") as handle:
                    if b"\0" in handle.read(4096):
                        continue
                files[path.relative_to(target).as_posix()] = sha256_file(path)
            except OSError:
                continue
    return files


def latest_prior_run(output_root, run_id):
    candidates = sorted(
        d for d in output_root.glob("audit-*")
        if d.is_dir() and d.name != run_id
    )
    for folder in reversed(candidates):
        if (folder / "coverage.json").exists() or (folder / "findings.json").exists():
            return folder
    return None


def read_json(path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def risk_score(rel):
    lowered = rel.lower()
    return sum(1 for word in RISK_WORDS if word in lowered)


def cmd_plan(args):
    target = pathlib.Path(args.target).resolve()
    output = pathlib.Path(args.output).resolve()
    run_dir = output / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    current = inventory(target, output)
    prior = latest_prior_run(output, args.run_id)

    prior_coverage = {}
    prior_findings = []
    prior_id = None
    if prior:
        prior_id = prior.name
        prior_coverage = read_json(prior / "coverage.json", {}).get("files", {})
        prior_findings = read_json(prior / "findings.json", {}).get("findings", [])

    explore = {c: [] for c in CATEGORIES}
    covered = {c: 0 for c in CATEGORIES}
    for rel, digest in current.items():
        checked = prior_coverage.get(rel, {}).get("checked", {})
        for category in CATEGORIES:
            if checked.get(category) == digest:
                covered[category] += 1
            else:
                explore[category].append(rel)

    for category in CATEGORIES:
        explore[category].sort(key=lambda rel: (-risk_score(rel), rel))
        explore[category] = explore[category][:300]

    recheck = []
    for finding in prior_findings:
        states = []
        for loc in finding.get("locations", []):
            rel = loc.get("file", "")
            if rel not in current:
                state = "missing"
            else:
                before = prior_coverage.get(rel, {}).get("hash")
                state = "unchanged" if before == current[rel] else "changed"
            states.append({"file": rel, "state": state})
        recheck.append({
            "carried_from": finding.get("id"),
            "title": finding.get("title"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "locations": finding.get("locations", []),
            "file_states": states,
        })

    notes = []
    if not prior:
        notes.append("No earlier run found in the output folder. Full exploration.")
    else:
        notes.append(f"Compared against previous run {prior_id}.")
    if len(current) == 0:
        notes.append("No auditable text files were found. Check the target path.")

    plan = {
        "run_id": args.run_id,
        "target": str(target),
        "prior_run": prior_id,
        "files_total": len(current),
        "explore_first": explore,
        "already_covered_unchanged": covered,
        "recheck": recheck,
        "notes": notes,
    }
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    print(f"Files in scope: {len(current)}. Previous run: {prior_id or 'none'}.")
    for category in CATEGORIES:
        print(f"  {category:18} explore {len(explore[category]):4}   already covered {covered[category]:4}")
    print(f"Prior findings to recheck: {len(recheck)}")
    print(f"Plan written to {run_dir / 'plan.json'}")


def cmd_save(args):
    target = pathlib.Path(args.target).resolve()
    output = pathlib.Path(args.output).resolve()
    run_dir = output / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    current = inventory(target, output)
    prior = latest_prior_run(output, args.run_id)
    prior_files = read_json(prior / "coverage.json", {}).get("files", {}) if prior else {}
    examined = read_json(pathlib.Path(args.examined), {}) if args.examined else {}
    examined_sets = {c: set(examined.get(c, [])) for c in CATEGORIES}

    files = {}
    for rel, digest in current.items():
        prev_checked = prior_files.get(rel, {}).get("checked", {})
        checked = {}
        for category in CATEGORIES:
            if rel in examined_sets[category]:
                checked[category] = digest
            elif prev_checked.get(category) == digest:
                checked[category] = digest
        files[rel] = {"hash": digest, "checked": checked}

    coverage = {
        "schema": "coverage-1",
        "run_id": args.run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }
    (run_dir / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    recorded = sum(len(v["checked"]) for v in files.values())
    print(f"Coverage saved: {len(files)} files, {recorded} file/category checks recorded.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("plan", "save"):
        p = sub.add_parser(name)
        p.add_argument("--target", required=True)
        p.add_argument("--output", required=True)
        p.add_argument("--run-id", required=True)
        if name == "save":
            p.add_argument("--examined", help="JSON of {category: [files actually read]}")

    args = ap.parse_args()
    if args.cmd == "plan":
        cmd_plan(args)
    else:
        cmd_save(args)


if __name__ == "__main__":
    sys.exit(main())
