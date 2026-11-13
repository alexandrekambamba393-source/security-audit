#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def load(path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def fence_for(text):
    longest = max((len(run) for run in _backtick_runs(text)), default=0)
    return "`" * max(3, longest + 1)


def _backtick_runs(text):
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
        else:
            if run:
                yield "`" * run
            run = 0
    if run:
        yield "`" * run


def render(run_dir):
    findings_doc = load(run_dir / "findings.json", None)
    if findings_doc is None:
        sys.exit(f"findings.json not found in {run_dir}")
    rejected = load(run_dir / "rejected.json", [])
    plan = load(run_dir / "plan.json", {})
    summary_path = run_dir / "summary.md"
    summary = summary_path.read_text(encoding="utf-8").strip() if summary_path.exists() else ""

    run = findings_doc["run"]
    scope = findings_doc.get("scope", {})
    stats = findings_doc.get("stats", {})
    findings = sorted(
        findings_doc.get("findings", []),
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]),
    )

    out = []
    out.append("# Security audit report")
    out.append("")
    out.append(f"- **Target:** `{run['target']}`")
    if run.get("git_commit"):
        out.append(f"- **Commit:** `{run['git_commit']}`")
    out.append(f"- **Run:** `{run['id']}`")
    out.append(f"- **Finished:** {run['finished_at']}")
    out.append(f"- **Previous run:** {run.get('previous_run') or 'none (first audit of this target)'}")
    out.append("")

    out.append("## Summary")
    out.append("")
    if summary:
        out.append(summary)
    else:
        out.append("No executive summary was written for this run.")
    out.append("")

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    out.append("| Severity | Confirmed |")
    out.append("|---|---|")
    for sev in SEVERITY_ORDER:
        out.append(f"| {SEVERITY_LABEL[sev]} | {counts.get(sev, 0)} |")
    out.append("")
    out.append(
        f"Candidates examined: {stats.get('candidates', 0)} · confirmed: {stats.get('confirmed', 0)} · "
        f"rejected: {stats.get('rejected', 0)} · carried forward from previous run: "
        f"{stats.get('carried_forward', 0)} · resolved since previous run: {stats.get('resolved_since_previous', 0)}"
    )
    out.append("")

    out.append("## Findings at a glance")
    out.append("")
    if findings:
        out.append("| ID | Severity | Category | Title | Primary location |")
        out.append("|---|---|---|---|---|")
        for f in findings:
            loc = f["locations"][0]
            where = f"`{loc['file']}:{loc['start_line']}`"
            title = f["title"].replace("|", "\\|")
            out.append(f"| {f['id']} | {SEVERITY_LABEL[f['severity']]} | {f['category']} | {title} | {where} |")
    else:
        out.append("No confirmed findings in this run.")
    out.append("")

    out.append("## Findings")
    out.append("")
    for f in findings:
        out.append(f"### {f['id']} · {f['title']}")
        out.append("")
        cwe = ", ".join(f.get("cwe", [])) or "n/a"
        out.append(
            f"**Severity:** {SEVERITY_LABEL[f['severity']]} · **Category:** {f['category']} · "
            f"**Confidence:** {f['confidence']} · **CWE:** {cwe}"
        )
        out.append("")
        out.append(f"**Reachability:** {f['entry_point']['reachability']}. {f['entry_point']['description']}")
        out.append("")
        out.append("**Where**")
        out.append("")
        for loc in f["locations"]:
            out.append(f"- `{loc['file']}` lines {loc['start_line']}–{loc['end_line']} ({loc['role']})")
        out.append("")
        for loc in f["locations"]:
            fence = fence_for(loc["snippet"])
            out.append(f"{fence}")
            out.append(loc["snippet"])
            out.append(f"{fence}")
            out.append("")
        out.append("**What happens**")
        out.append("")
        out.append(f["description"])
        out.append("")
        if f.get("data_flow"):
            out.append("**Data flow**")
            out.append("")
            for step in f["data_flow"]:
                out.append(f"- {step}")
            out.append("")
        out.append(f"**Impact:** {f['impact']}")
        out.append("")
        out.append(f"**Fix:** {f['remediation']}")
        out.append("")
        ver = f["verification"]
        out.append(
            f"*Verification: evidence check {ver['evidence_check']}; challenge {ver['challenge']['outcome']}. "
            f"{ver['challenge']['notes']}*"
        )
        if f.get("carried_from"):
            out.append("")
            out.append(f"*Carried forward from {f['carried_from']} and still present in the current code.*")
        out.append("")

    out.append("## Rejected candidates")
    out.append("")
    if rejected:
        out.append("Each candidate below was dropped. The reason names the guard, fact, or failed check.")
        out.append("")
        out.append("| ID | Title | Stage | Reason |")
        out.append("|---|---|---|---|")
        for r in rejected:
            reason = str(r.get("reason", "")).replace("|", "\\|")
            title = str(r.get("title", "")).replace("|", "\\|")
            out.append(f"| {r.get('id', '')} | {title} | {r.get('stage', '')} | {reason} |")
    else:
        out.append("No candidates were rejected.")
    out.append("")

    out.append("## Scope, coverage, and limits")
    out.append("")
    for label, key in (("Included", "included"), ("Excluded", "excluded"), ("Limits", "limits")):
        items = scope.get(key, [])
        out.append(f"**{label}:**")
        out.append("")
        if items:
            for item in items:
                out.append(f"- {item}")
        else:
            out.append("- none recorded")
        out.append("")
    if plan:
        reused = sum(plan.get("already_covered_unchanged", {}).values())
        out.append(
            f"Reuse from earlier runs: {reused} file/category checks skipped because the files were unchanged "
            f"since they were last examined for that category."
        )
        out.append("")
    out.append(
        "This is a static review of source code. It does not run the application or test live systems, "
        "and a clean result does not prove the absence of vulnerabilities."
    )
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    run_dir = pathlib.Path(args.run_dir).resolve()
    report = render(run_dir)
    (run_dir / "report.md").write_text(report, encoding="utf-8")
    print(f"Report written to {run_dir / 'report.md'}")


if __name__ == "__main__":
    main()
