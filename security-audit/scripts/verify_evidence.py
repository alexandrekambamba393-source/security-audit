#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

WS = re.compile(r"\s+")
MIN_EVIDENCE_CHARS = 8


def norm(text):
    return WS.sub(" ", text).strip()


def primary_location(locations):
    if not locations:
        return None
    for loc in locations:
        if loc.get("role") == "sink":
            return loc
    return locations[0]


def fingerprint(category, file, snippet):
    basis = f"{category}|{file}|{norm(snippet)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def snippet_in(block, snippet):
    parts = [norm(p) for p in snippet.split("…")]
    parts = [p for p in parts if p]
    if not parts:
        return False
    pos = 0
    for part in parts:
        idx = block.find(part, pos)
        if idx < 0:
            return False
        pos = idx + len(part)
    return True


def evidence_size(snippet):
    return sum(len(norm(p)) for p in snippet.split("…"))


def check_location(target, loc, cache):
    rel = loc.get("file")
    if not isinstance(rel, str) or not rel:
        return ["missing file"], None

    path = (target / rel).resolve()
    try:
        path.relative_to(target)
    except ValueError:
        return [f"file escapes target tree: {rel}"], None
    if not path.is_file():
        return [f"file not found: {rel}"], None

    if path not in cache:
        cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lines = cache[path]

    snippet = loc.get("snippet")
    if not isinstance(snippet, str) or evidence_size(snippet) < MIN_EVIDENCE_CHARS:
        return [f"snippet missing or shorter than {MIN_EVIDENCE_CHARS} characters"], None

    start, end = loc.get("start_line"), loc.get("end_line")
    if not (isinstance(start, int) and isinstance(end, int)):
        return ["start_line and end_line must be integers"], None
    if not (1 <= start <= end <= len(lines)):
        problems = [f"line range {start}-{end} is outside the file ({len(lines)} lines)"]
        window = max(1, min(end - start + 1, len(lines)))
    else:
        block = norm("\n".join(lines[start - 1:end]))
        if snippet_in(block, snippet):
            return [], None
        problems = [f"snippet not found at lines {start}-{end} of {rel}"]
        window = max(1, end - start + 1)

    for i in range(0, max(1, len(lines) - window + 1)):
        if snippet_in(norm("\n".join(lines[i:i + window])), snippet):
            return problems, {"suggested_start_line": i + 1, "suggested_end_line": i + window}
    return problems, None


def load_candidates(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("candidates", [])
    if not isinstance(data, list):
        raise SystemExit("candidates file must be a list or {\"candidates\": [...]}")
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    target = pathlib.Path(args.target).resolve()
    candidates = load_candidates(args.candidates)
    cache = {}
    results = []

    for index, cand in enumerate(candidates):
        cid = cand.get("id", f"idx-{index}")
        locations = cand.get("locations") or []
        problems_all = []
        loc_results = []

        if not locations:
            problems_all.append("candidate has no locations")

        for loc in locations:
            problems, hint = check_location(target, loc, cache)
            loc_results.append({
                "file": loc.get("file"),
                "ok": not problems,
                "problems": problems,
                **(hint or {}),
            })
            problems_all.extend(f"{loc.get('file')}: {p}" for p in problems)

        primary = primary_location(locations)
        fp = fingerprint(cand.get("category", ""), primary["file"], primary["snippet"]) \
            if primary and isinstance(primary.get("snippet"), str) and primary.get("file") else None

        results.append({
            "id": cid,
            "status": "failed" if problems_all else "passed",
            "problems": problems_all,
            "locations": loc_results,
            "fingerprint": fp,
            "suggested_start_line": next((l.get("suggested_start_line") for l in loc_results if "suggested_start_line" in l), None),
        })

    out = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(target),
        "results": results,
    }
    pathlib.Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")

    passed = sum(r["status"] == "passed" for r in results)
    print(f"Evidence check: {passed} passed, {len(results) - passed} failed, out of {len(results)}")
    for r in results:
        if r["status"] == "failed":
            hint = f" (snippet found near line {r['suggested_start_line']}; fix and re-run)" if r["suggested_start_line"] else ""
            print(f"  FAIL {r['id']}: {'; '.join(r['problems'])}{hint}")


if __name__ == "__main__":
    main()
