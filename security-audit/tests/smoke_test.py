import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FIX = ROOT / "tests" / "fixtures"
SAMPLE = FIX / "sample_app"


def run(*args):
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        out = tmp / "verified.json"
        r = run(SCRIPTS / "verify_evidence.py", "--target", SAMPLE,
                "--candidates", FIX / "candidates_example.json", "--out", out)
        results = {x["id"]: x["status"] for x in json.loads(out.read_text())["results"]}
        assert results == {"H-1": "passed", "H-2": "failed", "H-3": "failed", "H-4": "failed"}, results

        run_dir = tmp / "audit-20261113-180900"
        run_dir.mkdir()
        fp = json.loads(out.read_text())["results"][0]["fingerprint"]
        findings = {
            "schema_version": "1.0",
            "run": {"id": "audit-20261113-180900", "started_at": "2026-11-13T15:09:00Z",
                    "finished_at": "2026-11-13T15:30:00Z", "target": str(SAMPLE),
                    "git_commit": None, "previous_run": None},
            "scope": {"included": ["app/"], "excluded": [], "limits": []},
            "findings": [{
                "id": "F-001", "title": "SQL built by concatenation in get_user",
                "category": "injection", "severity": "high", "confidence": "high",
                "hunter": "injection", "cwe": ["CWE-89"],
                "locations": [{"file": "app/views.py", "start_line": 5, "end_line": 5,
                               "snippet": 'conn.execute("SELECT * FROM users WHERE id = " + user_id)',
                               "role": "sink"}],
                "entry_point": {"description": "get_user reads request.args directly",
                                "reachability": "unauthenticated"},
                "data_flow": ["request.args['id'] -> user_id -> SQL string"],
                "description": "The id query parameter is concatenated into the SQL string.",
                "impact": "Read or modify any table the database account can reach.",
                "remediation": "Use a parameterized query.",
                "fingerprint": fp,
                "verification": {"evidence_check": "passed",
                                 "challenge": {"outcome": "survived", "notes": "No guard between source and sink."}},
                "carried_from": None}],
            "stats": {"candidates": 4, "confirmed": 1, "rejected": 3,
                      "carried_forward": 0, "resolved_since_previous": 0}}
        fpath = run_dir / "findings.json"
        fpath.write_text(json.dumps(findings))
        r = run(SCRIPTS / "validate_findings.py", "--target", SAMPLE, "--findings", fpath)
        assert r.returncode == 0, r.stdout + r.stderr

        bad = json.loads(fpath.read_text())
        bad["findings"][0]["locations"][0]["snippet"] = "conn.execute(\"SELECT id FROM fake\")"
        fpath.write_text(json.dumps(bad))
        r = run(SCRIPTS / "validate_findings.py", "--target", SAMPLE, "--findings", fpath)
        assert r.returncode == 1, "tampered snippet must fail validation"

        state = tmp / "state"
        r = run(SCRIPTS / "audit_state.py", "plan", "--target", SAMPLE, "--output", state, "--run-id", "audit-20261113-180900")
        assert r.returncode == 0, r.stderr
        ex = tmp / "examined.json"
        ex.write_text(json.dumps({"injection": ["app/views.py"]}))
        r = run(SCRIPTS / "audit_state.py", "save", "--target", SAMPLE, "--output", state,
                "--run-id", "audit-20261113-180900", "--examined", ex)
        assert r.returncode == 0, r.stderr
        r = run(SCRIPTS / "audit_state.py", "plan", "--target", SAMPLE, "--output", state, "--run-id", "audit-20261113-190000")
        assert r.returncode == 0, r.stderr
        plan = json.loads((state / "audit-20261113-190000" / "plan.json").read_text())
        assert plan["prior_run"] == "audit-20261113-180900"

    print("smoke test passed")


if __name__ == "__main__":
    main()
