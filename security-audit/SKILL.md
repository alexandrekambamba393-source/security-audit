---
name: security-audit
description: Run a multi-pass security audit of a codebase. Use whenever the user says "security audit this codebase", "audit this repo", "find security bugs", "review this for vulnerabilities", "pentest the code", or asks for an injection, access-control, auth, business-logic, or client-side security review, even if they never say "audit". The workflow maps the app and its trust boundaries, runs eight specialized bug hunters in parallel, challenges and rejects weak findings, re-checks every finding against the real code, and writes a readable report plus schema-valid JSON. It remembers earlier runs in the output folder so later audits explore new or changed code.
---

# Security audit

This is a static, code-level audit. It finds flaws by reading source code and then checks
each finding against the actual files. It does not run the application, probe live systems,
or write working exploits. Audit only code the user owns or has permission to review, and note
that in the report scope.

Throughout this document, `<skill>` means the directory that contains this SKILL.md.

## Intake

1. **Target.** Use the path the user named. If they named none, use the current working
   directory, but only if it looks like a project (has a manifest or source files). Confirm the
   path exists.
2. **Output folder.** If the user did not give one, ask with AskUserQuestion. Offer
   `<parent of target>/security-audits (Recommended)` as the first option, and let "Other" take
   a custom path. Do not write into the target repository unless the user picks that path. Create
   the folder if it does not exist.
3. **Run id.** Use `audit-YYYYMMDD-HHMMSS` in UTC. The run folder is `OUTPUT/RUN_ID`. Create
   it. Keep this id for the whole run.

Tell the user in one or two sentences what is about to happen: an audit in several passes, with
parallel agents, that will take a while. Then start.

## Phase 1: Plan from earlier runs

```bash
python3 <skill>/scripts/audit_state.py plan --target TARGET --output OUTPUT --run-id RUN_ID
```

Read `RUN/plan.json`. If it names a prior run, tell the user something like "Found the previous
audit `<prior>`. I will skip N unchanged file and category pairs and recheck M earlier
findings." If there is no prior run, say that this is a full first audit.

Earlier runs are used through the coverage file. A file that was unchanged since a category last
examined it is not re-examined for that category. Changed files are examined again. Earlier
confirmed findings go to the recheck list and are tested again in Phase 4.

## Phase 2: Map the application

Spawn one general-purpose agent with the **Recon** brief from `<skill>/references/agents.md`.
Pass it the target path, the run folder, and the `plan.json` path. It writes `recon.json` and
`recon-notes.md`.

When it finishes, check the map yourself. Read `recon.json`, pick three entry points and confirm
their files exist with Read or Glob. If the map is thin (no entry points found in a web or API
project, or no trust boundaries), rerun recon once with a note about what was missed.

## Phase 3: Hunt in parallel

Spawn eight hunters in a single message, so they run concurrently. One per category:
`injection`, `access_control`, `business_logic`, `authentication`, `client_side`,
`crypto_secrets`, `misconfiguration`, `other_suspicious`.

Each hunter gets the **Hunter (shared rules)** brief plus its category section from
`<skill>/references/agents.md`, along with the target, recon path, and plan path. Each writes
`RUN/candidates/CATEGORY.json` and `RUN/examined/CATEGORY.json`.

A hunter may report zero candidates. Do not push one to find something.

## Phase 4: Consolidate

Merge the eight candidate files into `RUN/candidates.json` as `{"candidates": [...]}`.

- Give each candidate a unique id `C-001`, `C-002`, and so on, and keep the hunter's own id in a
  `hunter_id` field.
- Dedupe when two candidates share a category, a primary file, and overlapping lines. Keep the
  one with more evidence and note the merge.
- Add the recheck items from `plan.json` as candidates with `"recheck": true`. Use their
  `carried_from` value and their locations.

Build `RUN/examined.json` as `{category: [files]}` from the eight `examined` lists. The coverage
record uses it.

## Phase 5: Verify evidence (hard gate)

```bash
python3 <skill>/scripts/verify_evidence.py --target TARGET --candidates RUN/candidates.json --out RUN/verified.json
```

A candidate is not confirmed unless every cited snippet matches the code at its cited lines. The
script reports which ones failed and suggests a corrected line range when the snippet appears
nearby. Fix the candidate's line numbers where the suggestion is clearly right, then run the
script once more. Candidates that still fail are rejected with `stage: "evidence"` and the
reason from the script.

## Phase 6: Challenge

Take the candidates that passed evidence, excluding recheck items. Group them into batches of up
to four. Spawn one challenger agent per batch, all in one message, using the **Challenger** brief
in `<skill>/references/agents.md`. Write each batch to `RUN/challenge/batch-N.json`.

Apply the verdicts:
- `survive`: the candidate is confirmed, with its original severity.
- `downgrade`: the candidate is confirmed with `severity_after`.
- `reject`: the candidate goes to `rejected.json` with `stage: "challenge"` and the notes.

Recheck items skip the challenge. They already survived in an earlier run. Each one is either
still present, which carries it forward, or gone, which records it as resolved. A recheck item
counts as present only if its evidence check passed in Phase 5.

## Phase 7: Write the results

Assemble `RUN/findings.json` to match `<skill>/assets/findings.schema.json`.

For each confirmed finding:
- Assign `F-001`, `F-002`, and so on, in the order of severity, then id.
- Copy the hunter's fields. Put the sink location first, and set `role` on every location.
- Set `fingerprint` to the value in `verified.json` for that candidate. Do not compute it again by
  hand.
- Set `verification.evidence_check` to `"passed"`. Set `verification.challenge.outcome` to
  `"survived"` or `"downgraded"`, and copy the challenger's notes.
- Set `carried_from` to the earlier finding id for recheck items, otherwise `null`.

Fill `run`: `started_at`, `finished_at`, `target`, `git_commit` (from `git rev-parse HEAD` in the
target, or `null` when it is not a git repo), and `previous_run` from `plan.json`. Fill `scope`
with the included and excluded areas and any limits you hit, such as files skipped for size or
binary content. Fill `stats` with the counts.

Write `RUN/rejected.json` as a list of `{id, title, category, stage, reason}` objects. Write
`RUN/summary.md`, which is an executive summary of 6 to 10 sentences. Every claim in it must match
a confirmed finding. Do not describe clean areas as safe. Say only what was examined.

Validate, and repeat until it passes:

```bash
python3 <skill>/scripts/validate_findings.py --target TARGET --findings RUN/findings.json
```

The script checks the schema, unique ids, fingerprints, and every snippet again. Any failure
means a confirmed finding is not supported by the code, so fix or remove it. Do not weaken the
check.

## Phase 8: Report, save state, deliver

```bash
python3 <skill>/scripts/render_report.py --run-dir RUN
python3 <skill>/scripts/audit_state.py save --target TARGET --output OUTPUT --run-id RUN_ID --examined RUN/examined.json
```

Read `RUN/report.md` once, to check that the summary and the finding counts agree with
`findings.json`. Fix the summary if they do not.

Send the user `report.md` and `findings.json` with SendUserFile.

Your final message should be short:
- The counts by severity.
- The top three findings, one line each, with their ids and file locations.
- How many candidates were rejected, and the main reasons in one sentence.
- What was reused from the previous run.
- The paths to `report.md` and `findings.json`.

## Rules that hold across phases

- Never list a finding as confirmed unless its evidence check passed. The validator enforces this,
  and so should you.
- Judge severity by reachability and impact. A bug an unauthenticated user can reach outranks the
  same bug behind admin login.
- Do not write exploit payloads, even in the report. Describe the flaw, the input class, and the
  fix.
- Do not claim a clean result for an area that was not examined. The report's scope section must
  say what was covered.
- If the run is interrupted, the run folder shows where it stopped. Resume at the first missing
  artifact instead of starting over. Do not run the planner again, since it would overwrite the
  plan.
- Dependency CVEs are out of scope unless the user asks for them. This audit does not query
  vulnerability databases.
