# security-audit

Skill Claude pour audit de sécurité statique d'un code source, en plusieurs passes.

## Structure

```
SKILL.md                      workflow et déclencheurs (lu par Claude)
references/agents.md          briefs des agents : cartographie, 8 chasseurs, challengers
assets/findings.schema.json   schéma JSON des résultats confirmés
scripts/
  audit_state.py              mémoire entre audits : plan et save (coverage.json)
  verify_evidence.py          vérifie que chaque extrait cité existe au bon endroit
  validate_findings.py        valide findings.json (schéma + preuves + empreintes)
  render_report.py            génère report.md depuis findings.json
tests/
  smoke_test.py               test de bout en bout des scripts
  fixtures/                   petite application d'exemple avec failles volontaires
```

## Tests

```bash
python3 tests/smoke_test.py
```

## Dossiers de sortie

Chaque audit crée `OUTPUT/audit-AAAAMMJJ-HHMMSS/` avec `plan.json`, `recon.json`,
`candidates/`, `challenge/`, `findings.json`, `rejected.json`, `summary.md`,
`report.md` et `coverage.json`. Les audits suivants dans le même `OUTPUT` réutilisent
`coverage.json`.

## Licence

MIT License

Copyright (c) 2026 alexandrekambamba393-source

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
