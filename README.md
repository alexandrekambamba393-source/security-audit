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

Copyright (c) 2026 alexandrekambamba393-source

Copyright (c) 2026 Alexandre Kambamba. All rights reserved.

Permission is hereby granted to any person obtaining a copy of this software 
and associated documentation files (the "Software"), to download and use the 
Software for personal or internal use, subject to the following conditions:

1. The Software may NOT be modified, altered, translated, or adapted in any way.
2. The Software may NOT be used to create derivative works.
3. Redistribution or sublicensing of modified versions of the Software is strictly prohibited.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
