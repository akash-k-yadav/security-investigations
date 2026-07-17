# Security Investigation Writeups

Independent security investigations — reconstructing attack chains from raw evidence, separating confirmed findings from inference, and documenting what couldn't be resolved.

## Structure
```
security-investigation-writeups/
├── traffic-analysis/
│   └── [investigation-name]/
│       ├── background.md          # Source, dataset, and given information
│       ├── incident-report.md     # Short summary — what happened
│       ├── investigation-writeup.md  # Full methodology and evidence
│       └── snapshots/             # Supporting screenshots
│
    (WIP)
```
## How each investigation is documented

- **background.md** — where the dataset came from, and any information given at the start (network layout, domain, environment details).
- **incident-report.md** :- a short, high-level report: what happened, timeline, IOCs, and impact. Written for a reader who wants the outcome, not the process.
- **investigation-writeup.md** :- the full methodology: reasoning, tools used, dead ends, and evidence for each conclusion.
- **snapshots/** — screenshots referenced in the writeup.

Findings are marked **Confirmed** or **Suspected/Unconfirmed** throughout , conclusions aren't forced where evidence doesn't support them.