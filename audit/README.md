# Dmint Security Audit & Mutation Testing

This directory consolidates all security audit documentation, attack matrix verifications, and mutation testing infrastructure for the Dmint monorepo.

---

## Directory Layout

```text
audit/
├── README.md               # This guide
├── mutations.json          # Complete catalog of 57 security mutants (MUT-01 to MUT-57)
├── tools/
│   ├── mutate.py           # Automated mutation testing runner
│   ├── verify_report.py    # Audit report integrity verifier
│   └── ev.py               # Audit evidence recorder
├── reports/                # Preserved audit findings and matrices
│   ├── AUDIT_REPORT.md     # Authoritative security audit report
│   ├── attack_matrix.csv   # The 71 audit attack scenarios & verdicts
│   ├── claims.csv          # Security claims verification matrix
│   ├── coverage.md         # Audit test coverage report
│   ├── known_issues.json   # Security issue tracking ledger
│   └── phases/             # Detailed audit phase logs (Phase 0 through 11)
└── results/                # Output directory for generated results (gitignored)
    └── mutants.csv         # Latest mutation testing results
```

---

## Running Mutation Testing

To run the full mutation testing harness across all 57 security mutants:

```bash
# Using the active virtual environment:
python audit/tools/mutate.py
```

### Options & Environment Variables
- **Custom mutations file:** `python audit/tools/mutate.py path/to/mutations.json`
- **Custom output directory:** `export AUDIT_RUN=audit/results`
- **Custom timeout per mutant:** `export MUT_TIMEOUT=300` (default: 300 seconds)

Results are automatically saved to `audit/results/mutants.csv`.
