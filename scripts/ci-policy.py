#!/usr/bin/env python3
"""Fail unless committed GitHub workflow YAML matches gate discipline.

Parses `.github/workflows/*.yml` (and `.config/nextest.toml`) rather than
a parallel copy of the job list. Job `continue-on-error` on the per-push
`ci` workflow is allowed only for stress/chaos/soak. Named deterministic
MIT extras must fail-red per SHA.
Samba PAC / realtrust / Heimdal must fail-red on a scheduled workflow.

Gate discipline (docs/testing.md): red-at-HEAD artefacts live under
working/ which is gitignored, so CI cannot check them. This script
checks workflow YAML, gate-script structure, and the MIT parity
ledger `proof` column. `--checkpoint` adds the local-evidence rules the
checkpoint runner owns (W1-Z Z3.4: no cargo build tree under
`working/logs/`).
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ci_policy import main
# Module attributes read by the tools that load this file with importlib (check_policy_module_attrs):
# scripts/kdb-dump-gate.sh and scripts/lib/hygiene_inventory.py.
from ci_policy.common import ROOT
from ci_policy.gates import _dump_key_hexes, check_golden_dump_unique_keys
from ci_policy.ledger import DIFFSEND_CASES, _split_ledger_row, ledger_sources, recount_ledger_verdicts

if __name__ == "__main__":
    main()
