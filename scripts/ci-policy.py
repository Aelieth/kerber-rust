#!/usr/bin/env python3
"""Fail unless the kept ci-policy checks pass.

Reads the workflow YAML, the Makefile pins, the doc cites, and the
MIT parity ledger. MIT-anchor truth waits for KERBER_MIT_SRC, which
the ledger-mit job sets.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ci_policy import main
# scripts/kdb-dump-gate.sh reads _dump_key_hexes from this module.
from ci_policy.common import ROOT
from ci_policy.golden import _dump_key_hexes, check_golden_dump_unique_keys
from ci_policy.ledger import DIFFSEND_CASES, _split_ledger_row, ledger_sources, recount_ledger_verdicts

if __name__ == "__main__":
    main()
