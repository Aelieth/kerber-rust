"""ci-policy's self-test: every check against its green and red fixtures, the domains run in
the order they first appear in the single `_self_test` this package was split from."""

from __future__ import annotations

from .comments import _self_test_comments
from .docs import _self_test_docs
from .evidence import _self_test_evidence
from .gates import _self_test_gates_1, _self_test_gates_2
from .hygiene import _self_test_hygiene
from .ledger import _self_test_ledger
from .shell import _self_test_shell
from .workflows import _self_test_workflows


def _self_test() -> None:
    _self_test_workflows()
    _self_test_shell()
    _self_test_ledger()
    _self_test_gates_1()
    _self_test_gates_2()
    _self_test_docs()
    _self_test_hygiene()
    _self_test_evidence()
    _self_test_comments()
