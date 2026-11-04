"""ci-policy's self-test. Each kept check runs against its green and red fixtures."""

from __future__ import annotations

from .comments import _self_test_comments
from .common import _self_test_git_env_scrub
from .docs import _self_test_docs
from .hygiene import _self_test_hygiene
from .ledger import _self_test_ledger
from .workflows import _self_test_workflows


def _self_test() -> None:
    _self_test_git_env_scrub()
    _self_test_workflows()
    _self_test_ledger()
    _self_test_docs()
    _self_test_hygiene()
    _self_test_comments()
