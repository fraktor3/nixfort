"""The module dependency rule of docs/ARCHITECTURE.md §2, checked on every test run.

A new import that goes against the rule fails here, so the structure described in the documentation
stays the structure of the code."""

import re
from pathlib import Path

APPS = Path(__file__).resolve().parents[2]

# module -> modules it may import (besides core and accounts, which everyone may import)
ALLOWED = {
    "core": set(),
    "accounts": {"inventory"},
    "inventory": {"execution"},
    "policy": {"inventory", "execution"},
    "execution": set(),
    "checks": {"inventory", "execution", "policy"},
    "remediation": {"inventory", "execution", "policy", "checks"},
    "ids": {"inventory", "execution", "policy", "pcap"},
    "pcap": {"execution"},
    "seclog": {"execution", "ids"},
    "reports": {"inventory", "execution", "policy", "checks", "remediation", "ids"},
}
# Read-only exceptions (access checks and summary screens), listed in the same section of the document.
EXCEPTIONS = {
    "core/rbac.py": {"accounts", "inventory"},
    "core/views.py": {"checks", "execution"},
    "core/context_processors.py": {"checks", "execution"},
    "core/templatetags/nx.py": {"checks", "ids", "remediation"},
    "core/management/commands/selfcheck.py": {"execution"},
    "inventory/views.py": {"checks", "ids", "policy", "reports", "seclog"},
}


def test_module_dependency_rule():
    wrong = []
    for path in APPS.rglob("*.py"):
        rel = path.relative_to(APPS).as_posix()
        module = rel.split("/")[0]
        if module not in ALLOWED or "/tests/" in rel or "/migrations/" in rel:
            continue
        allowed = ALLOWED[module] | {"core", "accounts", module} | EXCEPTIONS.get(rel, set())
        for target in re.findall(r"^\s*(?:from|import) apps\.(\w+)", path.read_text(encoding="utf-8"), re.M):
            if target not in allowed:
                wrong.append(f"{rel} -> {target}")
    assert wrong == []
