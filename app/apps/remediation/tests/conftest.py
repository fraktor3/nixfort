"""Shared fixtures: lab nodes with confirmed host keys and a baseline audit from real lab facts (S-001)."""

import json
from pathlib import Path

import pytest
from django.utils import timezone

from apps.checks.tests.test_engine import FX
from apps.execution import services
from apps.execution.models import JobType
from apps.inventory.models import HostKey, InventorySnapshot


@pytest.fixture
def lab(project, lab_nodes, admin):
    for n in lab_nodes.values():
        HostKey.objects.create(
            node=n,
            key_type="ssh-ed25519",
            public_key="AAAA",
            fingerprint_sha256="x",
            confirmed_by=admin,
            confirmed_at=timezone.now(),
        )
    return lab_nodes


@pytest.fixture
def baseline_run(project, lab, operator, monkeypatch):
    def collect(node, job=None, log=None):
        facts = json.loads((Path(FX) / f"lab_{node.name.replace('nx-', '')}_baseline.json").read_text("utf-8"))
        return InventorySnapshot.objects.create(
            node=node, job=job, collected_at=timezone.now(), facts=facts, agent_version="1.0.0", sha256="0" * 64
        )

    monkeypatch.setattr("apps.inventory.collector.collect_node", collect)
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    return job.audit_run
