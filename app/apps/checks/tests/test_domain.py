"""Every check on real lab data (S-001) plus synthetic PASS/FAIL/UNKNOWN/ERROR variants."""

import copy
import json
from pathlib import Path

import pytest

from apps.checks import domain
from apps.checks.domain import ERROR, FAIL, NA, PASS, UNKNOWN, Ctx

FX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FX / f"lab_{name}_baseline.json").read_text(encoding="utf-8"))


SERVER_CTX = Ctx(roles=frozenset({"server"}), expected_tcp_ports=frozenset({22, 80}), controller_ip="10.77.0.10")
GW_CTX = Ctx(
    roles=frozenset({"gateway", "ids_sensor"}),
    expected_tcp_ports=frozenset({22}),
    ids_interface="enp0s9",
    controller_ip="10.77.0.10",
    active_policy_version=1,
)


def run_all(facts, ctx):
    return {c.id: domain.evaluate(c, facts, ctx).status for c in domain.CATALOG}


def test_catalog_has_21_unique_checks():
    assert len(domain.CATALOG) == 21
    assert len({c.id for c in domain.CATALOG}) == 21
    for c in domain.CATALOG:
        assert c.source_ref and c.title and c.facts


def test_lab_server_baseline_matches_reality():
    """nx-server as delivered by Ubuntu 24.04 + lab defects (lab-extra :8080)."""
    got = run_all(load("server"), SERVER_CTX)
    assert got == {
        "SYS-01": PASS,
        "SYS-02": PASS,
        "SYS-03": PASS,
        "SYS-04": FAIL,
        "SSH-01": FAIL,
        "SSH-02": FAIL,
        "SSH-03": PASS,
        "SSH-04": FAIL,
        "SSH-05": FAIL,
        "SSH-06": FAIL,
        "SSH-07": PASS,
        "FW-01": NA,
        "FW-02": NA,
        "FW-03": NA,
        "FW-04": NA,
        "F2B-01": FAIL,
        "F2B-02": FAIL,
        "F2B-03": FAIL,
        "IDS-01": NA,
        "IDS-02": NA,
        "IDS-03": NA,
    }


def test_lab_gateway_baseline_matches_reality():
    got = run_all(load("gateway"), GW_CTX)
    assert got["FW-01"] == PASS  # nftables installed, no ufw/firewalld/docker
    assert got["FW-02"] == FAIL and got["FW-03"] == FAIL
    assert got["FW-04"] == NA  # nothing applied yet: access not restricted
    assert got["IDS-01"] == FAIL and got["IDS-02"] == FAIL and got["IDS-03"] == FAIL
    assert got["F2B-01"] == NA and got["SYS-04"] == PASS


def test_fw02_unknown_without_active_policy():
    ctx = Ctx(roles=frozenset({"gateway"}), controller_ip="10.77.0.10", active_policy_version=None)
    assert domain.evaluate(domain.BY_ID["FW-02"], load("gateway"), ctx).status == UNKNOWN


def hardened_server():
    f = load("server")
    eff = f["ssh"]["result"]["effective"]
    eff.update(
        permitrootlogin="no", passwordauthentication="no", maxauthtries="4", logingracetime="60", x11forwarding="no"
    )
    f["listeners"]["result"]["listeners"] = [x for x in f["listeners"]["result"]["listeners"] if x["port"] != 8080]
    f["system"]["result"]["packages"]["fail2ban"] = "1.0.2-3ubuntu0.1"
    f["system"]["result"]["services"]["fail2ban"] = "active"
    f["fail2ban"]["result"] = {
        "installed": True,
        "service": "active",
        "jails": ["sshd"],
        "sshd": {"enabled": True, "maxretry": 5, "bantime": 600, "findtime": 600},
    }
    return f


def test_hardened_server_all_pass():
    got = run_all(hardened_server(), SERVER_CTX)
    assert {k: v for k, v in got.items() if v != NA} == {k: PASS for k, v in got.items() if v != NA}


def hardened_gateway():
    f = load("gateway")
    f["nft"]["result"].update(
        nixfort_table_present=True,
        nixfort_chains={"input": {"hook": "input", "policy": "drop"}, "forward": {"hook": "forward", "policy": "drop"}},
        nixfort_input_ssh_sources=["10.77.0.10"],
        policy_meta={"policy_version": 1, "plan_hash": "a" * 64},
    )
    f["system"]["result"]["packages"]["suricata"] = "1:7.0.3-1build3"
    f["system"]["result"]["services"]["suricata"] = "active"
    f["suricata"]["result"] = {
        "installed": True,
        "service": "active",
        "version": "7.0.3",
        "config_test": {"ok": True, "stderr_tail": ""},
        "eve": {"enabled": True, "path": "/var/log/suricata/eve.json", "readable": True, "size": 10},
        "af_packet_interfaces": ["enp0s9"],
        "nixfort_test_rule_loaded": True,
    }
    return f


def test_hardened_gateway_all_pass():
    got = run_all(hardened_gateway(), GW_CTX)
    assert {k for k, v in got.items() if k[:2] in ("FW", "ID") and v not in (PASS, NA)} == set()


def test_fw04_fail_when_controller_not_allowed():
    f = hardened_gateway()
    f["nft"]["result"]["nixfort_input_ssh_sources"] = ["10.77.0.99"]
    assert domain.evaluate(domain.BY_ID["FW-04"], f, GW_CTX).status == FAIL


def test_fw01_conflicts():
    for mutate in (
        lambda f: f["system"]["result"]["services"].update(ufw="active"),
        lambda f: f["nft"]["result"]["conflict"].update(firewalld=True),
        lambda f: f["nft"]["result"]["conflict"].update(docker=True),
        lambda f: f["nft"]["result"]["conflict"].update(foreign_base_chains=["ip filter INPUT"]),
        lambda f: f["system"]["result"]["packages"].update(nftables=None),
    ):
        f = load("gateway")
        mutate(f)
        assert domain.evaluate(domain.BY_ID["FW-01"], f, GW_CTX).status == FAIL


def test_ids03_wrong_interface():
    f = hardened_gateway()
    f["suricata"]["result"]["af_packet_interfaces"] = ["eth0"]
    out = domain.evaluate(domain.BY_ID["IDS-03"], f, GW_CTX)
    assert out.status == FAIL and "enp0s9" in out.explanation


def test_f2b_permanent_ban_ok_and_weak_params_fail():
    f = hardened_server()
    f["fail2ban"]["result"]["sshd"]["bantime"] = -1
    assert domain.evaluate(domain.BY_ID["F2B-03"], f, SERVER_CTX).status == PASS
    f["fail2ban"]["result"]["sshd"].update(maxretry=10, bantime=600)
    assert domain.evaluate(domain.BY_ID["F2B-03"], f, SERVER_CTX).status == FAIL
    f["fail2ban"]["result"]["sshd"].update(maxretry=None)
    assert domain.evaluate(domain.BY_ID["F2B-03"], f, SERVER_CTX).status == UNKNOWN


# ---- the "no false PASS" guarantees (AT-06 / AT-07) -------------------------------------


@pytest.mark.parametrize("check", domain.CATALOG, ids=lambda c: c.id)
def test_agent_error_gives_error_never_pass(check):
    f = hardened_gateway() if check.roles & {"gateway", "ids_sensor"} else hardened_server()
    ctx = GW_CTX if check.roles & {"gateway", "ids_sensor"} else SERVER_CTX
    for key in check.facts:
        broken = copy.deepcopy(f)
        broken[key] = {"state": "TRANSPORT_ERROR", "result": {}, "error_code": "timeout"}
        assert domain.evaluate(check, broken, ctx).status == ERROR


@pytest.mark.parametrize("check", domain.CATALOG, ids=lambda c: c.id)
def test_missing_fact_gives_unknown_never_pass(check):
    f = hardened_gateway() if check.roles & {"gateway", "ids_sensor"} else hardened_server()
    ctx = GW_CTX if check.roles & {"gateway", "ids_sensor"} else SERVER_CTX
    for key in check.facts:
        partial = copy.deepcopy(f)
        del partial[key]
        assert domain.evaluate(check, partial, ctx).status == UNKNOWN


@pytest.mark.parametrize("check", domain.CATALOG, ids=lambda c: c.id)
def test_garbage_result_never_pass(check):
    ctx = GW_CTX if check.roles & {"gateway", "ids_sensor"} else SERVER_CTX
    garbage = {k: {"state": "OK", "result": {"unexpected": [1, 2]}} for k in check.facts}
    # Unexpected agent output must never be interpreted as PASS or as a confirmed FAIL.
    assert domain.evaluate(check, garbage, ctx).status in (UNKNOWN, ERROR)


def test_unsupported_os_only_sys01_evaluated():
    f = hardened_server()
    f["system"]["result"]["os_supported"] = False
    got = run_all(f, SERVER_CTX)
    assert got["SYS-01"] == FAIL
    assert all(v in (UNKNOWN, NA) for k, v in got.items() if k != "SYS-01")


def test_invalid_sshd_config_makes_ssh_checks_unknown():
    f = hardened_server()
    f["ssh"]["result"] = {"config_valid": False, "validate_stderr": "line 3: Bad option", "effective": {}}
    got = run_all(f, SERVER_CTX)
    assert got["SSH-07"] == FAIL
    assert all(got[f"SSH-0{i}"] == UNKNOWN for i in range(1, 7))


def test_test_client_gets_only_not_applicable():
    ctx = Ctx(roles=frozenset({"test_client"}))
    assert set(run_all(load("client"), ctx).values()) == {NA}
