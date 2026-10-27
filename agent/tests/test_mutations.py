"""Mutation machinery: snapshot / validate / timer / apply / commit / rollback, with a fake systemd."""

import json
import os
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from nixfort_agent.__main__ import handle
from nixfort_agent.osprofile import UBUNTU_2404
from nixfort_agent.runner import RunResult

from .helpers import make_ctx, ok, request

SSHD_CONFIG = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
SURI_YAML = "%YAML 1.1\n---\naf-packet:\n  - interface: eth0\n"
NFT_CONF = "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n"


class FakeSystem:
    """Simulates systemd timers, sshd -t, fail2ban-client and apt for the agent."""

    def __init__(
        self,
        sshd_valid=True,
        arm_ok=True,
        reload_ok=True,
        f2b_valid=True,
        sshd_t_seq=None,
        nft_valid=True,
        nft_ruleset=None,
        nft_enabled=False,
        suri_valid=True,
        suri_starts=True,
        suri_active=False,
        suri_enabled=False,
        suri_start_limited=False,
    ):
        self.suri_start_limited = suri_start_limited
        self.suri_valid, self.suri_starts = suri_valid, suri_starts
        self.suri_active, self.suri_enabled = suri_active, suri_enabled
        self.suri_events: list[str] = []
        self.sshd_t_seq = list(sshd_t_seq or [])
        self.nft_valid, self.nft_enabled = nft_valid, nft_enabled
        self.nft_ruleset = nft_ruleset or {"nftables": []}
        self.nft_table: str | None = None  # text of the file last loaded with `nft -f`
        self.nft_events: list[str] = []
        self.timers: set[str] = set()
        self.calls: list[list[str]] = []
        self.sshd_valid, self.arm_ok, self.reload_ok, self.f2b_valid = sshd_valid, arm_ok, reload_ok, f2b_valid
        self.reloads = 0

    def __call__(self, argv, timeout, **kw):
        assert isinstance(argv, list) and argv[0].startswith("/")
        self.calls.append(argv)
        name = os.path.basename(argv[0])
        a = argv[1:]
        if name == "systemd-run":
            if not self.arm_ok:
                return RunResult(1, "", "Failed to start transient timer", False)
            unit = a[0].split("=", 1)[1]
            self.timers.add(unit + ".timer")
            return ok()
        if name == "systemctl" and a[-1] == "suricata.service":
            if a[0] == "show":
                return ok(f"ActiveState={'active' if self.suri_active else 'failed'}\n")
            if a[0] == "is-enabled":
                return ok("enabled\n" if self.suri_enabled else "disabled\n")
            self.suri_events.append(a[0])
            if a[0] == "reset-failed":
                self.suri_start_limited = False
            if a[0] == "restart":
                if self.suri_start_limited:  # systemd: "Start request repeated too quickly"
                    return RunResult(1, "", "Job for suricata.service failed", False)
                self.suri_active = self.suri_starts
            elif a[0] == "stop":
                self.suri_active = False
            elif a[0] in ("enable", "disable"):
                self.suri_enabled = a[0] == "enable"
            return ok()
        if name == "suricata" and a[0] == "-T":
            return ok() if self.suri_valid else RunResult(1, "", "Error: bad af-packet", False)
        if name == "systemctl":
            if a[0] == "show":
                return ok(f"ActiveState={'active' if a[1] in self.timers else 'inactive'}\n")
            if a[0] == "stop":
                self.timers.discard(a[1])
                return ok()
            if a[0] == "is-enabled":
                return ok("enabled\n" if self.nft_enabled else "disabled\n")
            if a[0] in ("enable", "disable") and a[1] == "nftables.service":
                self.nft_enabled = a[0] == "enable"
                self.nft_events.append(a[0])
                return ok()
            if a[0] in ("try-reload-or-restart", "restart"):
                self.reloads += 1
                if getattr(self, "reload_fail_once", False):
                    self.reload_fail_once = False
                    return RunResult(1, "", "failed", False)
                return ok() if self.reload_ok else RunResult(1, "", "failed", False)
            return ok()
        if name == "sshd":
            if a == ["-t"]:
                valid = self.sshd_t_seq.pop(0) if self.sshd_t_seq else self.sshd_valid
                return ok() if valid else RunResult(255, "", "line 3: Bad configuration option", False)
            return ok(
                "permitrootlogin no\npasswordauthentication no\nmaxauthtries 4\nlogingracetime 60\n"
                "x11forwarding no\npermitemptypasswords no\n"
            )
        if name == "fail2ban-client":
            if a == ["-t"]:
                return ok("OK") if self.f2b_valid else RunResult(255, "", "ERROR bad jail", False)
            return ok("pong")
        if name == "nft":
            if a[:2] == ["-c", "-f"]:
                return ok() if self.nft_valid else RunResult(1, "", "Error: syntax error", False)
            if a[0] == "-f":
                with open(a[1]) as fh:
                    self.nft_table = fh.read()
                self.nft_events.append("load")
                return ok()
            if a[:3] == ["-j", "list", "ruleset"]:
                return ok(json.dumps(self.nft_ruleset))
            if a[:2] == ["list", "table"]:
                return ok(self.nft_table) if self.nft_table else RunResult(1, "", "No such file", False)
            if a[:2] == ["delete", "table"]:
                self.nft_table = None
                self.nft_events.append("delete")
                return ok()
        if name == "apt-get":
            return ok()
        if name == "dpkg-query":
            return ok("".join(f"{p}\tinstalled\t1.0\n" for p in a[3:]))
        return RunResult(1, "", "unexpected", False)


class Env:
    def __init__(self, **fs_kw):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        paths = dict(UBUNTU_2404.paths)
        paths.update(
            snapshots_dir=f"{root}/snapshots",
            sshd_owned=f"{root}/sshd_config.d/00-nixfort.conf",
            sshd_privsep_dir=root,
            f2b_owned=f"{root}/jail.d/nixfort-sshd.local",
            nft_owned=f"{root}/nftables.d/nixfort.nft",
            nft_conf=f"{root}/nftables.conf",
            suricata_yaml=f"{root}/suricata/suricata.yaml",
            suricata_owned=f"{root}/suricata/nixfort-sensor.yaml",
            suricata_test_rules=f"{root}/suricata/rules/nixfort-test.rules",
            suricata_dist_rules=f"{root}/var-lib-suricata/suricata.rules",
            sys_class_net=f"{root}/sys-class-net",
        )
        os.makedirs(f"{root}/sys-class-net/enp0s9")
        os.makedirs(f"{root}/suricata")
        with open(paths["suricata_yaml"], "w") as fh:
            fh.write(SURI_YAML)
        # every tool resolves to an existing "executable" so os.access checks pass
        bins = {k: (f"{root}/bin/{os.path.basename(v[0])}",) for k, v in UBUNTU_2404.bins.items()}
        os.makedirs(f"{root}/bin")
        for (p,) in bins.values():
            open(p, "w").close()
            os.chmod(p, 0o755)
        self.profile = replace(UBUNTU_2404, paths=paths, bins=bins)
        self.sys = FakeSystem(**fs_kw)
        self.files = {"/etc/ssh/sshd_config": SSHD_CONFIG, "/proc/sys/net/ipv4/ip_forward": "1\n"}
        with open(paths["nft_conf"], "w") as fh:
            fh.write(NFT_CONF)
        self.files[paths["nft_conf"]] = NFT_CONF
        self.files[paths["suricata_yaml"]] = SURI_YAML

    def _access(self, path, mode, _real=os.access):
        # /tmp in the controller container is a noexec tmpfs, where access(X_OK)
        # is always false; the fake binaries count as executable regardless.
        if str(path).startswith(self.tmp.name + "/bin/"):
            return True
        return _real(path, mode)

    def call(self, action, params=None):
        def factory(deadline):
            ctx = make_ctx(runner=self.sys, files=self.files)
            ctx.profile = self.profile
            return ctx

        with mock.patch("os.access", self._access):
            return json.loads(handle(request(action, params or {}), ctx_factory=factory))

    def ctx(self):
        c = make_ctx(runner=self.sys, files=self.files)
        c.profile = self.profile
        return c


SSH_PARAMS = {
    "permit_root_login": "no",
    "password_authentication": False,
    "max_auth_tries": 4,
    "login_grace_time_s": 60,
    "x11_forwarding": False,
    "rollback_timeout_s": 90,
}
F2B_PARAMS = {
    "maxretry": 5,
    "bantime_s": 600,
    "findtime_s": 600,
    "ignore_ips": ["10.77.0.10"],
    "rollback_timeout_s": 90,
}


class SshProfileTests(unittest.TestCase):
    def test_apply_then_commit(self):
        e = Env()
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual(r["state"], "OK", r)
        sid = r["result"]["snapshot_id"]
        text = open(e.profile.paths["sshd_owned"]).read()
        self.assertIn("PermitRootLogin no", text)
        self.assertIn("PasswordAuthentication no", text)
        self.assertEqual(e.sys.reloads, 1)
        self.assertIn(f"nixfort-rb-{sid}.timer", e.sys.timers)  # safety net armed before activation
        # order: snapshot+write -> validate -> arm -> reload
        names = [os.path.basename(c[0]) + ":" + c[1] for c in e.sys.calls]
        self.assertLess(
            names.index("systemd-run:--unit=nixfort-rb-" + sid), names.index("systemctl:try-reload-or-restart")
        )
        c = e.call("mutation.commit.v1", {"snapshot_id": sid})
        self.assertEqual(c["result"], {"committed": True, "timer_cancelled": True, "rolled_back": False})
        self.assertEqual(e.sys.timers, set())

    def test_invalid_candidate_is_restored_and_nothing_activated(self):
        e = Env(sshd_t_seq=[True, False])  # current config valid, candidate invalid
        os.makedirs(os.path.dirname(e.profile.paths["sshd_owned"]))
        with open(e.profile.paths["sshd_owned"], "w") as fh:
            fh.write("# previous\n")
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("FAILED", "validation_failed"))
        self.assertEqual(open(e.profile.paths["sshd_owned"]).read(), "# previous\n")
        self.assertEqual(e.sys.reloads, 0)
        self.assertEqual(e.sys.timers, set())

    def test_refuses_when_current_config_already_invalid(self):
        e = Env(sshd_valid=False)
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual(r["state"], "REJECTED")
        self.assertFalse(os.path.exists(e.profile.paths["sshd_owned"]))

    def test_refuses_without_include(self):
        e = Env()
        e.files["/etc/ssh/sshd_config"] = "Port 22\n"
        self.assertEqual(e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)["state"], "REJECTED")

    def test_no_timer_no_change(self):
        e = Env(arm_ok=False)
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("ERROR", "timer_failed"))
        self.assertFalse(os.path.exists(e.profile.paths["sshd_owned"]))
        self.assertEqual(e.sys.reloads, 0)

    def test_reload_failure_is_rolled_back_and_reported_failed(self):
        e = Env()
        e.sys.reload_fail_once = True  # the new config does not activate, the restored one does
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("FAILED", "activation_failed"), r)
        self.assertFalse(os.path.exists(e.profile.paths["sshd_owned"]))
        self.assertEqual(e.sys.timers, set())

    def test_unconfirmed_rollback_is_an_error(self):
        e = Env(reload_ok=False)  # even the restored config cannot be activated
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("ERROR", "rollback_failed"), r)

    def test_rollback_now_restores_previous(self):
        e = Env()
        r = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)
        sid = r["result"]["snapshot_id"]
        rb = e.call("mutation.rollback_now.v1", {"snapshot_id": sid})
        self.assertEqual(rb["state"], "OK")
        self.assertTrue(rb["result"]["rolled_back"])
        self.assertFalse(os.path.exists(e.profile.paths["sshd_owned"]))  # did not exist before
        self.assertEqual(e.sys.reloads, 2)
        st = e.call("mutation.snapshot_status.v1", {"snapshot_id": sid})["result"]
        self.assertTrue(st["rolled_back"]) and self.assertFalse(st["timer_active"])
        # commit after rollback must not report success
        c = e.call("mutation.commit.v1", {"snapshot_id": sid})["result"]
        self.assertEqual(c["committed"], False)
        self.assertTrue(c["rolled_back"])

    def test_timer_fired_rollback_is_idempotent(self):
        from nixfort_agent.mutation import perform_rollback

        e = Env()
        sid = e.call("ssh.apply_hardening_profile.v1", SSH_PARAMS)["result"]["snapshot_id"]
        first = perform_rollback(e.ctx(), sid)
        second = perform_rollback(e.ctx(), sid)
        self.assertEqual(first, second)
        self.assertEqual(e.sys.reloads, 2)

    def test_params_are_strict(self):
        e = Env()
        for bad in (
            {**SSH_PARAMS, "permit_root_login": "yes"},
            {**SSH_PARAMS, "max_auth_tries": 10},
            {**SSH_PARAMS, "extra": "Match all"},
            {**SSH_PARAMS, "x11_forwarding": "no"},
            {**SSH_PARAMS, "rollback_timeout_s": 5},
        ):
            self.assertEqual(e.call("ssh.apply_hardening_profile.v1", bad)["state"], "REJECTED", bad)

    def test_bad_snapshot_ids(self):
        e = Env()
        for bad in ("../../etc", "x" * 32, "ABCDEF" + "0" * 26, ""):
            self.assertEqual(e.call("mutation.rollback_now.v1", {"snapshot_id": bad})["state"], "REJECTED")
        r = e.call("mutation.commit.v1", {"snapshot_id": "0" * 32})
        self.assertEqual((r["state"], r["error_code"]), ("ERROR", "snapshot_not_found"))


class Fail2banProfileTests(unittest.TestCase):
    def test_apply_renders_only_typed_values(self):
        e = Env()
        r = e.call("fail2ban.apply_sshd_profile.v1", F2B_PARAMS)
        self.assertEqual(r["state"], "OK", r)
        text = open(e.profile.paths["f2b_owned"]).read()
        self.assertIn("[sshd]\nenabled = true", text)
        self.assertIn("maxretry = 5", text)
        self.assertIn("ignoreip = 127.0.0.1/8 ::1 10.77.0.10", text)

    def test_injection_in_ignore_ips(self):
        e = Env()
        for bad in (["10.0.0.1\n[recidive]"], ["10.0.0.1 ; x"], ["evil.com"], ["10.0.0.0/33"]):
            r = e.call("fail2ban.apply_sshd_profile.v1", {**F2B_PARAMS, "ignore_ips": bad})
            self.assertEqual(r["state"], "REJECTED", bad)

    def test_invalid_jail_restored(self):
        e = Env(f2b_valid=False)
        r = e.call("fail2ban.apply_sshd_profile.v1", F2B_PARAMS)
        self.assertEqual(r["state"], "FAILED")
        self.assertFalse(os.path.exists(e.profile.paths["f2b_owned"]))


class PkgTests(unittest.TestCase):
    def test_install_allowlist(self):
        e = Env()
        r = e.call("pkg.install_security_tool.v1", {"package": "fail2ban"})
        self.assertEqual(r["state"], "OK", r)
        apt = [c for c in e.sys.calls if c[0].endswith("apt-get") and c[1] == "install"][0]
        self.assertEqual(apt[-2:], ["fail2ban", "python3-systemd"])
        for bad in ("netcat", "fail2ban; rm -rf /", "../suricata"):
            self.assertEqual(e.call("pkg.install_security_tool.v1", {"package": bad})["state"], "REJECTED")


NFT_PARAMS = {
    "policy_version": 2,
    "management_sources": ["10.77.0.10"],
    "forward_allow": [{"src": "10.88.0.0/24", "dst": "10.99.0.10", "port": 80}],
    "input_allow": [],
    "rollback_timeout_s": 90,
}


class NftPolicyTests(unittest.TestCase):
    def test_apply_commit(self):
        e = Env()
        r = e.call("nft.apply_policy.v1", NFT_PARAMS)
        self.assertEqual(r["state"], "OK", r)
        owned = open(e.profile.paths["nft_owned"]).read()
        self.assertIn("ip saddr 10.88.0.0/24 ip daddr 10.99.0.10 tcp dport 80 accept", owned)
        self.assertIn("ip saddr { 10.77.0.10 } tcp dport 22 accept", owned)
        conf = open(e.profile.paths["nft_conf"]).read()
        self.assertTrue(conf.startswith(NFT_CONF.rstrip("\n")))
        self.assertEqual(conf.count('include "/etc/nftables.d/*.nft"'), 1)
        self.assertEqual(e.sys.nft_events, ["load", "enable"])
        self.assertEqual(e.sys.nft_table, owned)
        sid = r["result"]["snapshot_id"]
        self.assertIn(f"nixfort-rb-{sid}.timer", e.sys.timers)
        names = [os.path.basename(c[0]) + ":" + c[1] for c in e.sys.calls]
        self.assertLess(names.index("systemd-run:--unit=nixfort-rb-" + sid), names.index("nft:-f"))
        self.assertEqual(e.call("mutation.commit.v1", {"snapshot_id": sid})["result"]["committed"], True)
        # second apply: include is not duplicated
        self.assertEqual(e.call("nft.apply_policy.v1", {**NFT_PARAMS, "policy_version": 3})["state"], "OK")
        self.assertEqual(open(e.profile.paths["nft_conf"]).read().count("nftables.d"), 1)

    def test_rollback_from_nothing_removes_table_and_restores_conf(self):
        e = Env()
        sid = e.call("nft.apply_policy.v1", NFT_PARAMS)["result"]["snapshot_id"]
        rb = e.call("mutation.rollback_now.v1", {"snapshot_id": sid})
        self.assertTrue(rb["result"]["rolled_back"], rb)
        self.assertFalse(os.path.exists(e.profile.paths["nft_owned"]))
        self.assertEqual(open(e.profile.paths["nft_conf"]).read(), NFT_CONF)
        self.assertIsNone(e.sys.nft_table)
        self.assertEqual(e.sys.nft_events, ["load", "enable", "delete", "disable"])  # never `stop`
        self.assertFalse(any(c[1:3] == ["stop", "nftables.service"] for c in e.sys.calls))

    def test_rollback_to_previous_version_reloads_it(self):
        e = Env(nft_enabled=True)
        first = e.call("nft.apply_policy.v1", NFT_PARAMS)["result"]["snapshot_id"]
        e.call("mutation.commit.v1", {"snapshot_id": first})
        v1 = e.sys.nft_table
        sid = e.call("nft.apply_policy.v1", {**NFT_PARAMS, "policy_version": 3})["result"]["snapshot_id"]
        self.assertNotEqual(e.sys.nft_table, v1)
        e.call("mutation.rollback_now.v1", {"snapshot_id": sid})
        self.assertEqual(e.sys.nft_table, v1)
        self.assertNotIn("disable", e.sys.nft_events)  # service was enabled before: left enabled

    def test_invalid_candidate_nothing_loaded(self):
        e = Env(nft_valid=False)
        r = e.call("nft.apply_policy.v1", NFT_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("FAILED", "validation_failed"))
        self.assertFalse(os.path.exists(e.profile.paths["nft_owned"]))
        self.assertEqual(open(e.profile.paths["nft_conf"]).read(), NFT_CONF)
        self.assertEqual(e.sys.nft_events, [])
        self.assertEqual(e.sys.timers, set())

    def test_conflicts_refused_before_any_change(self):
        foreign = {
            "nftables": [
                {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}}
            ]
        }
        cases = [Env(nft_ruleset=foreign), Env()]
        cases[1].files["/proc/sys/net/ipv4/ip_forward"] = "0\n"
        for e in cases:
            r = e.call("nft.apply_policy.v1", NFT_PARAMS)
            self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "conflict"), r)
            self.assertFalse(os.path.exists(e.profile.paths["nft_owned"]))
            self.assertEqual(e.sys.nft_events, [])

    def test_injection_and_limits(self):
        e = Env()
        rule = NFT_PARAMS["forward_allow"][0]
        for bad in (
            {**NFT_PARAMS, "forward_allow": [{**rule, "src": "10.88.0.0/24 accept; flush ruleset"}]},
            {**NFT_PARAMS, "forward_allow": [{**rule, "dst": "10.99.0.0/24"}]},
            {**NFT_PARAMS, "forward_allow": [{**rule, "port": 0}]},
            {**NFT_PARAMS, "forward_allow": [{**rule, "action": "accept"}]},
            {**NFT_PARAMS, "management_sources": []},
            {**NFT_PARAMS, "management_sources": ["10.77.0.0/24"]},
            {**NFT_PARAMS, "input_allow": [{"src": "0.0.0.0/0", "port": "22 accept"}]},
            {**NFT_PARAMS, "forward_allow": [rule] * 201},
        ):
            self.assertEqual(e.call("nft.apply_policy.v1", bad)["state"], "REJECTED", bad)
        self.assertEqual(e.sys.nft_events, [])


SURI_PARAMS = {"interface": "enp0s9", "test_rules": True, "rollback_timeout_s": 180}


class SuricataProfileTests(unittest.TestCase):
    def setUp(self):
        # restart waits with time.sleep between state polls
        patcher = mock.patch("nixfort_agent.actions.suricata.time.sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_apply_from_failing_default(self):
        e = Env()  # fresh package: service failed on eth0, disabled
        r = e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)
        self.assertEqual(r["state"], "OK", r)
        owned = open(e.profile.paths["suricata_owned"]).read()
        self.assertIn("  - interface: enp0s9\n", owned)
        self.assertIn(e.profile.paths["suricata_test_rules"], owned)
        self.assertNotIn("suricata.rules", owned)  # no distribution rules on the node -> not referenced
        rules = open(e.profile.paths["suricata_test_rules"]).read()
        self.assertIn("NIXFORT-IDS-TEST-7f3a", rules)
        self.assertIn("sid:9000002", rules) and self.assertIn("sid:9000003", rules)
        conf = open(e.profile.paths["suricata_yaml"]).read()
        self.assertTrue(conf.startswith(SURI_YAML.rstrip("\n")))
        self.assertEqual(conf.count("include: " + e.profile.paths["suricata_owned"]), 1)
        self.assertEqual(e.sys.suri_events, ["enable", "reset-failed", "restart"])
        self.assertTrue(e.sys.suri_active)

    def test_after_package_crash_loop_start_limit_is_cleared(self):
        # S-006: apt starts the packaged service on eth0, it crash-loops and systemd blocks restarts
        e = Env(suri_start_limited=True, suri_enabled=True)
        r = e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)
        self.assertEqual(r["state"], "OK", r)
        self.assertLess(e.sys.suri_events.index("reset-failed"), e.sys.suri_events.index("restart"))

    def test_keeps_distribution_rules(self):
        e = Env()
        os.makedirs(os.path.dirname(e.profile.paths["suricata_dist_rules"]))
        open(e.profile.paths["suricata_dist_rules"], "w").close()
        e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)
        self.assertIn("  - suricata.rules", open(e.profile.paths["suricata_owned"]).read())

    def test_service_does_not_come_up_is_rolled_back(self):
        e = Env(suri_starts=False)
        r = e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)
        # previous state restored and confirmed by the agent -> FAILED (nothing changed), not ERROR/unknown
        self.assertEqual((r["state"], r["error_code"]), ("FAILED", "activation_failed"), r)
        self.assertFalse(os.path.exists(e.profile.paths["suricata_owned"]))
        self.assertEqual(open(e.profile.paths["suricata_yaml"]).read(), SURI_YAML)
        self.assertIn("disable", e.sys.suri_events)  # was disabled before -> disabled again
        self.assertEqual(e.sys.timers, set())

    def test_invalid_config_nothing_restarted(self):
        e = Env(suri_valid=False)
        r = e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)
        self.assertEqual((r["state"], r["error_code"]), ("FAILED", "validation_failed"))
        self.assertEqual(e.sys.suri_events, [])
        self.assertFalse(os.path.exists(e.profile.paths["suricata_test_rules"]))

    def test_rollback_restores_running_sensor(self):
        e = Env(suri_active=True, suri_enabled=True)
        sid = e.call("suricata.apply_sensor_profile.v1", SURI_PARAMS)["result"]["snapshot_id"]
        e.call("mutation.rollback_now.v1", {"snapshot_id": sid})
        self.assertFalse(os.path.exists(e.profile.paths["suricata_owned"]))
        self.assertEqual(e.sys.suri_events, ["reset-failed", "restart", "reset-failed", "restart"])
        self.assertTrue(e.sys.suri_active)

    def test_interface_and_injection(self):
        e = Env()
        for bad in ("eth9", "enp0s9\nrule-files: []", "../../etc", "ENP0S9", "a" * 16, ""):
            r = e.call("suricata.apply_sensor_profile.v1", {**SURI_PARAMS, "interface": bad})
            self.assertEqual(r["state"], "REJECTED", bad)
        self.assertEqual(e.sys.suri_events, [])


class NftHostFirewallTests(unittest.TestCase):
    PARAMS = {"version": 1, "management_sources": ["10.77.0.10"], "allow_ports": [80, 443], "rollback_timeout_s": 90}

    def test_apply_commit_no_ip_forward_required(self):
        e = Env()
        e.files["/proc/sys/net/ipv4/ip_forward"] = "0\n"  # a server is not a router
        r = e.call("nft.apply_host_firewall.v1", self.PARAMS)
        self.assertEqual(r["state"], "OK", r)
        owned = open(e.profile.paths["nft_owned"]).read()
        self.assertIn("ip saddr { 10.77.0.10 } tcp dport 22 accept", owned)
        self.assertIn("tcp dport { 80, 443 } accept", owned)
        self.assertNotIn("chain forward", owned)
        self.assertEqual(e.sys.nft_events, ["load", "enable"])
        sid = r["result"]["snapshot_id"]
        self.assertEqual(e.call("mutation.commit.v1", {"snapshot_id": sid})["result"]["committed"], True)

    def test_rollback_removes_table(self):
        e = Env()
        sid = e.call("nft.apply_host_firewall.v1", self.PARAMS)["result"]["snapshot_id"]
        e.call("mutation.rollback_now.v1", {"snapshot_id": sid})
        self.assertFalse(os.path.exists(e.profile.paths["nft_owned"]))
        self.assertIsNone(e.sys.nft_table)

    def test_conflict_and_injection_refused(self):
        foreign = {
            "nftables": [
                {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}}
            ]
        }
        self.assertEqual(Env(nft_ruleset=foreign).call("nft.apply_host_firewall.v1", self.PARAMS)["state"], "REJECTED")
        e = Env()
        for bad in (
            {**self.PARAMS, "allow_ports": [80, 80]},  # duplicate
            {**self.PARAMS, "allow_ports": [0]},  # out of range
            {**self.PARAMS, "management_sources": []},  # empty
            {**self.PARAMS, "management_sources": ["10.0.0.0/24"]},
        ):
            self.assertEqual(e.call("nft.apply_host_firewall.v1", bad)["state"], "REJECTED", bad)


class RollbackLauncherTests(unittest.TestCase):
    def test_rejects_bad_argument(self):
        from nixfort_agent.rollback_main import main

        self.assertEqual(main([]), 64)
        self.assertEqual(main(["../../x"]), 64)
        self.assertEqual(main(["a", "b"]), 64)


if __name__ == "__main__":
    unittest.main()
