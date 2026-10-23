"""Mutation machinery: snapshot / validate / timer / apply / commit / rollback, with a fake systemd."""

import json
import os
import tempfile
import unittest
from dataclasses import replace

from nixfort_agent.__main__ import handle
from nixfort_agent.osprofile import UBUNTU_2404
from nixfort_agent.runner import RunResult

from .helpers import make_ctx, ok, request

SSHD_CONFIG = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"


class FakeSystem:
    """Simulates systemd timers, sshd -t, fail2ban-client and apt for the agent."""

    def __init__(self, sshd_valid=True, arm_ok=True, reload_ok=True, f2b_valid=True, sshd_t_seq=None):
        self.sshd_t_seq = list(sshd_t_seq or [])
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
        if name == "systemctl":
            if a[0] == "show":
                return ok(f"ActiveState={'active' if a[1] in self.timers else 'inactive'}\n")
            if a[0] == "stop":
                self.timers.discard(a[1])
                return ok()
            if a[0] in ("try-reload-or-restart", "restart"):
                self.reloads += 1
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
        )
        # every tool resolves to an existing "executable" so os.access checks pass
        bins = {k: (f"{root}/bin/{os.path.basename(v[0])}",) for k, v in UBUNTU_2404.bins.items()}
        os.makedirs(f"{root}/bin")
        for (p,) in bins.values():
            open(p, "w").close()
            os.chmod(p, 0o755)
        self.profile = replace(UBUNTU_2404, paths=paths, bins=bins)
        self.sys = FakeSystem(**fs_kw)
        self.files = {"/etc/ssh/sshd_config": SSHD_CONFIG}

    def call(self, action, params=None):
        def factory(deadline):
            ctx = make_ctx(runner=self.sys, files=self.files)
            ctx.profile = self.profile
            return ctx

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


class RollbackLauncherTests(unittest.TestCase):
    def test_rejects_bad_argument(self):
        from nixfort_agent.rollback_main import main

        self.assertEqual(main([]), 64)
        self.assertEqual(main(["../../x"]), 64)
        self.assertEqual(main(["a", "b"]), 64)


if __name__ == "__main__":
    unittest.main()
