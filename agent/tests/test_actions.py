import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nixfort_agent.__main__ import handle
from nixfort_agent.actions import net

from .helpers import FakeRunner, make_ctx, ok, request

FX = Path(__file__).parent / "fixtures"
ACTIVE = ok("LoadState=loaded\nActiveState=active\n")
ABSENT = ok("LoadState=not-found\nActiveState=inactive\n")


def call(raw, runner, **kw):
    return json.loads(handle(raw, ctx_factory=lambda d: make_ctx(runner=runner, **kw)))


class SystemFactsTests(unittest.TestCase):
    def runner(self):
        return FakeRunner(
            {
                ("-j", "addr", "show"): ok((FX / "ip_addr.json").read_text()),
                ("-j", "-4", "route", "show"): ok('[{"dst":"10.88.0.0/24","gateway":"10.99.0.1","dev":"enp0s9"}]'),
                ("show",): ok("NTPSynchronized=yes\nNTP=yes\n"),
                ("show", "-p", "LoadState", "-p", "ActiveState", "ssh.service"): ACTIVE,
                ("show", "-p", "LoadState", "-p", "ActiveState", "systemd-journald.service"): ACTIVE,
                ("show", "-p", "LoadState", "-p", "ActiveState", "systemd-timesyncd.service"): ACTIVE,
                ("show", "-p", "LoadState", "-p", "ActiveState"): ABSENT,
                ("-W",): ok("openssh-server\tinstalled\t1:9.6p1\nnftables\tinstalled\t1.0.9\n"),
            }
        )

    def test_collect_facts(self):
        files = {"/proc/sys/net/ipv4/ip_forward": "0\n"}
        with mock.patch("nixfort_agent.actions.system.os.access", return_value=False):
            r = call(request("system.collect_facts.v1"), self.runner(), files=files)
        self.assertEqual(r["state"], "OK", r)
        res = r["result"]
        self.assertTrue(res["os_supported"])
        self.assertEqual(res["time_sync"], {"service": "systemd-timesyncd.service", "synchronized": True})
        self.assertTrue(res["journald_active"])
        self.assertIs(res["ip_forward"], False)
        self.assertEqual(res["services"]["ssh"], "active")
        self.assertEqual(res["services"]["fail2ban"], "absent")
        self.assertIsNone(res["packages"]["fail2ban"])

    def test_ip_failure_is_error_not_ok(self):
        r = call(request("system.collect_facts.v1"), FakeRunner({}))
        self.assertEqual((r["state"], r["error_code"]), ("ERROR", "tool_failed"))

    def test_listeners(self):
        rn = FakeRunner({("-H", "-ltnp"): ok((FX / "ss_ltnp.txt").read_text())})
        r = call(request("system.collect_listeners.v1"), rn)
        self.assertEqual(len(r["result"]["listeners"]), 6)

    def test_all_calls_use_list_argv_and_absolute_binary(self):
        rn = self.runner()
        call(request("system.collect_facts.v1"), rn)
        self.assertTrue(rn.calls)
        for argv in rn.calls:
            self.assertTrue(argv[0].startswith("/"))


class SshTests(unittest.TestCase):
    def test_effective(self):
        rn = FakeRunner({("-t",): ok(), ("-T",): ok((FX / "sshd_T_ubuntu.txt").read_text())})
        with mock.patch("nixfort_agent.actions.ssh.ensure_privsep_dir"):
            r = call(request("ssh.read_effective_config.v1"), rn)
        self.assertTrue(r["result"]["config_valid"])
        self.assertEqual(r["result"]["effective"]["x11forwarding"], "yes")

    def test_invalid_config_reported_not_parsed(self):
        rn = FakeRunner({("-t",): ok(stderr="/etc/ssh/sshd_config line 3: Bad option", rc=255)})
        with mock.patch("nixfort_agent.actions.ssh.ensure_privsep_dir"):
            r = call(request("ssh.read_effective_config.v1"), rn)
        self.assertEqual(r["state"], "OK")
        self.assertFalse(r["result"]["config_valid"])
        self.assertEqual(r["result"]["effective"], {})


class Fail2banTests(unittest.TestCase):
    def test_not_installed(self):
        rn = FakeRunner({("show",): ABSENT})
        with mock.patch("nixfort_agent.actions.fail2ban.os.access", return_value=False):
            r = call(request("fail2ban.read_status.v1"), rn)
        self.assertEqual(r["result"], {"installed": False, "service": "absent", "jails": [], "sshd": None})

    def test_active_sshd(self):
        rn = FakeRunner(
            {
                ("show",): ACTIVE,
                ("status",): ok("Status\n`- Jail list:\tsshd\n"),
                ("status", "sshd"): ok("   |- Currently banned:\t0\n   `- Banned IP list:\t\n"),
                ("get", "sshd", "maxretry"): ok("5\n"),
                ("get", "sshd", "bantime"): ok("600\n"),
                ("get", "sshd", "findtime"): ok("600\n"),
            }
        )
        with mock.patch("nixfort_agent.actions.fail2ban.os.access", return_value=True):
            r = call(request("fail2ban.read_status.v1"), rn)
        self.assertEqual(r["result"]["sshd"]["maxretry"], 5)
        self.assertEqual(r["result"]["sshd"]["banned_ips"], [])


class SuricataEventsTests(unittest.TestCase):
    def test_events_from_file(self):
        with tempfile.TemporaryDirectory() as d:
            eve = Path(d) / "eve.json"
            eve.write_text((FX / "eve.json").read_text())
            dump = f"default-log-dir = {d}/\noutputs.1.eve-log.enabled = yes\noutputs.1.eve-log.filename = eve.json\n"
            rn = FakeRunner({("--dump-config",): ok(dump)})
            r = call(request("suricata.read_events.v1", {"since_ts": None, "limit": 10, "types": ["alert"]}), rn)
        self.assertTrue(r["result"]["eve_available"])
        self.assertEqual(r["result"]["events"][0]["dest_port"], 8080)

    def test_eve_disabled_is_distinguishable(self):
        rn = FakeRunner({("--dump-config",): ok("outputs.1.eve-log.enabled = no\n")})
        r = call(request("suricata.read_events.v1", {"since_ts": None, "limit": 10, "types": ["alert"]}), rn)
        self.assertEqual(r["result"], {"eve_available": False, "reason": "eve_disabled", "events": []})

    def test_bad_since_ts(self):
        r = call(
            request("suricata.read_events.v1", {"since_ts": "$(id)", "limit": 10, "types": ["alert"]}), FakeRunner()
        )
        self.assertEqual(r["state"], "REJECTED")


class NetProbeTests(unittest.TestCase):
    """Real sockets on loopback."""

    def test_open(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(5)
            port = srv.getsockname()[1]
            self.assertEqual(net.probe("127.0.0.1", port, 1)["result"], "OPEN")

    def test_closed(self):
        with socket.socket() as s:  # bound but not listening -> RST
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            self.assertEqual(net.probe("127.0.0.1", port, 1)["result"], "CLOSED")

    def test_via_protocol(self):
        r = call(
            request("net.tcp_probe.v1", {"targets": [{"ip": "127.0.0.1", "port": 1}], "timeout_ms": 300}), FakeRunner()
        )
        self.assertEqual(r["result"]["results"][0]["result"], "CLOSED")


class SshLoginAttemptsTests(unittest.TestCase):
    def test_outcomes_and_fixed_argv(self):
        replies = iter(
            [
                ok(rc=255, stderr="nixfort-test-1@10.99.0.10: Permission denied (publickey,password)."),
                ok(rc=255, stderr="ssh: connect to host 10.99.0.10 port 22: Connection refused"),
                ok(rc=255, stderr="ssh: connect to host 10.99.0.10 port 22: Connection timed out"),
            ]
        )
        runner = FakeRunner({(): lambda argv: next(replies)})
        r = call(request("net.ssh_login_attempts.v1", {"ip": "10.99.0.10", "port": 22, "count": 3}), runner)
        self.assertEqual(r["state"], "OK", r)
        self.assertEqual(r["result"]["summary"], {"REJECTED": 1, "CLOSED": 1, "TIMEOUT": 1, "ERROR": 0})
        argv = runner.calls[0]
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertIn("BatchMode=yes", argv)  # never sends a password
        self.assertEqual(argv[-3:], ["nixfort-test-1", "10.99.0.10", "true"])

    def test_params_strict(self):
        for bad in (
            {"ip": "10.99.0.10; id", "port": 22, "count": 3},
            {"ip": "10.99.0.10", "port": 22, "count": 50},
            {"ip": "-oProxyCommand=x", "port": 22, "count": 1},
        ):
            self.assertEqual(call(request("net.ssh_login_attempts.v1", bad), FakeRunner())["state"], "REJECTED")


class CaptureTests(unittest.TestCase):
    def test_params_are_fixed_profiles_only(self):
        for bad in (
            {"interface": "lo", "duration_s": 5, "max_packets": 100, "profile": "tcp port 22 or (1=1)"},
            {"interface": "lo; reboot", "duration_s": 5, "max_packets": 100, "profile": "all"},
            {"interface": "lo", "duration_s": 600, "max_packets": 100, "profile": "all"},
            {"interface": "lo", "duration_s": 5, "max_packets": 10**6, "profile": "all"},
        ):
            self.assertEqual(call(request("net.capture.v1", bad), FakeRunner())["state"], "REJECTED", bad)

    def test_unknown_interface(self):
        r = call(
            request("net.capture.v1", {"interface": "eth9", "duration_s": 5, "max_packets": 100, "profile": "all"}),
            FakeRunner(),
        )
        self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "invalid_params"))

    def test_tcpdump_summary(self):
        from nixfort_agent.actions.capture import _stats

        err = "tcpdump: listening on enp0s9\n46 packets captured\n46 packets received by filter\n0 packets dropped by kernel\n"
        self.assertEqual(_stats(err), {"captured": 46, "dropped": 0})


# The real-kernel nft check lives in tests/test_nft_real.py.


class LoadTestTests(unittest.TestCase):
    def test_params_strict(self):
        base = {"ip": "10.99.0.10", "port": 80, "connections": 80, "concurrency": 20, "duration_s": 5}
        for bad in (
            {**base, "ip": "10.99.0.10; rm"},
            {**base, "connections": 5},  # below min
            {**base, "connections": 9999},  # above max
            {**base, "concurrency": 99},
            {**base, "duration_s": 99},
        ):
            self.assertEqual(call(request("net.load_test.v1", bad), FakeRunner())["state"], "REJECTED", bad)

    def test_bounded_run_against_real_socket(self):
        import socket as _s
        import threading as _t

        srv = _s.socket()
        srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(64)
        stop = _t.Event()

        def acc():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                    c.close()
                except OSError:
                    break

        _t.Thread(target=acc, daemon=True).start()
        from nixfort_agent import runner

        r = call(
            request(
                "net.load_test.v1",
                {"ip": "127.0.0.1", "port": port, "connections": 60, "concurrency": 10, "duration_s": 5},
            ),
            runner.run,
        )
        stop.set()
        srv.close()
        res = r["result"]
        self.assertEqual(r["state"], "OK")
        self.assertTrue(res["service_available"] and res["succeeded"] > 0)
        self.assertEqual(res["refused"], 0)
        self.assertLessEqual(res["attempted"], 60)


class AuthFailuresTests(unittest.TestCase):
    JOURNAL = (
        "Failed password for invalid user admin from 10.88.0.10 port 5 ssh2\n"
        "Invalid user root from 10.88.0.10 port 6\n"
        "Failed password for labadmin from 10.88.0.10 port 7 ssh2\n"
        "Accepted password for ok from 10.77.0.10 port 8 ssh2\n"
    )

    def test_reads_and_aggregates(self):
        runner = FakeRunner({("_COMM=sshd",): ok(self.JOURNAL)})
        r = call(request("system.read_auth_failures.v1", {"hours": 24}), runner)
        self.assertEqual(r["state"], "OK")
        res = r["result"]
        self.assertEqual(res["total"], 3)
        self.assertEqual(res["by_source"][0], {"ip": "10.88.0.10", "count": 3})
        self.assertEqual(res["window_hours"], 24)
        argv = runner.calls[0]
        self.assertEqual(argv[0], "/usr/bin/journalctl")
        self.assertIn("_COMM=sshd", argv)

    def test_params_strict(self):
        for bad in ({"hours": 0}, {"hours": 999}, {}):
            self.assertEqual(call(request("system.read_auth_failures.v1", bad), FakeRunner())["state"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
