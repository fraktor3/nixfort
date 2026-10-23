import json
import os
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


@unittest.skipUnless(os.geteuid() == 0 and os.path.exists("/usr/sbin/nft"), "needs root and nft")
class NftRealTests(unittest.TestCase):
    """Runs the real nft binary inside a fresh network namespace."""

    def test_inspect_in_netns(self):
        import subprocess
        import sys

        code = (
            "import json,sys; sys.path.insert(0,'.');"
            "from nixfort_agent.__main__ import handle;"
            "from tests.helpers import request, make_ctx;"
            "from nixfort_agent import runner;"
            "from unittest import mock;"
            "mock.patch('nixfort_agent.actions.nft.ufw_active', return_value=False).start();"
            "mock.patch('nixfort_agent.actions.nft.unit_state', return_value='absent').start();"
            "print(handle(request('nft.inspect.v1'), ctx_factory=lambda d: make_ctx(runner=runner.run)).decode())"
        )
        agent_dir = str(Path(__file__).resolve().parent.parent)
        out = subprocess.run(
            ["unshare", "-n", sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
            cwd=agent_dir,
        )
        r = json.loads(out.stdout)
        self.assertEqual(r["state"], "OK", out)
        self.assertFalse(r["result"]["nixfort_table_present"])
        self.assertRegex(r["result"]["nft_version"], r"\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
