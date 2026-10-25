import json
import unittest
from pathlib import Path

from nixfort_agent import parsers
from nixfort_agent.osprofile import parse_os_release, select_profile

FX = Path(__file__).parent / "fixtures"


class ParserTests(unittest.TestCase):
    def test_os_release(self):
        osr = parse_os_release('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n# c\n')
        self.assertEqual(select_profile(osr).name, "ubuntu-24.04")
        self.assertEqual(select_profile({"ID": "astra", "VERSION_ID": "1.8_x86-64"}).name, "astra-1.8")
        self.assertFalse(select_profile({"ID": "ubuntu", "VERSION_ID": "22.04"}).supported)
        self.assertFalse(select_profile({}).supported)

    def test_unit_state(self):
        self.assertEqual(parsers.unit_state("LoadState=loaded\nActiveState=active\n"), "active")
        self.assertEqual(parsers.unit_state("LoadState=loaded\nActiveState=inactive\n"), "inactive")
        self.assertEqual(parsers.unit_state("LoadState=loaded\nActiveState=failed\n"), "failed")
        self.assertEqual(parsers.unit_state("LoadState=not-found\nActiveState=inactive\n"), "absent")
        self.assertEqual(parsers.unit_state(""), "absent")

    def test_dpkg(self):
        out = "openssh-server\tinstalled\t1:9.6p1-3ubuntu13\nnftables\tinstalled\t1.0.9-1build1\nsuricata\tnot-installed\t\n"
        r = parsers.parse_dpkg(out, ("nftables", "fail2ban", "suricata", "openssh-server"))
        self.assertEqual(r["nftables"], "1.0.9-1build1")
        self.assertIsNone(r["fail2ban"])
        self.assertIsNone(r["suricata"])

    def test_ip_addr(self):
        ifaces, v6 = parsers.parse_ip_addr((FX / "ip_addr.json").read_text())
        self.assertFalse(v6)
        self.assertEqual(ifaces[2], {"name": "enp0s9", "state": "UP", "ipv4": ["10.99.0.10/24"]})

    def test_ss(self):
        ls = parsers.parse_ss_listeners((FX / "ss_ltnp.txt").read_text())
        ports = {(x["addr"], x["port"]) for x in ls}
        self.assertIn(("127.0.0.53", 53), ports)
        self.assertIn(("::", 22), ports)
        self.assertIn(("0.0.0.0", 443), ports)
        dns = next(x for x in ls if x["port"] == 53)
        self.assertTrue(dns["loopback"])
        web = next(x for x in ls if x["port"] == 8080)
        self.assertEqual(web["process"], "python3")
        self.assertFalse(web["loopback"])

    def test_sshd_t(self):
        cfg = parsers.parse_sshd_t((FX / "sshd_T_ubuntu.txt").read_text())
        self.assertEqual(cfg["permitrootlogin"], "without-password")
        self.assertEqual(cfg["passwordauthentication"], "yes")
        self.assertEqual(cfg["maxauthtries"], "6")
        self.assertNotIn("maxsessions", cfg)

    def test_f2b(self):
        status = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd, recidive\n"
        self.assertEqual(parsers.parse_f2b_jail_list(status), ["sshd", "recidive"])
        js = (
            "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n`- Actions\n"
            "   |- Currently banned:\t1\n   |- Total banned:\t1\n   `- Banned IP list:\t10.88.0.10\n"
        )
        self.assertEqual(parsers.parse_f2b_jail_status(js), {"currently_banned": 1, "banned_ips": ["10.88.0.10"]})
        self.assertEqual(parsers.parse_int_value("600\n"), 600)
        self.assertIsNone(parsers.parse_int_value("Sorry but the jail 'x' does not exist"))

    def test_suricata_dump(self):
        d = parsers.parse_suricata_dump((FX / "suricata_dump.txt").read_text())
        self.assertTrue(d["eve_enabled"])
        self.assertEqual(d["eve_path"], "/var/log/suricata/eve.json")
        self.assertEqual(d["af_packet_interfaces"], ["eth0"])
        self.assertEqual(parsers.parse_suricata_version("This is Suricata version 7.0.3 RELEASE"), "7.0.3")

    def test_eve(self):
        lines = (FX / "eve.json").read_text().splitlines()
        ev = parsers.parse_eve_lines(lines, None, {"alert"}, 10)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["alert"]["signature_id"], 9000001)
        self.assertNotIn("payload", json.dumps(ev))  # payload never leaves the node
        both = parsers.parse_eve_lines(lines, "2026-11-01T10:00:01.000000+0300", {"alert", "anomaly"}, 10)
        self.assertEqual([e["event_type"] for e in both], ["anomaly"])

    def test_nft_ruleset(self):
        rs = {
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {
                    "table": {
                        "family": "inet",
                        "name": "nixfort",
                        "handle": 1,
                        "comment": "nixfort policy_version=3 plan_hash=" + "a" * 64,
                    }
                },
                {
                    "chain": {
                        "family": "inet",
                        "table": "nixfort",
                        "name": "input",
                        "hook": "input",
                        "prio": 0,
                        "policy": "drop",
                        "type": "filter",
                    }
                },
                {
                    "chain": {
                        "family": "inet",
                        "table": "nixfort",
                        "name": "forward",
                        "hook": "forward",
                        "prio": 0,
                        "policy": "drop",
                        "type": "filter",
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "nixfort",
                        "chain": "input",
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                    "right": {"set": ["10.77.0.10"]},
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                    "right": 22,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                },
                {"table": {"family": "ip", "name": "filter"}},
                {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}},
                {"chain": {"family": "ip", "table": "filter", "name": "DOCKER"}},
            ]
        }
        r = parsers.parse_nft_ruleset(json.dumps(rs))
        self.assertTrue(r["nixfort_table_present"])
        self.assertEqual(r["policy_meta"], {"policy_version": 3, "rules_sha256": "a" * 64})
        self.assertEqual(r["nixfort_chains"]["forward"]["policy"], "drop")
        self.assertEqual(r["nixfort_input_ssh_sources"], ["10.77.0.10"])
        self.assertEqual(r["conflict"]["foreign_base_chains"], ["ip filter INPUT"])
        self.assertTrue(r["conflict"]["docker"])

    def test_nft_empty(self):
        r = parsers.parse_nft_ruleset('{"nftables":[{"metainfo":{}}]}')
        self.assertFalse(r["nixfort_table_present"])
        self.assertIsNone(r["policy_meta"])


if __name__ == "__main__":
    unittest.main()


class EveSinceTests(unittest.TestCase):
    def test_since_compares_instants_across_offsets(self):
        lines = [
            '{"timestamp":"2026-10-26T01:14:00.000000+0300","event_type":"alert","alert":{"signature_id":1}}',
            '{"timestamp":"2026-10-26T01:15:00.000000+0300","event_type":"alert","alert":{"signature_id":2}}',
            '{"timestamp":"garbage","event_type":"alert","alert":{"signature_id":3}}',
        ]
        # 22:14:30 UTC == 01:14:30 +0300: only the second event is newer
        out = parsers.parse_eve_lines(lines, "2026-10-25T22:14:30+00:00", {"alert"}, 10)
        self.assertEqual([e["alert"]["signature_id"] for e in out], [2])
        self.assertEqual(len(parsers.parse_eve_lines(lines, None, {"alert"}, 10)), 3)
