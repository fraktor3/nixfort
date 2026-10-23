"""nft.apply_policy rendering against the REAL nft binary and kernel, in a routed topology of three
network namespaces that mirrors the lab: client 10.88.0.10 -> gateway -> server 10.99.0.10."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from nixfort_agent import parsers
from nixfort_agent.actions import nft

AGENT_DIR = str(Path(__file__).resolve().parent.parent)


def _can_netns() -> bool:
    if os.geteuid() != 0 or not shutil.which("nft") or not shutil.which("ip"):
        return False
    name = "nxprobe" + uuid.uuid4().hex[:6]
    ok = subprocess.run(["ip", "netns", "add", name], capture_output=True).returncode == 0
    subprocess.run(["ip", "netns", "del", name], capture_output=True)
    return ok


def sh(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=30, check=True)


PARAMS = {
    "policy_version": 3,
    "management_sources": ["10.77.0.10", "10.0.2.2"],
    "forward_allow": [{"src": "10.88.0.0/24", "dst": "10.99.0.10", "port": 80}],
    "input_allow": [],
    "rollback_timeout_s": 90,
}


@unittest.skipUnless(_can_netns(), "needs root, nft and ip netns")
class NftPolicyInKernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = uuid.uuid4().hex[:4]
        cls.cl, cls.gw, cls.sv = f"nxcl{s}", f"nxgw{s}", f"nxsv{s}"
        for ns in (cls.cl, cls.gw, cls.sv):
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "link", "add", f"a{s}", "netns", cls.cl, "type", "veth", "peer", "name", f"b{s}", "netns", cls.gw)
        sh("ip", "link", "add", f"c{s}", "netns", cls.gw, "type", "veth", "peer", "name", f"d{s}", "netns", cls.sv)
        for ns, dev, addr in (
            (cls.cl, f"a{s}", "10.88.0.10/24"),
            (cls.gw, f"b{s}", "10.88.0.1/24"),
            (cls.gw, f"c{s}", "10.99.0.1/24"),
            (cls.sv, f"d{s}", "10.99.0.10/24"),
        ):
            sh("ip", "-n", ns, "addr", "add", addr, "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        sh("ip", "-n", cls.cl, "route", "add", "default", "via", "10.88.0.1")
        sh("ip", "-n", cls.sv, "route", "add", "default", "via", "10.99.0.1")
        sh("ip", "netns", "exec", cls.gw, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        server = (
            "import socket,threading\n"
            "def serve(p):\n"
            "  s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',p));s.listen()\n"
            "  while True:\n"
            "    c,_=s.accept();c.close()\n"
            "for p in (22,80,8080): threading.Thread(target=serve,args=(p,),daemon=True).start()\n"
            "import time;time.sleep(600)\n"
        )
        cls.srv = subprocess.Popen(["ip", "netns", "exec", cls.sv, sys.executable, "-c", server])
        time.sleep(0.5)
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        cls.srv.kill()
        cls.srv.wait()
        for ns in (cls.cl, cls.gw, cls.sv):
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def probe(self, port: int) -> str:
        code = (
            "import sys,json; sys.path.insert(0,'.');"
            "from nixfort_agent.actions.net import probe;"
            f"print(json.dumps(probe('10.99.0.10', {port}, 1.0)))"
        )
        out = subprocess.run(
            ["ip", "netns", "exec", self.cl, sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
            cwd=AGENT_DIR,
        )
        return json.loads(out.stdout)["result"]

    def gw_nft(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["ip", "netns", "exec", self.gw, "nft", *args], capture_output=True, text=True)

    def load(self, params) -> None:
        path = os.path.join(self.tmp, "nixfort.nft")
        Path(path).write_text(nft.render_policy(params))
        chk = self.gw_nft("-c", "-f", path)
        self.assertEqual(chk.returncode, 0, chk.stderr)
        res = self.gw_nft("-f", path)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_policy_lifecycle(self):
        # baseline: everything open through the gateway
        self.assertEqual([self.probe(p) for p in (80, 8080, 22)], ["OPEN", "OPEN", "OPEN"])

        self.load(PARAMS)
        # ALLOW kept, DENY blocked by `policy drop` (no reply -> TIMEOUT)
        self.assertEqual([self.probe(p) for p in (80, 8080, 22)], ["OPEN", "TIMEOUT", "TIMEOUT"])

        # what nft.inspect reports from the kernel is what the checks FW-02..04 read
        parsed = parsers.parse_nft_ruleset(self.gw_nft("-j", "list", "ruleset").stdout)
        self.assertTrue(parsed["nixfort_table_present"])
        self.assertEqual(parsed["policy_meta"], {"policy_version": 3, "rules_sha256": nft.rules_sha256(PARAMS)})
        self.assertEqual(parsed["nixfort_chains"]["forward"]["policy"], "drop")
        self.assertEqual(parsed["nixfort_chains"]["input"]["policy"], "drop")
        self.assertEqual(parsed["nixfort_input_ssh_sources"], ["10.0.2.2", "10.77.0.10"])
        self.assertEqual(parsed["conflict"]["foreign_base_chains"], [])

        # re-applying (new version, extra rule) replaces the table atomically, no duplicates
        p2 = {
            **PARAMS,
            "policy_version": 4,
            "forward_allow": [*PARAMS["forward_allow"], {"src": "10.88.0.10", "dst": "10.99.0.10", "port": 8080}],
        }
        self.load(p2)
        self.load(p2)
        self.assertEqual([self.probe(p) for p in (80, 8080, 22)], ["OPEN", "OPEN", "TIMEOUT"])
        tables = [
            t
            for t in parsers.parse_nft_ruleset(self.gw_nft("-j", "list", "ruleset").stdout)["tables"]
            if t["name"] == "nixfort"
        ]
        self.assertEqual(len(tables), 1)

        # rollback to "no table" (what _reapply_nft does when the file did not exist before)
        self.assertEqual(self.gw_nft("delete", "table", "inet", "nixfort").returncode, 0)
        self.assertEqual([self.probe(p) for p in (80, 8080, 22)], ["OPEN", "OPEN", "OPEN"])

    def test_render_rejects_nothing_but_typed_values(self):
        text = nft.render_policy(PARAMS)
        self.assertIn('comment "nixfort policy_version=3 rules_sha256=', text)
        self.assertNotIn("8080", text)  # DENY flows are enforced by policy drop, never written


if __name__ == "__main__":
    unittest.main()
