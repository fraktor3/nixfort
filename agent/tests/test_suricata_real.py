"""The sensor profile against the REAL Suricata binary (7.0.3 = Ubuntu 24.04): the include replaces af-packet and
rule-files, `suricata -T` accepts it, `--dump-config` shows what IDS-03 reads. Detection of the three rules was
checked on live traffic in network namespaces (marker, port scan, SSH brute force) — see S-006."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace

from nixfort_agent import parsers
from nixfort_agent.actions import suricata
from nixfort_agent.osprofile import UBUNTU_2404

from .helpers import make_ctx

DIST = "/etc/suricata/suricata.yaml"


@unittest.skipUnless(shutil.which("suricata") and os.path.isfile(DIST), "needs suricata")
class SensorProfileWithRealSuricata(unittest.TestCase):
    def test_include_is_valid_and_effective(self):
        with tempfile.TemporaryDirectory() as d:
            paths = dict(UBUNTU_2404.paths)
            paths.update(
                suricata_yaml=f"{d}/suricata.yaml",
                suricata_owned=f"{d}/nixfort-sensor.yaml",
                suricata_test_rules=f"{d}/nixfort-test.rules",
                suricata_dist_rules=f"{d}/none.rules",
            )
            ctx = make_ctx()
            ctx.profile = replace(UBUNTU_2404, paths=paths)
            ctx.read_file = lambda p: open(p, encoding="utf-8").read()
            shutil.copy(DIST, paths["suricata_yaml"])
            with open(paths["suricata_owned"], "w") as fh:
                fh.write(suricata.render_sensor(ctx, {"interface": "lo", "test_rules": True}))
            with open(paths["suricata_test_rules"], "w") as fh:
                fh.write(suricata.TEST_RULES)
            new_conf = suricata._yaml_with_include(ctx)  # read before the file is reopened for writing
            with open(paths["suricata_yaml"], "w") as fh:
                fh.write(new_conf)
            self.assertIsNone(suricata._yaml_with_include(ctx))  # include added only once

            t = subprocess.run(
                ["suricata", "-T", "-c", paths["suricata_yaml"], "-l", d], capture_output=True, text=True
            )
            self.assertEqual(t.returncode, 0, t.stderr + t.stdout)
            dump = subprocess.run(
                ["suricata", "--dump-config", "-c", paths["suricata_yaml"]], capture_output=True, text=True
            ).stdout
            cfg = parsers.parse_suricata_dump(dump)
            self.assertEqual(cfg["af_packet_interfaces"], ["lo"])  # the distribution's eth0 is gone
            self.assertEqual(cfg["rule_files"], [paths["suricata_test_rules"]])
            self.assertTrue(cfg["eve_enabled"])


if __name__ == "__main__":
    unittest.main()
