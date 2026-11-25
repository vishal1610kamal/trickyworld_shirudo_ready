import contextlib
import io
import json
import os
import subprocess
import sys

from shirudoready.__main__ import main

from .btfgen import shirudo_like
from .helpers import RootCase

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class CliTest(RootCase):
    def test_check_ready_and_not_ready(self):
        self.make_ready()
        code, out = run(["check", "--root", self.root])
        self.assertEqual(code, 0)
        self.assertIn("Verdict: ready: every target check passes.", out)
        self.assertIn("What would stop working, or weaken, if it enforced?", out)
        self.write("/sys/kernel/security/lsm", "lockdown,capability,apparmor")
        code, out = run(["check", "--root", self.root, "--json"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertFalse(doc["ready"])
        self.assertEqual((doc["failed"], doc["total"]), (1, 11))
        self.assertEqual(doc["kernel_release"], "7.4.0-test")
        self.assertEqual([r["name"] for r in doc["target"] if r["status"] == "fail"], ["bpf_lsm_active"])
        self.assertEqual(len(doc["conflicts"]), 8)

    def test_check_is_the_default_command(self):
        self.make_ready()
        self.assertEqual(run(["--root", self.root])[0], 0)

    def test_items_are_truncated(self):
        self.make_ready()
        for i in range(5):
            self.write(f"/usr/lib/systemd/system/s{i}.service", "[Service]\nIPAddressDeny=any\n")
        out = run(["check", "--root", self.root, "--items", "2"])[1]
        self.assertIn("s1.service: IPAddressDeny=any", out)
        self.assertNotIn("s2.service", out)
        self.assertIn("... and 3 more (--items 0 shows all)", out)
        self.assertIn("s4.service", run(["check", "--root", self.root, "--items", "0"])[1])

    def test_btf_command(self):
        good = self.write("/good.btf", shirudo_like().to_bytes(), binary=True)
        bad = self.write("/bad.btf", shirudo_like(tpm_hook=False).to_bytes(), binary=True)
        junk = self.write("/junk.btf", "hello, this file is not BTF in any way at all")
        short = self.write("/short.btf", "hi")
        code, out = run(["btf", good])
        self.assertEqual(code, 0)
        self.assertIn("Does this kernel pass shirudo's kernel checks?", out)
        self.assertEqual(run(["btf", bad])[0], 1)
        code, out = run(["btf", junk, "--json"])
        self.assertEqual(code, 1)
        self.assertIn("not BTF", json.loads(out)["target"][0]["detail"])
        self.assertIn("too short", run(["btf", short])[1])
        self.assertIn("No such file", run(["btf", self.p("/nope.btf")])[1])

    def test_config_command(self):
        from .helpers import READY_CONFIG
        cfg = self.write("/kernel.config", READY_CONFIG)
        self.assertEqual(run(["config", cfg])[0], 0)
        code, out = run(["config", self.p("/missing.config")])
        self.assertEqual(code, 1)
        self.assertIn("No such file", out)

    def test_units_command(self):
        self.write("/usr/lib/systemd/system/web.service", "[Service]\nPrivateDevices=yes\n")
        code, out = run(["units", "--root", self.root])
        self.assertEqual(code, 0)
        self.assertIn("web.service: DevicePolicy=closed (from PrivateDevices=yes)", out)
        self.assertNotIn("Verdict", out)

    def test_runs_as_a_module(self):
        self.make_ready()
        p = subprocess.run([sys.executable, "-m", "shirudoready", "check", "--root", self.root],
                           cwd=PROJECT, capture_output=True, text=True, check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("shirudo-ready 1.0.0", p.stdout)
