"""Checks against real kernels and a real shirudo checkout, when they are available.

  TW_SHIRUDO_BTF     the BTF of shirudo's test kernel (vmlinux-<release>.btf from its kernel-packages zip)
  TW_SHIRUDO_CONFIG  that kernel's configuration (config-<release> from the same zip)
  TW_SHIRUDO_SRC     a shirudo checkout, to compare the LSM hook list with its BPF sources
The running kernel's /sys/kernel/btf/vmlinux is used when it is readable.
"""

import os
import re
import unittest

from shirudoready import abi
from shirudoready.btf import BTF
from shirudoready.host import OK, Host, check_config, parse_kernel_config
from shirudoready.conflicts import conflict_checks

SHIRUDO_BTF = os.environ.get("TW_SHIRUDO_BTF")
SHIRUDO_CONFIG = os.environ.get("TW_SHIRUDO_CONFIG")
SHIRUDO_SRC = os.environ.get("TW_SHIRUDO_SRC")
HOST_BTF = "/sys/kernel/btf/vmlinux"


@unittest.skipUnless(SHIRUDO_BTF and os.path.exists(SHIRUDO_BTF), "TW_SHIRUDO_BTF not set")
class ShirudoTestKernelTest(unittest.TestCase):
    def test_passes_every_kernel_check(self):
        b = BTF.from_file(SHIRUDO_BTF)
        for c in abi.run_all(b):
            self.assertTrue(c.ok, c)


@unittest.skipUnless(SHIRUDO_CONFIG and os.path.exists(SHIRUDO_CONFIG), "TW_SHIRUDO_CONFIG not set")
class ShirudoTestKernelConfigTest(unittest.TestCase):
    def test_has_every_required_option(self):
        with open(SHIRUDO_CONFIG) as f:
            self.assertEqual(check_config(parse_kernel_config(f.read())).status, OK)


@unittest.skipUnless(os.access(HOST_BTF, os.R_OK), "no readable kernel BTF on this machine")
class RunningKernelTest(unittest.TestCase):
    def test_reads_the_running_kernel(self):
        b = BTF.from_file(HOST_BTF)
        self.assertIsNotNone(b.find("bpf_map", 4))
        abi_ok = abi.signed_loader_abi(b).ok
        if abi_ok:  # a kernel with the whole ABI also has the tpm_command hook the ABI check requires
            self.assertTrue(b.has_func("bpf_lsm_tpm_command"))

    def test_full_check_runs_on_this_host(self):
        h = Host("/")
        results = h.target_checks() + conflict_checks(h)
        self.assertEqual(len(results), 20)
        self.assertTrue(all(r.status in ("ok", "fail", "warn", "info") for r in results))


@unittest.skipUnless(SHIRUDO_SRC and os.path.isdir(SHIRUDO_SRC), "TW_SHIRUDO_SRC not set")
class HookListTest(unittest.TestCase):
    def test_matches_the_embedded_objects(self):
        hooks = set()
        for name in ("bpf2.c", "seal.c"):
            with open(os.path.join(SHIRUDO_SRC, "bpf", name)) as f:
                hooks |= set(re.findall(r'SEC\("lsm(?:\.s)?/([a-z_0-9]+)"\)', f.read()))
        self.assertEqual(hooks, set(abi.LSM_HOOKS))


if __name__ == "__main__":
    unittest.main()
