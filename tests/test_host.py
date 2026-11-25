import gzip
import os
import unittest

from shirudoready import host as H
from shirudoready.host import FAIL, INFO, OK, WARN, Host, check_config, parse_kernel_config

from .btfgen import shirudo_like
from .helpers import READY_CONFIG, RELEASE, RootCase


def by_name(results):
    return {r.name: r for r in results}


class ReadyHostTest(RootCase):
    def test_every_target_check_passes(self):
        self.make_ready()
        results = by_name(Host(self.root).target_checks())
        self.assertEqual(list(results), ["kernel_btf", "signed_loader_kernel_abi", "kernel_lsm_hooks",
                                         "module_signatures", "bpf_lsm_active", "bpffs_supported", "kernel_config",
                                         "tpm2_device", "systemd_version", "uki_boot", "dracut_initrd",
                                         "keyring_cmdline"])
        for r in results.values():
            self.assertEqual(r.status, INFO if r.name == "keyring_cmdline" else OK, r)
        self.assertEqual(results["keyring_cmdline"].detail, "both keyring parameters set")
        self.assertIn("systemd 257", results["systemd_version"].detail)
        self.assertIn("StubInfo", results["uki_boot"].detail)
        self.assertIn("/dev/tpmrm0 present, TPM 2.0, SHA-256 PCR bank", results["tpm2_device"].detail)


class TargetCheckTest(RootCase):
    def setUp(self):
        super().setUp()
        self.make_ready()

    def check(self, name, **kw):
        return by_name(Host(self.root, **kw).target_checks())[name]

    def test_bpf_lsm(self):
        self.write("/sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor")
        r = self.check("bpf_lsm_active")
        self.assertEqual(r.status, FAIL)
        self.assertIn("(no bpf)", r.detail)
        self.assertIn("lsm=lockdown,capability,landlock,yama,apparmor,bpf", r.hint)
        os.remove(self.p("/sys/kernel/security/lsm"))
        self.assertIn("cannot read", self.check("bpf_lsm_active").detail)

    def test_bpffs(self):
        self.write("/proc/filesystems", "nodev\tsysfs\n\text4\n")
        self.assertEqual(self.check("bpffs_supported").status, FAIL)

    def test_stock_kernel_btf(self):
        self.write("/sys/kernel/btf/vmlinux", shirudo_like(sha=False, excl=False, sig=False, tpm_hook=False,
                                                           hooks=[h for h in H.abi.LSM_HOOKS
                                                                  if h not in H.abi.CARRIED_HOOKS]).to_bytes(),
                   binary=True)
        results = by_name(Host(self.root).target_checks())
        self.assertEqual(results["signed_loader_kernel_abi"].status, FAIL)
        hooks = results["kernel_lsm_hooks"]
        self.assertEqual(hooks.status, FAIL)
        self.assertIn("mm_read_access, tpm_command come only from patches shirudo carries", hooks.hint)
        self.assertEqual(results["module_signatures"].status, OK)

    def test_missing_or_broken_btf_fails_all_four_checks(self):
        os.remove(self.p("/sys/kernel/btf/vmlinux"))
        results = by_name(Host(self.root).target_checks())
        for name in ("kernel_btf", "signed_loader_kernel_abi", "kernel_lsm_hooks", "module_signatures"):
            self.assertEqual(results[name].status, FAIL, name)
        self.write("/sys/kernel/btf/vmlinux", b"not btf at all, just bytes", binary=True)
        self.assertIn("not BTF", self.check("kernel_btf").detail)

    def test_btf_path_override(self):
        other = self.write("/elsewhere/vmlinux.btf", shirudo_like(tpm_hook=False).to_bytes(), binary=True)
        self.assertEqual(self.check("signed_loader_kernel_abi", btf_path=other).status, FAIL)

    def test_kernel_config_sources(self):
        os.remove(self.p(f"/boot/config-{RELEASE}"))
        self.assertEqual(self.check("kernel_config").status, WARN)
        with gzip.open(self.p("/proc/config.gz"), "wt") as f:
            f.write(READY_CONFIG)
        r = self.check("kernel_config")
        self.assertEqual(r.status, OK)
        self.assertIn("/proc/config.gz", r.detail)
        explicit = self.write("/tmp/other.config", READY_CONFIG.replace("CONFIG_DM_VERITY=y", ""))
        self.assertEqual(self.check("kernel_config", config_path=explicit).status, FAIL)

    def test_tpm(self):
        os.remove(self.p("/dev/tpmrm0"))
        r = self.check("tpm2_device")
        self.assertEqual(r.status, FAIL)
        self.assertIn("sysfs reports a TPM 2.x", r.detail)
        self.write("/dev/tpmrm0")
        self.write("/sys/class/tpm/tpm0/tpm_version_major", "1\n")
        self.assertIn("TPM version 1.x", self.check("tpm2_device").detail)
        self.write("/sys/class/tpm/tpm0/tpm_version_major", "2\n")
        os.rmdir(self.p("/sys/class/tpm/tpm0/pcr-sha256"))
        self.assertEqual(self.check("tpm2_device").status, WARN)

    def test_systemd_version(self):
        os.remove(self.p("/usr/lib/systemd/libsystemd-shared-257.so"))
        self.write("/lib/systemd/libsystemd-shared-249.so")
        r = self.check("systemd_version")
        self.assertEqual((r.status, r.detail), (FAIL, "systemd 249"))
        os.remove(self.p("/lib/systemd/libsystemd-shared-249.so"))
        self.write("/usr/lib64/systemd/libsystemd-shared-256.11-1.fc41.so")
        self.assertEqual(self.check("systemd_version").detail, "systemd 256")
        os.remove(self.p("/usr/lib64/systemd/libsystemd-shared-256.11-1.fc41.so"))
        self.assertEqual(self.check("systemd_version").status, WARN)

    def test_systemd_version_from_systemctl_on_the_live_root(self):
        h = Host("/", runner=lambda argv: "systemd 258 (258.1-1)\n+PAM +AUDIT\n")
        h.listdir = lambda p: []
        self.assertEqual(h.systemd_version(), 258)
        h = Host("/", runner=lambda argv: None)
        h.listdir = lambda p: []
        self.assertIsNone(h.systemd_version())

    def test_uki(self):
        stub = self.p(f"/sys/firmware/efi/efivars/StubInfo-{H.SYSTEMD_EFI_VENDOR}")
        os.remove(stub)
        self.write("/sys/firmware/efi/efivars/StubInfo-00000000-0000-0000-0000-000000000000")
        self.write(f"/sys/firmware/efi/efivars/LoaderInfo-{H.SYSTEMD_EFI_VENDOR}")
        r = self.check("uki_boot")
        self.assertEqual(r.status, FAIL)
        self.assertIn("no systemd-stub variables", r.detail)
        self.write(f"/sys/firmware/efi/efivars/StubPcrKernelImage-{H.SYSTEMD_EFI_VENDOR}")
        self.assertEqual(self.check("uki_boot").status, OK)
        import shutil
        shutil.rmtree(self.p("/sys/firmware/efi"))
        self.assertIn("without UEFI", self.check("uki_boot").detail)

    def test_dracut(self):
        os.remove(self.p("/usr/bin/dracut"))
        self.assertEqual(self.check("dracut_initrd").status, FAIL)
        self.write("/usr/sbin/dracut")
        self.assertEqual(self.check("dracut_initrd").status, OK)

    def test_keyring_cmdline_is_information_only(self):
        self.write("/proc/cmdline", "root=/dev/sda1 bpf.keyring_unsealed=1\n")
        r = self.check("keyring_cmdline")
        self.assertEqual(r.status, INFO)
        self.assertEqual(r.detail, "not set: dm_verity.keyring_unsealed=1")


class KernelConfigTest(unittest.TestCase):
    def test_parse(self):
        opts = parse_kernel_config('CONFIG_A=y\nCONFIG_B=m\nCONFIG_LSM="a,b"\n# CONFIG_C is not set\n# comment\n')
        self.assertEqual(opts, {"CONFIG_A": "y", "CONFIG_B": "m", "CONFIG_LSM": "a,b", "CONFIG_C": "n"})

    def test_ready_config(self):
        r = check_config(parse_kernel_config(READY_CONFIG))
        self.assertEqual(r.status, OK)
        self.assertIn('CONFIG_LSM="landlock,lockdown,bpf"', r.detail)

    def test_missing_options_are_listed(self):
        cfg = READY_CONFIG.replace("CONFIG_CRYPTO_MLDSA=m", "# CONFIG_CRYPTO_MLDSA is not set")
        cfg = cfg.replace('CONFIG_LSM="landlock,lockdown,bpf"', 'CONFIG_LSM="apparmor"')
        r = check_config(parse_kernel_config(cfg))
        self.assertEqual(r.status, FAIL)
        self.assertTrue(any(i.startswith("CONFIG_CRYPTO_MLDSA") for i in r.items))
        self.assertIn("so bpf must be added with lsm=", r.detail)

    def test_either_or_options(self):
        cfg = READY_CONFIG.replace("CONFIG_UPROBE_EVENTS=y", "")
        self.assertEqual(check_config(parse_kernel_config(cfg)).status, FAIL)
        cfg = READY_CONFIG.replace("CONFIG_TCG_CRB=y", "")
        r = check_config(parse_kernel_config(cfg))
        self.assertEqual(r.status, WARN)
        self.assertIn("CONFIG_TCG_TIS or CONFIG_TCG_CRB", r.items[0])

    def test_unsigned_modules(self):
        cfg = READY_CONFIG.replace("CONFIG_MODULE_SIG=y", "# CONFIG_MODULE_SIG is not set")
        r = check_config(parse_kernel_config(cfg))
        self.assertEqual(r.status, FAIL)
        self.assertTrue(any("CONFIG_MODULE_SIG" in i for i in r.items))


if __name__ == "__main__":
    unittest.main()
