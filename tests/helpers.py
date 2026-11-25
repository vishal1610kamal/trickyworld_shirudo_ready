"""Fake system roots for the host and conflict checks."""

import os
import shutil
import tempfile
import unittest

from shirudoready.host import SYSTEMD_EFI_VENDOR

from .btfgen import shirudo_like

READY_CONFIG = """\
CONFIG_LOCALVERSION="-test"
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_SECURITY=y
CONFIG_LSM="landlock,lockdown,bpf"
CONFIG_BPF_EVENTS=y
CONFIG_PERF_EVENTS=y
CONFIG_UPROBE_EVENTS=y
# CONFIG_KPROBE_EVENTS is not set
CONFIG_SECURITYFS=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_CRYPTO_MLDSA=m
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA256=y
CONFIG_TCG_TPM=y
CONFIG_TCG_CRB=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_TMPFS=y
CONFIG_TMPFS_XATTR=y
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
"""

RELEASE = "7.4.0-test"


class RootCase(unittest.TestCase):
    """Each test gets an empty directory standing in for a system's /."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="shirudo-ready-test-")
        self.addCleanup(shutil.rmtree, self.root)

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def write(self, rel, content="", binary=False):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb" if binary else "w") as f:
            f.write(content)
        return path

    def mkdir(self, rel):
        os.makedirs(self.p(rel), exist_ok=True)

    def symlink(self, target, rel):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)

    def make_ready(self, **btf_args):
        """A root that passes every target check."""
        self.write("/proc/sys/kernel/osrelease", RELEASE + "\n")
        self.write("/sys/kernel/security/lsm", "lockdown,capability,landlock,bpf")
        self.write("/proc/filesystems", "nodev\tsysfs\nnodev\tbpf\n\text4\n")
        self.write("/sys/kernel/btf/vmlinux", shirudo_like(**btf_args).to_bytes(), binary=True)
        self.write(f"/boot/config-{RELEASE}", READY_CONFIG)
        self.write("/dev/tpmrm0")
        self.write("/sys/class/tpm/tpm0/tpm_version_major", "2\n")
        self.mkdir("/sys/class/tpm/tpm0/pcr-sha256")
        self.write("/usr/lib/systemd/libsystemd-shared-257.so")
        self.write(f"/sys/firmware/efi/efivars/StubInfo-{SYSTEMD_EFI_VENDOR}", b"\x06\x00\x00\x00", binary=True)
        self.write("/usr/bin/dracut")
        self.write("/proc/cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/vda1 bpf.keyring_unsealed=1 "
                                    "dm_verity.keyring_unsealed=1\n")
        self.write("/sys/power/state", "freeze mem\n")
