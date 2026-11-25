"""Read a Linux host, or a copy of its files under --root, and check what a Shirudo target needs.

Everything here reads files that any user can read. Nothing is written, loaded or changed. The requirements
come from shirudo's Documentation/operate/plan/system-requirements.rst and its pre-flight checks
(util/preflight.c) at commit 8a3b249b4be8.
"""

import gzip
import os
import re
import subprocess
from dataclasses import dataclass, field

from . import abi
from .btf import BTF, BTFError

OK, FAIL, WARN, INFO = "ok", "fail", "warn", "info"

# systemd's vendor UUID for the variables the boot loader and systemd-stub set (systemd-stub(7)).
SYSTEMD_EFI_VENDOR = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
STUB_VARIABLES = ("StubInfo", "StubImageIdentifier", "StubDevicePartUUID", "StubPcrKernelImage",
                  "StubPcrKernelParameters", "StubProfile")
MIN_SYSTEMD = 256

# Kernel options a target needs, from the "Kernel configuration" table of the system requirements.
REQUIRED_OPTIONS = (
    ("CONFIG_BPF_SYSCALL", "the bpf() system call, bpffs and the .bpf keyring"),
    ("CONFIG_BPF_JIT", "BPF trampolines for fentry, fexit, fmod_ret and lsm programs"),
    ("CONFIG_BPF_LSM", "every admission gate, guard and the seal"),
    ("CONFIG_SECURITY", "the LSM framework"),
    ("CONFIG_BPF_EVENTS", "needed by CONFIG_BPF_LSM"),
    ("CONFIG_PERF_EVENTS", "needed by CONFIG_BPF_EVENTS"),
    ("CONFIG_SECURITYFS", "/sys/kernel/security/lsm"),
    ("CONFIG_FUNCTION_TRACER", "trampolines on ftrace-managed functions"),
    ("CONFIG_DYNAMIC_FTRACE", "trampolines on ftrace-managed functions"),
    ("CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS", "trampolines on ftrace-managed functions"),
    ("CONFIG_DEBUG_INFO_BTF", "/sys/kernel/btf/vmlinux and CO-RE"),
    ("CONFIG_KEYS", "the .bpf and .dm-verity keyrings"),
    ("CONFIG_ASYMMETRIC_KEY_TYPE", "certificates as asymmetric keys"),
    ("CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE", "certificates as asymmetric keys"),
    ("CONFIG_X509_CERTIFICATE_PARSER", "certificates as asymmetric keys"),
    ("CONFIG_PKCS7_MESSAGE_PARSER", "loader signatures"),
    ("CONFIG_SYSTEM_DATA_VERIFICATION", "loader and config image signatures"),
    ("CONFIG_CRYPTO_MLDSA", "ML-DSA-87, the only signature shirudo makes"),
    ("CONFIG_CRYPTO_SHA512", "the digest OpenSSL adds to an ML-DSA signature"),
    ("CONFIG_CRYPTO_SHA256", "the hash trees of the runtime and config images"),
    ("CONFIG_TCG_TPM", "/dev/tpmrm0"),
    ("CONFIG_BLK_DEV_DM", "dm-verity images"),
    ("CONFIG_DM_VERITY", "dm-verity images"),
    ("CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG", "the signed config image and the .dm-verity keyring"),
    ("CONFIG_BLK_DEV_LOOP", "image files on loop devices"),
    ("CONFIG_EXT4_FS", "the images are ext4"),
    ("CONFIG_EXT4_FS_SECURITY", "security labels on /var/lib/shirudo, when it is on ext4"),
    ("CONFIG_TMPFS", "/run/shirudo"),
    ("CONFIG_TMPFS_XATTR", "labels on /run/shirudo"),
)
ONE_OF_OPTIONS = (
    (("CONFIG_KPROBE_EVENTS", "CONFIG_UPROBE_EVENTS"), "needed by CONFIG_BPF_EVENTS", FAIL),
    (("CONFIG_TCG_TIS", "CONFIG_TCG_CRB"), "a TPM driver, unless the platform needs another one", WARN),
)


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""
    hint: str = ""
    items: list = field(default_factory=list)

    def as_dict(self):
        d = {"name": self.name, "status": self.status, "detail": self.detail}
        if self.hint:
            d["hint"] = self.hint
        if self.items:
            d["items"] = self.items
        return d


def default_runner(argv):
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def parse_kernel_config(text):
    opts = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", line)
        if m:
            opts[m.group(1)] = m.group(2).strip('"')
            continue
        m = re.match(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$", line)
        if m:
            opts[m.group(1)] = "n"
    return opts


def check_config(opts):
    """The required options a kernel configuration lacks, as a Result."""
    missing, warn = [], []
    for name, why in REQUIRED_OPTIONS:
        if opts.get(name, "n") not in ("y", "m"):
            missing.append(f"{name} ({why})")
    for names, why, level in ONE_OF_OPTIONS:
        if not any(opts.get(n, "n") in ("y", "m") for n in names):
            (missing if level == FAIL else warn).append(f"{' or '.join(names)} ({why})")
    if opts.get("CONFIG_MODULES") == "y" and opts.get("CONFIG_MODULE_SIG", "n") != "y":
        missing.append("CONFIG_MODULE_SIG (shirudo init refuses a kernel that loads unsigned modules)")
    lsm = opts.get("CONFIG_LSM", "")
    lsm_note = f'CONFIG_LSM="{lsm}"' + ("" if "bpf" in lsm.split(",") else ", so bpf must be added with lsm=")
    if missing:
        return Result("kernel_config", FAIL, f"{len(missing)} required option(s) missing; {lsm_note}",
                      items=missing + [f"warning: {w}" for w in warn])
    if warn:
        return Result("kernel_config", WARN, f"all required options set; {lsm_note}",
                      items=[f"warning: {w}" for w in warn])
    return Result("kernel_config", OK, f"all {len(REQUIRED_OPTIONS) + len(ONE_OF_OPTIONS)} required options "
                                       f"set; {lsm_note}")


class Host:
    """A Linux system seen through its files. root="/" is the running system."""

    def __init__(self, root="/", btf_path=None, config_path=None, runner=default_runner):
        self.root = root
        self.btf_path = btf_path
        self.config_path = config_path
        self.runner = runner
        self._btf = None
        self._btf_error = None

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def read(self, p, binary=False):
        try:
            with open(self.path(p), "rb" if binary else "r", **({} if binary else {"errors": "replace"})) as f:
                return f.read()
        except OSError:
            return None

    def exists(self, p):
        return os.path.lexists(self.path(p))

    def listdir(self, p):
        try:
            return sorted(os.listdir(self.path(p)))
        except OSError:
            return []

    def kernel_release(self):
        text = self.read("/proc/sys/kernel/osrelease")
        return text.strip() if text else None

    def lsm_list(self):
        text = self.read("/sys/kernel/security/lsm")
        if text is None:
            return None
        return [t for t in re.split(r"[,\n]", text) if t]

    def cmdline(self):
        text = self.read("/proc/cmdline")
        return text.split() if text else []

    def btf(self):
        if self._btf is None and self._btf_error is None:
            path = self.btf_path or self.path("/sys/kernel/btf/vmlinux")
            try:
                self._btf = BTF.from_file(path)
            except (OSError, BTFError) as e:
                self._btf_error = f"{path}: {e}"
        return self._btf

    def kernel_config(self):
        """(path, options) of the running kernel's configuration, or (None, None)."""
        candidates = [self.config_path] if self.config_path else []
        release = self.kernel_release()
        if not self.config_path:
            if release:
                candidates.append(self.path(f"/boot/config-{release}"))
            candidates.append(self.path("/proc/config.gz"))
        for c in candidates:
            try:
                if c.endswith(".gz"):
                    with gzip.open(c, "rt", errors="replace") as f:
                        return c, parse_kernel_config(f.read())
                with open(c, errors="replace") as f:
                    return c, parse_kernel_config(f.read())
            except OSError:
                continue
        return None, None

    def systemd_version(self):
        for d in ("/usr/lib/systemd", "/lib/systemd", "/usr/lib64/systemd"):
            for name in self.listdir(d):
                m = re.match(r"^libsystemd-shared-(\d+)", name)
                if m:
                    return int(m.group(1))
        if self.root == "/" and self.runner:
            out = self.runner(["systemctl", "--version"])
            m = re.match(r"^systemd (\d+)", out or "")
            if m:
                return int(m.group(1))
        return None

    # --- the checks a target must pass -------------------------------------------------------------------

    def check_btf_present(self):
        b = self.btf()
        if b is None:
            return Result("kernel_btf", FAIL, f"cannot read kernel BTF ({self._btf_error})",
                          "a target needs CONFIG_DEBUG_INFO_BTF=y")
        return Result("kernel_btf", OK, f"{len(b)} types")

    def check_abi(self):
        b = self.btf()
        if b is None:
            return [Result(n, FAIL, "no kernel BTF to check") for n in
                    ("signed_loader_kernel_abi", "kernel_lsm_hooks", "module_signatures")]
        out = []
        for c in abi.run_all(b):
            hint = ""
            if c.name == "kernel_lsm_hooks" and not c.ok:
                carried = [h for h in abi.CARRIED_HOOKS if h in abi.missing_lsm_hooks(b)]
                if carried:
                    hint = f"{', '.join(carried)} come only from patches shirudo carries; no stock kernel has them"
            out.append(Result(c.name, OK if c.ok else FAIL, c.detail, hint))
        return out

    def check_bpf_lsm(self):
        lsms = self.lsm_list()
        if lsms is None:
            return Result("bpf_lsm_active", FAIL, "cannot read /sys/kernel/security/lsm",
                          "needs CONFIG_SECURITYFS and securityfs mounted")
        if "bpf" in lsms:
            return Result("bpf_lsm_active", OK, "active LSMs: " + ",".join(lsms))
        return Result("bpf_lsm_active", FAIL, "active LSMs: " + ",".join(lsms) + " (no bpf)",
                      "needs CONFIG_BPF_LSM=y and bpf in CONFIG_LSM, or lsm=" + ",".join(lsms + ["bpf"]) +
                      " on the kernel command line")

    def check_bpffs(self):
        text = self.read("/proc/filesystems") or ""
        if any(line.split("\t")[-1].strip() == "bpf" for line in text.splitlines()):
            return Result("bpffs_supported", OK, "/proc/filesystems lists bpf")
        return Result("bpffs_supported", FAIL, "/proc/filesystems does not list bpf", "needs CONFIG_BPF_SYSCALL=y")

    def check_kernel_config(self):
        path, opts = self.kernel_config()
        if opts is None:
            return Result("kernel_config", WARN, "no kernel configuration found in /boot or /proc/config.gz",
                          "pass --config <file>")
        r = check_config(opts)
        r.detail += f" ({path.replace(self.root.rstrip('/'), '', 1) if self.root != '/' else path})"
        return r

    def check_tpm(self):
        dev = self.path("/dev/tpmrm0")
        major = (self.read("/sys/class/tpm/tpm0/tpm_version_major") or "").strip()
        has_sha256 = self.exists("/sys/class/tpm/tpm0/pcr-sha256")
        if not os.path.lexists(dev):
            detail = "no /dev/tpmrm0"
            if major:
                detail += f" (sysfs reports a TPM {major}.x)"
            return Result("tpm2_device", FAIL, detail, "every target needs a TPM 2.0 behind the kernel's "
                                                       "resource manager; there is no mode without one")
        if major and major != "2":
            return Result("tpm2_device", FAIL, f"TPM version {major}.x", "shirudo needs TPM 2.0")
        detail = "/dev/tpmrm0 present" + (", TPM 2.0" if major == "2" else "")
        if self.exists("/sys/class/tpm/tpm0"):
            detail += ", SHA-256 PCR bank" if has_sha256 else ", no SHA-256 PCR bank in sysfs"
            if not has_sha256:
                return Result("tpm2_device", WARN, detail, "shirudo reads and extends PCRs in the SHA-256 bank")
        return Result("tpm2_device", OK, detail, "shirudo opens it as root; this check only sees that it exists")

    def check_systemd(self):
        v = self.systemd_version()
        if v is None:
            return Result("systemd_version", WARN, "systemd version not found")
        if v >= MIN_SYSTEMD:
            return Result("systemd_version", OK, f"systemd {v}")
        return Result("systemd_version", FAIL, f"systemd {v}", f"needs systemd {MIN_SYSTEMD} or newer "
                                                               "(shirudo-initrd.service orders after tpm2.target)")

    def check_uki(self):
        if not self.exists("/sys/firmware/efi"):
            return Result("uki_boot", FAIL, "booted without UEFI", "a target boots a unified kernel image "
                                                                   "through systemd-stub")
        names = self.listdir("/sys/firmware/efi/efivars")
        found = [n.split("-", 1)[0] for n in names
                 if n.endswith("-" + SYSTEMD_EFI_VENDOR) and n.split("-", 1)[0] in STUB_VARIABLES]
        if found:
            return Result("uki_boot", OK, "systemd-stub variables present: " + ", ".join(sorted(set(found))))
        return Result("uki_boot", FAIL, "UEFI boot, but no systemd-stub variables (not a unified kernel image)",
                      "a target boots a signed UKI through systemd-stub, which measures the initrd into PCR 11")

    def check_dracut(self):
        for p in ("/usr/bin/dracut", "/usr/sbin/dracut", "/bin/dracut", "/sbin/dracut"):
            if self.exists(p):
                return Result("dracut_initrd", OK, f"{p} present")
        return Result("dracut_initrd", FAIL, "dracut is not installed",
                      "a target boots a systemd initrd built by dracut with shirudo's 90shirudo module")

    def check_keyring_cmdline(self):
        args = self.cmdline()
        want = ("bpf.keyring_unsealed=1", "dm_verity.keyring_unsealed=1")
        have = [w for w in want if w in args]
        # Information only: a host that is not yet a target has no reason to set them.
        if len(have) == len(want):
            return Result("keyring_cmdline", INFO, "both keyring parameters set")
        return Result("keyring_cmdline", INFO, "not set: " + ", ".join(w for w in want if w not in have),
                      "a target boots with both, from its signed UKI, so that init can enroll and seal the keyrings")

    def target_checks(self):
        return [self.check_btf_present(), *self.check_abi(), self.check_bpf_lsm(), self.check_bpffs(),
                self.check_kernel_config(), self.check_tpm(), self.check_systemd(), self.check_uki(),
                self.check_dracut(), self.check_keyring_cmdline()]
