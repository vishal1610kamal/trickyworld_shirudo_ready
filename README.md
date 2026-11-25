# shirudo-ready: could this Linux server run Shirudo shields?

On 23 November 2026, Cisco and OpenAI released **Shirudo**, an open-source runtime that loads small signed
programs, called shields or *upatches*, into a running Linux system to block a known flaw until the real patch is
installed ([OpenAI's post](https://openai.com/index/introducing-shirudo/),
[Isovalent's post](https://isovalent.com/blog/post/cisco-openai-shirudo/),
[the code](https://github.com/shirudo-dev/shirudo), [the docs](https://docs.shirudo.dev/)). It is pre-release.
A machine can only become a Shirudo *target* with a bpf-next kernel carrying shirudo's patches, a TPM 2.0, a
systemd 256+ initrd built by dracut and a unified kernel image. Once it enforces, every other piece of software
that loads BPF stops working, and several systemd hardening settings quietly stop applying.

`shirudo-ready` tells you, before you install anything, how far a server is from that and what would break:

- **Can this host be a Shirudo target?** The kernel checks `shirudo init --check-only` runs
  (`signed_loader_kernel_abi`, `kernel_lsm_hooks`, `module_signatures`, `bpf_lsm_active`, `bpffs_supported`, the
  TPM), read from the kernel's BTF and files instead of the running kernel, plus the rest of the
  [system requirements](https://docs.shirudo.dev/operate/plan/system-requirements.html): 31 kernel options,
  systemd 256 or newer, a boot through systemd-stub, dracut.
- **What would stop working, or weaken?** From the
  [interoperability page](https://docs.shirudo.dev/operate/plan/interoperability.html): systemd units whose
  settings systemd enforces with BPF (`IPAddressDeny=`, `DeviceAllow=`, `RestrictFileSystems=`, and the device
  policy that `PrivateDevices=yes` and `ProtectClock=yes` add), BPF agents and tools, container runtimes, kdump,
  hibernation, `systemd-keyring-setup` and other LSMs.

It needs no root and changes nothing: it only reads files every user can read, such as
`/sys/kernel/btf/vmlinux` and `/sys/kernel/security/lsm`. Python 3.10 or newer, standard library only.

This is the code behind the TrickyWorld article
[Shirudo: can eBPF shields guard your web server?](https://www.trickyworld.in/computer-tricks/cyber-security/shirudo-ebpf-shields-web-server/).

## Try it

```
python3 -m shirudoready                      # check this machine (same as: check)
python3 -m shirudoready check --json         # the same, as JSON
python3 -m shirudoready check --items 0      # list every unit and item, not just the first 12
python3 -m shirudoready btf vmlinux.btf      # the kernel checks on any kernel's BTF file
python3 -m shirudoready config config-7.4    # the kernel options in any kernel configuration file
python3 -m shirudoready units                # only the systemd units whose settings need BPF
python3 -m shirudoready check --root /mnt/image --btf vmlinux.btf --config config-7.4   # a mounted image
```

The exit code is 0 when every target check passes and 1 when one fails.

## What it found

**An Ubuntu 22.04.5 machine** (kernel 6.8.0-149-generic, systemd 249; [results/ubuntu-22.04-kernel-6.8.txt](results/ubuntu-22.04-kernel-6.8.txt)):
7 of 11 target checks fail.

| Check | Result |
|---|---|
| `signed_loader_kernel_abi` | fails at the first field: `struct bpf_map.sha` is missing |
| `kernel_lsm_hooks` | 7 of 49 hooks missing, among them `tpm_command` and `mm_read_access`, which only shirudo's own kernel patches add |
| `bpf_lsm_active` | BPF LSM built (`CONFIG_BPF_LSM=y`) but not active: `lockdown,capability,landlock,yama,apparmor` |
| `kernel_config` | `CONFIG_CRYPTO_MLDSA` missing (ML-DSA-87 is the only signature shirudo makes) |
| `systemd_version` | 249; a target needs 256 |
| `uki_boot` | UEFI, but not booted through systemd-stub |
| `dracut_initrd` | not installed (Ubuntu 22.04 uses initramfs-tools) |
| `kernel_btf`, `module_signatures`, `bpffs_supported`, `tpm2_device` | pass (the machine has a TPM 2.0 with a SHA-256 bank) |

And **28 unit files** use settings that systemd enforces with BPF. On an enforcing target these units still start,
without those restrictions and without an error. They include `systemd-journald`, `systemd-logind`,
`systemd-udevd` and `systemd-resolved`, and, for web servers, `php8.2-fpm` and `php8.3-fpm` (the PHP packages'
own units set `PrivateDevices=true`, whose device policy is a BPF program) and `redis-server`.

**Shirudo's own test kernel** (the x86-64 kernel of release `test-kernel-45212180772`, 7.4 bpf-next with shirudo's
patches, SHA-256 checked; [results/shirudo-test-kernel-7.4.txt](results/shirudo-test-kernel-7.4.txt),
[where it came from](results/shirudo-test-kernel-source.txt)): every kernel check passes and all 31 required
options are set. That is the positive control: the reimplemented checks accept the kernel shirudo is tested on.

## How the kernel checks work

`shirudoready/btf.py` reads raw BTF (the format of `/sys/kernel/btf/vmlinux`, described in the kernel's
`Documentation/bpf/btf.rst`) without libbpf. `shirudoready/abi.py` then applies the same tests as shirudo's
`util/kernel_abi.c` and `util/kernel_prereq.c` at commit `8a3b249b4be8`, reimplemented in Python:

- `struct bpf_map` has `sha` of type `u8[32]` and `excl_prog_sha`, a pointer to a byte, neither a bitfield;
- `struct bpf_prog_aux` has a struct `sig` with `keyring_serial` (s32), `keyring_type` (u8) and `verdict` (u8);
- the kernel has `bpf_lsm_tpm_command`, and a `bpf_lsm_<hook>` function for each of the 49 LSM hooks that
  shirudo's embedded programs (`bpf/bpf2.c`, `bpf/seal.c`) attach to;
- the kernel loads no modules (`__module_address` absent) or checks their signatures (`mod_verify_sig` present).

Typedefs and const/volatile/restrict/type-tag wrappers are followed the way libbpf's helpers do.

## Limits

- It reads; it never loads BPF or opens the TPM. `tpm2_device` sees that `/dev/tpmrm0` exists, not that root can
  use it, and nothing here checks the operator's ML-DSA-87 certificate, which `shirudo init` also verifies.
- The unit scan reads unit files and drop-ins with systemd's precedence (masked units, aliases, `<type>.d/` and
  `<unit>.d/` drop-ins, empty assignments that clear a list). It reports every unit that defines such a setting,
  enabled or not, and does not read user units.
- The list of BPF agents is a short curated one; `sudo bpftool prog show` lists every loaded program.
- The requirements follow shirudo's documentation at commit `8a3b249b4be8`. shirudo has no release yet and its
  requirements may change.

## Tests

```
python3 -m unittest discover -s tests -t .
```

61 tests, all passing on Python 3.10.12, 3.11.0rc1, 3.12.12 and 3.13.11. They build BTF blobs byte by byte to
cover every way the ABI check can fail, and fake system roots for the host and unit checks. Three tests use real
data when you point them at it, and skip otherwise:

```
TW_SHIRUDO_BTF=vmlinux-7.4-shirudo-ci-20261123.btf \
TW_SHIRUDO_CONFIG=config-7.4-shirudo-ci-20261123 \
TW_SHIRUDO_SRC=path/to/shirudo/checkout \
python3 -m unittest discover -s tests -t .
```

The first two come from `kernel-packages-x86-64-ci.zip` of shirudo's `test-kernel-45212180772` release. The
third checks that the 49 hooks in `abi.py` are exactly the ones in shirudo's BPF sources.
