"""Command line: python3 -m shirudoready {check,btf,config,units} ..."""

import argparse
import sys

from . import __version__, abi, report
from .btf import BTF, BTFError
from .conflicts import check_systemd_settings, conflict_checks
from .host import FAIL, OK, Host, Result, check_config, parse_kernel_config


def _btf_results(path):
    try:
        b = BTF.from_file(path)
    except (OSError, BTFError) as e:
        return [Result("kernel_btf", FAIL, f"{path}: {e}")]
    out = [Result("kernel_btf", OK, f"{len(b)} types, {b.byteorder}-endian")]
    for c in abi.run_all(b):
        out.append(Result(c.name, OK if c.ok else FAIL, c.detail))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(prog="shirudo-ready", description="Check, without root, whether a Linux host "
                                "could become a Shirudo target and what would stop working if it did.")
    p.add_argument("--version", action="version", version=f"shirudo-ready {__version__}")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="check this host (the default)")
    c.add_argument("--root", default="/", help="read a copy of a system's files under this directory")
    c.add_argument("--btf", help="kernel BTF to check instead of /sys/kernel/btf/vmlinux")
    c.add_argument("--config", help="kernel configuration instead of /boot/config-<release>")
    c.add_argument("--json", action="store_true")
    c.add_argument("--items", type=int, default=12, help="items listed per check in text output (0: all)")

    b = sub.add_parser("btf", help="run the kernel ABI checks on a BTF file")
    b.add_argument("file")
    b.add_argument("--json", action="store_true")

    k = sub.add_parser("config", help="check a kernel configuration file")
    k.add_argument("file")
    k.add_argument("--json", action="store_true")

    u = sub.add_parser("units", help="list systemd units whose settings need BPF")
    u.add_argument("--root", default="/")
    u.add_argument("--json", action="store_true")
    u.add_argument("--items", type=int, default=0)

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version")):
        argv = ["check"] + argv  # check is the default command
    args = p.parse_args(argv)

    heading = "Can this host be a Shirudo target?"
    if args.cmd == "check":
        host = Host(root=args.root, btf_path=args.btf, config_path=args.config)
        target, conflicts, kernel = host.target_checks(), conflict_checks(host), host.kernel_release()
    elif args.cmd == "btf":
        target, conflicts, kernel = _btf_results(args.file), None, f"(BTF file {args.file})"
        heading = "Does this kernel pass shirudo's kernel checks?"
    elif args.cmd == "config":
        try:
            with open(args.file, errors="replace") as f:
                target = [check_config(parse_kernel_config(f.read()))]
        except OSError as e:
            target = [Result("kernel_config", FAIL, str(e))]
        conflicts, kernel = None, f"(configuration file {args.file})"
        heading = "Does this configuration have every option a target needs?"
    else:
        host = Host(root=args.root)
        target, conflicts, kernel = [], [check_systemd_settings(host)], host.kernel_release()

    if args.json:
        sys.stdout.write(report.as_json(kernel, target, conflicts))
    else:
        sys.stdout.write(report.text(kernel, target, conflicts, getattr(args, "items", 12), heading))
    ready, _, _ = report.verdict(target)
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
