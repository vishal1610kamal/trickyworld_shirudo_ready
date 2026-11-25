"""What on a host would stop working, or quietly weaken, once Shirudo enforces on it.

On an enforcing target only signed shirudo loaders may load BPF. The list follows shirudo's
Documentation/operate/plan/interoperability.rst at commit 8a3b249b4be8: other BPF software fails to load, and
systemd starts units without its BPF-based settings, without failing them.
"""

import os

from .host import Result, OK, WARN, INFO

UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
             "/usr/lib/systemd/system", "/lib/systemd/system")
UNIT_TYPES = ("service", "socket", "slice", "scope", "mount", "swap")

# systemd settings that need BPF (interoperability.rst, "systemd's BPF-based settings"). Values of list
# settings add up, and an empty assignment clears them.
LIST_SETTINGS = ("IPAddressAllow", "IPAddressDeny", "IPIngressFilterPath", "IPEgressFilterPath", "DeviceAllow",
                 "BPFProgram", "SocketBindAllow", "SocketBindDeny", "RestrictNetworkInterfaces",
                 "RestrictFileSystems")
SINGLE_SETTINGS = ("IPAccounting", "DevicePolicy", "BindNetworkInterface", "PrivateDevices", "ProtectClock")
TRUE = {"1", "yes", "y", "true", "t", "on"}

# Processes that load their own BPF programs. The first group is named on the interoperability page.
BPF_PROCESSES = {
    "cilium-agent": "Cilium datapath", "tetragon": "Tetragon", "falco": "Falco (its eBPF drivers)",
    "bpftrace": "bpftrace", "system-probe": "Datadog system-probe", "parca-agent": "Parca agent",
    "beyla": "Grafana Beyla", "tracee": "Tracee", "kepler": "Kepler",
}
BPF_TOOLS = ("/usr/bin/bpftrace", "/usr/sbin/bpftool", "/usr/bin/bpftool", "/usr/share/bcc/tools",
             "/usr/bin/falco", "/usr/bin/tetragon", "/usr/local/bin/tetragon", "/usr/local/bin/cilium-agent")
CONTAINER_RUNTIMES = ("/usr/bin/dockerd", "/usr/bin/containerd", "/usr/bin/podman", "/usr/bin/crio",
                      "/usr/sbin/runc", "/usr/bin/runc", "/usr/bin/crun")
OTHER_LSMS = ("apparmor", "selinux", "smack", "tomoyo")


def _unit_type(name):
    return name.rsplit(".", 1)[-1] if "." in name else ""


def _read_unit(text):
    """(key, value) assignments of a unit file outside [Unit] and [Install], with continuations joined."""
    out, section, pending = [], None, ""
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section in (None, "Unit", "Install") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out.append((key.strip(), " ".join(value.split())))
    return out


def effective_settings(assignments):
    """The BPF-based settings left after applying assignments in order, as {setting: description}."""
    lists = {k: [] for k in LIST_SETTINGS}
    single = {}
    for key, value in assignments:
        if key in lists:
            if value == "":
                lists[key] = []
            else:
                lists[key].append(value)
        elif key in SINGLE_SETTINGS:
            single[key] = value
    found = {}
    for key, values in lists.items():
        if values:
            found[key] = " ".join(values)
    if single.get("IPAccounting", "").lower() in TRUE:
        found["IPAccounting"] = "yes"
    if single.get("DevicePolicy", "").lower() in ("closed", "strict"):
        found["DevicePolicy"] = single["DevicePolicy"]
    if single.get("BindNetworkInterface"):
        found["BindNetworkInterface"] = single["BindNetworkInterface"]
    if single.get("PrivateDevices", "").lower() in TRUE and "DevicePolicy" not in found:
        found["DevicePolicy"] = "closed (from PrivateDevices=yes)"
    if single.get("ProtectClock", "").lower() in TRUE:
        found.setdefault("DeviceAllow", "char-rtc r (from ProtectClock=yes)")
    return found


class UnitScanner:
    def __init__(self, host):
        self.host = host

    def _link_target(self, path):
        try:
            target = os.readlink(path)
        except OSError:
            return None
        return target

    def units(self):
        """{unit name: real file path} for every unit the dirs define, by systemd's precedence, skipping masked
        units and aliases."""
        chosen = {}
        for d in UNIT_DIRS:
            for name in self.host.listdir(d):
                if name in chosen or _unit_type(name) not in UNIT_TYPES:
                    continue
                p = os.path.join(self.host.path(d), name)
                target = self._link_target(p)
                if target is not None:
                    if target == "/dev/null":
                        chosen[name] = None  # masked: lower directories do not count
                        continue
                    if os.path.basename(target) != name:
                        continue  # an alias of another unit, which is scanned under its own name
                    p = self.host.path(target) if os.path.isabs(target) else os.path.join(os.path.dirname(p), target)
                if os.path.isfile(p):
                    chosen[name] = p
        return {k: v for k, v in chosen.items() if v}

    def dropins(self, name):
        """Drop-in files for a unit, by precedence and then in name order: <type>.d/ and <unit>.d/."""
        found = {}
        for dirname in (_unit_type(name) + ".d", name + ".d"):
            for d in UNIT_DIRS:
                for f in self.host.listdir(os.path.join(d, dirname)):
                    if f.endswith(".conf") and (dirname, f) not in found:
                        found[(dirname, f)] = os.path.join(self.host.path(d), dirname, f)
        ordered = sorted(found.items(), key=lambda kv: (kv[0][0] != _unit_type(name) + ".d", kv[0][1]))
        return [p for _, p in ordered]

    def scan(self):
        """[(unit, {setting: value})] for units whose effective configuration uses a BPF-based setting."""
        out = []
        for name, path in sorted(self.units().items()):
            assignments = []
            for p in [path] + self.dropins(name):
                try:
                    with open(p, errors="replace") as f:
                        assignments += _read_unit(f.read())
                except OSError:
                    continue
            found = effective_settings(assignments)
            if found:
                out.append((name, found))
        return out


def check_systemd_settings(host):
    hits = UnitScanner(host).scan()
    if not hits:
        return Result("systemd_bpf_settings", OK, "no unit uses a BPF-based setting")
    items = [f"{unit}: " + ", ".join(f"{k}={v}" for k, v in sorted(s.items())) for unit, s in hits]
    return Result("systemd_bpf_settings", WARN,
                  f"{len(hits)} unit(s) use settings that systemd enforces with BPF; on an enforcing target "
                  "they start without them, with no error", "use nftables or a signed cgroup_skb/netfilter "
                                                            "upatch for address rules", items)


def check_bpf_processes(host):
    seen = {}
    for pid in host.listdir("/proc"):
        if not pid.isdigit():
            continue
        comm = (host.read(f"/proc/{pid}/comm") or "").strip()
        if comm in BPF_PROCESSES or comm.startswith("scx_"):
            seen.setdefault(comm, BPF_PROCESSES.get(comm, "a sched_ext scheduler"))
    if not seen:
        return Result("bpf_programs_running", OK, "no known BPF agent is running")
    return Result("bpf_programs_running", WARN, f"{len(seen)} BPF agent(s) running; their loads would be refused",
                  "ship what they do as signed upatches, or keep them off enforcing targets",
                  [f"{c} ({what})" for c, what in sorted(seen.items())])


def check_bpf_tools(host):
    found = [p for p in BPF_TOOLS if host.exists(p)]
    found += [f"/usr/sbin/{n}" for n in host.listdir("/usr/sbin") if n.endswith("-bpfcc")][:1]
    if not found:
        return Result("bpf_tools_installed", OK, "no BPF tracing tools installed")
    return Result("bpf_tools_installed", INFO, "installed BPF tools stop at their first map or program load "
                  "(bpftool's prog show keeps working)", "run one-off investigations on a host that does not "
                                                          "enforce", found)


def check_container_runtimes(host):
    found = [p for p in CONTAINER_RUNTIMES if host.exists(p)]
    if not found:
        return Result("container_runtimes", OK, "no container runtime installed")
    return Result("container_runtimes", WARN, "on cgroup v2, container device rules are BPF programs, and their "
                  "loads are refused", "shirudo's docs: test your runtime on an enforcing target", found)


def check_kdump(host):
    size = (host.read("/sys/kernel/kexec_crash_size") or "0").strip()
    loaded = (host.read("/sys/kernel/kexec_crash_loaded") or "0").strip()
    units = [u for u in ("kdump-tools.service", "kdump.service")
             if any(host.exists(os.path.join(d, u)) for d in UNIT_DIRS)]
    if size not in ("", "0") or loaded == "1" or units:
        why = units + ([f"crash kernel memory {size} bytes"] if size not in ("", "0") else [])
        return Result("kdump_kexec", WARN, "kexec and kdump are refused on an enforcing target",
                      "plan targets without kdump; pstore needs no second kernel", why)
    return Result("kdump_kexec", OK, "no crash kernel configured")


def check_hibernation(host):
    state = (host.read("/sys/power/state") or "").split()
    if "disk" in state:
        return Result("hibernation", WARN, "hibernation is available here; an enforcing target refuses it",
                      "set AllowHibernation=no in /etc/systemd/sleep.conf")
    return Result("hibernation", OK, "hibernation not offered (" + (" ".join(state) or "no /sys/power/state") + ")")


def check_keyring_setup(host):
    if any(host.exists(os.path.join(d, "systemd-keyring-setup.service")) for d in UNIT_DIRS):
        return Result("systemd_keyring_setup", WARN, "systemd-keyring-setup is installed and would seal the "
                      "keyrings before shirudo init", "mask it in the initrd and on the root file system")
    return Result("systemd_keyring_setup", OK, "systemd-keyring-setup not installed")


def check_other_lsms(host):
    active = [l for l in (host.lsm_list() or []) if l in OTHER_LSMS]
    if not active:
        return Result("other_lsms", OK, "no other major LSM active")
    return Result("other_lsms", INFO, "also active: " + ", ".join(active),
                  "shirudo's docs: run no other LSM whose policy root can change at runtime; the lsm= order "
                  "decides which LSM sees and logs a refusal")


def conflict_checks(host):
    return [check_systemd_settings(host), check_bpf_processes(host), check_bpf_tools(host),
            check_container_runtimes(host), check_kdump(host), check_hibernation(host), check_keyring_setup(host),
            check_other_lsms(host)]
