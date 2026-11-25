import unittest

from shirudoready import conflicts as C
from shirudoready.host import INFO, OK, WARN, Host

from .helpers import RootCase

VENDOR = "/usr/lib/systemd/system"


class UnitScanTest(RootCase):
    def scan(self):
        return dict(C.UnitScanner(Host(self.root)).scan())

    def test_settings_and_implied_settings(self):
        self.write(f"{VENDOR}/a.service", "[Service]\nIPAddressDeny=any\nIPAddressAllow=localhost\n")
        self.write(f"{VENDOR}/b.service", "[Service]\nPrivateDevices=yes\nProtectClock=true\n")
        self.write(f"{VENDOR}/c.service", "[Service]\nPrivateDevices=no\nIPAccounting=no\nDevicePolicy=auto\n")
        self.write(f"{VENDOR}/d.socket", "[Socket]\nSocketBindDeny=any\nRestrictNetworkInterfaces=eth0\n")
        self.write(f"{VENDOR}/e.service", "[Service]\nPrivateDevices=1\nDevicePolicy=strict\nDeviceAllow=/dev/null rw\n"
                                          "ProtectClock=yes\n")
        self.write(f"{VENDOR}/f.slice", "[Slice]\nIPAccounting=on\nRestrictFileSystems=ext4 tmpfs\n")
        self.write(f"{VENDOR}/g.service", "[Service]\nBindNetworkInterface=eth1\nBPFProgram=egress:/sys/fs/bpf/x\n"
                                          "IPIngressFilterPath=/sys/fs/bpf/in\n")
        found = self.scan()
        self.assertEqual(found["a.service"], {"IPAddressDeny": "any", "IPAddressAllow": "localhost"})
        self.assertEqual(found["b.service"], {"DevicePolicy": "closed (from PrivateDevices=yes)",
                                              "DeviceAllow": "char-rtc r (from ProtectClock=yes)"})
        self.assertNotIn("c.service", found)
        self.assertEqual(found["d.socket"], {"SocketBindDeny": "any", "RestrictNetworkInterfaces": "eth0"})
        # Explicit values win over what PrivateDevices= and ProtectClock= imply.
        self.assertEqual(found["e.service"], {"DevicePolicy": "strict", "DeviceAllow": "/dev/null rw"})
        self.assertEqual(found["f.slice"], {"IPAccounting": "yes", "RestrictFileSystems": "ext4 tmpfs"})
        self.assertEqual(set(found["g.service"]), {"BindNetworkInterface", "BPFProgram", "IPIngressFilterPath"})

    def test_parsing_rules(self):
        self.write(f"{VENDOR}/p.service", "# IPAddressDeny=any\n; IPAddressDeny=any\n[Unit]\nIPAddressDeny=any\n"
                                          "[Install]\nIPAddressDeny=any\n[Service]\nExecStart=/bin/true\n")
        self.write(f"{VENDOR}/q.service", "[Service]\nIPAddressDeny=10.0.0.0/8 \\\n  192.168.0.0/16\n")
        self.write(f"{VENDOR}/r.service", "[Service]\nIPAddressDeny=any\nIPAddressDeny=\n")
        found = self.scan()
        self.assertNotIn("p.service", found)
        self.assertEqual(found["q.service"]["IPAddressDeny"], "10.0.0.0/8 192.168.0.0/16")
        self.assertNotIn("r.service", found)  # an empty assignment clears the list

    def test_precedence_mask_alias_and_link(self):
        self.write(f"{VENDOR}/over.service", "[Service]\nIPAddressDeny=any\n")
        self.write("/etc/systemd/system/over.service", "[Service]\nExecStart=/bin/true\n")
        self.write(f"{VENDOR}/masked.service", "[Service]\nIPAddressDeny=any\n")
        self.symlink("/dev/null", "/etc/systemd/system/masked.service")
        self.write(f"{VENDOR}/real.service", "[Service]\nIPAddressDeny=any\n")
        self.symlink(f"{VENDOR}/real.service", "/etc/systemd/system/alias.service")
        self.write("/opt/app/linked.service", "[Service]\nDeviceAllow=/dev/fuse rw\n")
        self.symlink("/opt/app/linked.service", "/etc/systemd/system/linked.service")
        found = self.scan()
        self.assertNotIn("over.service", found)
        self.assertNotIn("masked.service", found)
        self.assertNotIn("alias.service", found)
        self.assertIn("real.service", found)
        self.assertEqual(found["linked.service"], {"DeviceAllow": "/dev/fuse rw"})

    def test_dropins(self):
        self.write(f"{VENDOR}/web.service", "[Service]\nIPAddressDeny=any\n")
        self.write(f"{VENDOR}/web.service.d/10-vendor.conf", "[Service]\nIPAddressAllow=127.0.0.1\n")
        self.write("/etc/systemd/system/web.service.d/10-vendor.conf", "[Service]\nExecStartPre=/bin/true\n")
        self.write("/etc/systemd/system/web.service.d/20-reset.conf", "[Service]\nIPAddressDeny=\n")
        self.write(f"{VENDOR}/web.service.d/README", "IPAddressDeny=any\n")
        self.write(f"{VENDOR}/other.service", "[Service]\nExecStart=/bin/true\n")
        self.write("/etc/systemd/system/service.d/50-all.conf", "[Service]\nIPAccounting=yes\n")
        found = self.scan()
        # /etc's 10-vendor.conf replaces the vendor one, and 20-reset.conf clears the deny list.
        self.assertEqual(found["web.service"], {"IPAccounting": "yes"})
        self.assertEqual(found["other.service"], {"IPAccounting": "yes"})

    def test_merged_usr_and_other_files(self):
        self.write(f"{VENDOR}/once.service", "[Service]\nIPAddressDeny=any\n")
        self.symlink("usr/lib", "/lib")
        self.write(f"{VENDOR}/multi-user.target", "[Unit]\nDescription=x\n")
        self.write(f"{VENDOR}/notes.txt", "IPAddressDeny=any\n")
        hits = C.UnitScanner(Host(self.root)).scan()
        self.assertEqual([u for u, _ in hits], ["once.service"])

    def test_result(self):
        r = C.check_systemd_settings(Host(self.root))
        self.assertEqual(r.status, OK)
        self.write(f"{VENDOR}/z.service", "[Service]\nIPAddressDeny=any\n")
        self.write(f"{VENDOR}/a.service", "[Service]\nPrivateDevices=yes\n")
        r = C.check_systemd_settings(Host(self.root))
        self.assertEqual(r.status, WARN)
        self.assertEqual(r.items, ["a.service: DevicePolicy=closed (from PrivateDevices=yes)",
                                   "z.service: IPAddressDeny=any"])


class OtherConflictsTest(RootCase):
    def test_bpf_processes(self):
        self.assertEqual(C.check_bpf_processes(Host(self.root)).status, OK)
        self.write("/proc/101/comm", "cilium-agent\n")
        self.write("/proc/102/comm", "scx_rusty\n")
        self.write("/proc/103/comm", "bash\n")
        self.write("/proc/self/comm", "python3\n")
        r = C.check_bpf_processes(Host(self.root))
        self.assertEqual(r.status, WARN)
        self.assertEqual(r.items, ["cilium-agent (Cilium datapath)", "scx_rusty (a sched_ext scheduler)"])

    def test_tools_and_runtimes(self):
        h = Host(self.root)
        self.assertEqual(C.check_bpf_tools(h).status, OK)
        self.assertEqual(C.check_container_runtimes(h).status, OK)
        self.write("/usr/sbin/bpftool")
        self.write("/usr/sbin/opensnoop-bpfcc")
        self.write("/usr/sbin/execsnoop-bpfcc")
        self.write("/usr/bin/containerd")
        r = C.check_bpf_tools(h)
        self.assertEqual(r.status, INFO)
        self.assertEqual(r.items, ["/usr/sbin/bpftool", "/usr/sbin/execsnoop-bpfcc"])
        self.assertEqual(C.check_container_runtimes(h).items, ["/usr/bin/containerd"])

    def test_kdump(self):
        h = Host(self.root)
        self.write("/sys/kernel/kexec_crash_size", "0\n")
        self.assertEqual(C.check_kdump(h).status, OK)
        self.write("/sys/kernel/kexec_crash_size", "268435456\n")
        r = C.check_kdump(h)
        self.assertEqual(r.status, WARN)
        self.assertIn("crash kernel memory 268435456 bytes", r.items)
        self.write("/sys/kernel/kexec_crash_size", "0\n")
        self.write("/usr/lib/systemd/system/kdump-tools.service", "[Service]\n")
        self.assertEqual(C.check_kdump(h).items, ["kdump-tools.service"])

    def test_hibernation_keyring_setup_and_lsms(self):
        h = Host(self.root)
        self.write("/sys/power/state", "freeze mem disk\n")
        self.assertEqual(C.check_hibernation(h).status, WARN)
        self.write("/sys/power/state", "freeze mem\n")
        self.assertEqual(C.check_hibernation(h).status, OK)
        self.assertEqual(C.check_keyring_setup(h).status, OK)
        self.write("/usr/lib/systemd/system/systemd-keyring-setup.service", "[Service]\n")
        self.assertEqual(C.check_keyring_setup(h).status, WARN)
        self.write("/sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor,bpf")
        r = C.check_other_lsms(h)
        self.assertEqual((r.status, r.detail), (INFO, "also active: apparmor"))
        self.write("/sys/kernel/security/lsm", "lockdown,capability,bpf")
        self.assertEqual(C.check_other_lsms(h).status, OK)

    def test_all_conflict_checks_run_on_an_empty_root(self):
        names = [r.name for r in C.conflict_checks(Host(self.root))]
        self.assertEqual(names, ["systemd_bpf_settings", "bpf_programs_running", "bpf_tools_installed",
                                 "container_runtimes", "kdump_kexec", "hibernation", "systemd_keyring_setup",
                                 "other_lsms"])


if __name__ == "__main__":
    unittest.main()
