"""Three of the kernel checks that `shirudo init --check-only` runs, done on a BTF file instead of the running
kernel, so they work without root, on any machine, against any kernel's BTF:

- signed_loader_kernel_abi: the fields of the signed BPF loader interface, with the types shirudo expects,
  and the tpm_command LSM hook (shirudo util/kernel_abi.c, kernel_abi_validate_btf);
- kernel_lsm_hooks: a bpf_lsm_<hook> function for every LSM hook shirudo's embedded programs attach to
  (util/kernel_abi.c, kernel_abi_validate_lsm_hooks);
- module_signatures: the kernel loads no modules, or checks their signatures (util/kernel_prereq.c).

The logic follows shirudo at commit 8a3b249b4be8; this is an independent reimplementation in Python.
"""

from dataclasses import dataclass

from . import btf as B

SHA_SIZE = 32

# The LSM hooks that shirudo's two embedded BPF objects attach to: every SEC("lsm/<hook>") and
# SEC("lsm.s/<hook>") in bpf/bpf2.c and bpf/seal.c at commit 8a3b249b4be8.
LSM_HOOKS = (
    "bdev_free_security", "bdev_setintegrity", "bpf", "bpf_map", "bpf_prog", "bpf_prog_load",
    "bprm_check_security", "bprm_committed_creds", "bprm_creds_for_exec", "file_ioctl", "file_ioctl_compat",
    "file_mprotect", "file_open", "inode_copy_up", "inode_create", "inode_file_setattr", "inode_init_security",
    "inode_link", "inode_mkdir", "inode_mknod", "inode_post_removexattr", "inode_post_setxattr",
    "inode_remove_acl", "inode_removexattr", "inode_rename", "inode_rmdir", "inode_set_acl", "inode_setattr",
    "inode_setxattr", "inode_symlink", "inode_unlink", "kernel_load_data", "kernel_read_file", "key_permission",
    "locked_down", "mm_read_access", "mmap_file", "move_mount", "perf_event_alloc", "ptrace_access_check",
    "sb_mount", "sb_remount", "sb_umount", "socket_post_create", "task_alloc", "task_kill", "task_prctl",
    "task_setrlimit", "tpm_command",
)

# Hooks no upstream tree has yet: they come from patches shirudo carries (Documentation/internals/kernel-patches).
CARRIED_HOOKS = ("mm_read_access", "tpm_command")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


def _is_int(t, nbytes):
    return (t is not None and t.kind == B.INT and t.size == nbytes and t.int_offset == 0
            and t.int_bits == nbytes * 8)


def is_unsigned_int(t, nbytes):
    return _is_int(t, nbytes) and not t.int_encoding & B.INT_SIGNED


def is_signed_int(t, nbytes):
    return _is_int(t, nbytes) and bool(t.int_encoding & B.INT_SIGNED)


def is_byte_int(t):
    return _is_int(t, 1)


def _fail(name, detail):
    return Check(name, False, detail)


def signed_loader_abi(btf):
    name = "signed_loader_kernel_abi"
    patched = "; boot a shirudo-patched kernel"
    bpf_map = btf.find("bpf_map", B.STRUCT)
    if bpf_map is None:
        return _fail(name, "kernel BTF has no struct bpf_map" + patched)

    sha = btf.member(bpf_map, "sha")
    if sha is None:
        return _fail(name, "struct bpf_map.sha is missing" + patched)
    if sha.bitfield_size:
        return _fail(name, "struct bpf_map.sha must not be a bitfield")
    arr = btf.unwrap(sha.type)
    if arr is None or arr.kind != B.ARRAY or arr.array_nelems != SHA_SIZE \
            or not is_unsigned_int(btf.unwrap(arr.array_elem), 1):
        return _fail(name, "struct bpf_map.sha must have type u8[32]")

    excl = btf.member(bpf_map, "excl_prog_sha")
    if excl is None:
        return _fail(name, "struct bpf_map.excl_prog_sha is missing" + patched)
    if excl.bitfield_size:
        return _fail(name, "struct bpf_map.excl_prog_sha must not be a bitfield")
    ptr = btf.unwrap(excl.type)
    if ptr is None or ptr.kind != B.PTR:
        return _fail(name, "struct bpf_map.excl_prog_sha must have pointer type")
    if not is_byte_int(btf.unwrap(ptr.ref)):
        return _fail(name, "struct bpf_map.excl_prog_sha must point to a byte")

    aux = btf.find("bpf_prog_aux", B.STRUCT)
    if aux is None:
        return _fail(name, "kernel BTF has no struct bpf_prog_aux" + patched)
    sig = btf.member(aux, "sig")
    if sig is None:
        return _fail(name, "struct bpf_prog_aux.sig is missing" + patched)
    sig_t = btf.unwrap(sig.type)
    if sig_t is None or sig_t.kind != B.STRUCT:
        return _fail(name, "struct bpf_prog_aux.sig must have struct type")
    for field, test, want in (("keyring_serial", is_signed_int, (4, "s32")),
                              ("keyring_type", is_unsigned_int, (1, "u8")),
                              ("verdict", is_unsigned_int, (1, "u8"))):
        m = btf.member(sig_t, field)
        if m is None or not test(btf.unwrap(m.type), want[0]):
            return _fail(name, f"struct bpf_prog_aux.sig.{field} must have type {want[1]}")

    if not btf.has_func("bpf_lsm_tpm_command"):
        return _fail(name, "tpm_command LSM hook is missing" + patched)
    return Check(name, True)


def missing_lsm_hooks(btf, hooks=LSM_HOOKS):
    return [h for h in hooks if not btf.has_func("bpf_lsm_" + h)]


def lsm_hooks(btf, hooks=LSM_HOOKS):
    missing = missing_lsm_hooks(btf, hooks)
    if not missing:
        return Check("kernel_lsm_hooks", True, f"all {len(hooks)} hooks present")
    s = "s" if len(missing) > 1 else ""
    return _fail("kernel_lsm_hooks", f"kernel has no LSM hook{s} {', '.join(missing)} "
                                     f"({len(missing)} of {len(hooks)}); boot a shirudo-patched kernel")


def module_signatures(btf):
    # Each name is a function only its kernel option builds, so its absence from BTF means the option is off.
    modules = btf.has_func("__module_address")
    module_sig = btf.has_func("mod_verify_sig")
    if not modules:
        return Check("module_signatures", True, "the kernel loads no modules")
    if module_sig:
        return Check("module_signatures", True, "modules are signature-checked (CONFIG_MODULE_SIG)")
    return _fail("module_signatures", "the kernel loads modules without checking their signatures "
                                      "(needs CONFIG_MODULE_SIG=y, or CONFIG_MODULES=n)")


def run_all(btf):
    return [signed_loader_abi(btf), lsm_hooks(btf), module_signatures(btf)]
