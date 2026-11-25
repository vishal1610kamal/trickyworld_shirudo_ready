import unittest

from shirudoready import abi
from shirudoready.btf import BTF

from .btfgen import shirudo_like


def run(**kw):
    t = BTF(shirudo_like(**kw).to_bytes())
    return abi.signed_loader_abi(t), abi.lsm_hooks(t), abi.module_signatures(t)


class SignedLoaderAbiTest(unittest.TestCase):
    def test_a_patched_kernel_passes_every_check(self):
        for c in run():
            self.assertTrue(c.ok, c)
        self.assertEqual(run()[1].detail, f"all {len(abi.LSM_HOOKS)} hooks present")

    def assertAbiFails(self, message, **kw):
        c = run(**kw)[0]
        self.assertFalse(c.ok)
        self.assertEqual(c.name, "signed_loader_kernel_abi")
        self.assertIn(message, c.detail)

    def test_each_part_of_the_abi(self):
        cases = [
            ("kernel BTF has no struct bpf_map", dict(bpf_map=False)),
            ("struct bpf_map.sha is missing", dict(sha=False)),
            ("struct bpf_map.sha must not be a bitfield", dict(sha_bitfield=True)),
            ("struct bpf_map.sha must have type u8[32]", dict(sha_nelems=20)),
            ("struct bpf_map.sha must have type u8[32]", dict(sha_signed=True)),
            ("struct bpf_map.sha must have type u8[32]", dict(sha_as_ptr=True)),
            ("struct bpf_map.excl_prog_sha is missing", dict(excl=False)),
            ("struct bpf_map.excl_prog_sha must not be a bitfield", dict(excl_bitfield=True)),
            ("struct bpf_map.excl_prog_sha must have pointer type", dict(excl_as_int=True)),
            ("struct bpf_map.excl_prog_sha must point to a byte", dict(excl_pointee="u16")),
            ("kernel BTF has no struct bpf_prog_aux", dict(prog_aux=False)),
            ("struct bpf_prog_aux.sig is missing", dict(sig=False)),
            ("struct bpf_prog_aux.sig must have struct type", dict(sig_union=True)),
            ("sig.keyring_serial must have type s32", dict(serial_signed=False)),
            ("sig.keyring_type must have type u8", dict(type_size=2)),
            ("sig.verdict must have type u8", dict(verdict=False)),
            ("tpm_command LSM hook is missing", dict(tpm_hook=False)),
        ]
        for message, kw in cases:
            with self.subTest(message=message, kw=kw):
                self.assertAbiFails(message, **kw)

    def test_the_first_problem_is_the_one_reported(self):
        # A stock kernel lacks everything; shirudo reports the first gap, bpf_map.sha.
        c = run(sha=False, excl=False, sig=False, tpm_hook=False)[0]
        self.assertIn("bpf_map.sha is missing", c.detail)


class HooksAndModulesTest(unittest.TestCase):
    def test_missing_hooks_are_listed_in_order(self):
        hooks = [h for h in abi.LSM_HOOKS if h not in ("mm_read_access", "bdev_setintegrity")]
        c = run(hooks=hooks)[1]
        self.assertFalse(c.ok)
        self.assertIn("kernel has no LSM hooks bdev_setintegrity, mm_read_access (2 of 49)", c.detail)
        one = run(hooks=[h for h in abi.LSM_HOOKS if h != "task_kill"])[1]
        self.assertIn("kernel has no LSM hook task_kill (1 of 49)", one.detail)

    def test_hook_list_matches_shirudo(self):
        self.assertEqual(len(abi.LSM_HOOKS), 49)
        self.assertEqual(len(set(abi.LSM_HOOKS)), 49)
        self.assertEqual(list(abi.LSM_HOOKS), sorted(abi.LSM_HOOKS))
        self.assertTrue(set(abi.CARRIED_HOOKS) <= set(abi.LSM_HOOKS))

    def test_module_signatures(self):
        self.assertEqual(run(modules=False, module_sig=False)[2].detail, "the kernel loads no modules")
        self.assertTrue(run(modules=True, module_sig=True)[2].ok)
        c = run(modules=True, module_sig=False)[2]
        self.assertFalse(c.ok)
        self.assertIn("without checking their signatures", c.detail)


class IntHelpersTest(unittest.TestCase):
    def test_integer_shapes(self):
        t = BTF(shirudo_like().to_bytes())
        by_name = {x.name: x for x in t.types if x.kind == 1}
        self.assertTrue(abi.is_unsigned_int(by_name["unsigned char"], 1))
        self.assertFalse(abi.is_unsigned_int(by_name["signed char"], 1))
        self.assertTrue(abi.is_signed_int(by_name["int"], 4))
        self.assertFalse(abi.is_signed_int(by_name["unsigned int"], 4))
        self.assertTrue(abi.is_byte_int(by_name["char"]))
        self.assertFalse(abi.is_byte_int(by_name["unsigned short"]))
        self.assertFalse(abi.is_unsigned_int(None, 1))


if __name__ == "__main__":
    unittest.main()
