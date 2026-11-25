import struct
import unittest

from shirudoready import btf as B

from .btfgen import BTFBuilder, shirudo_like


class ParseTest(unittest.TestCase):
    def test_reads_types_names_and_members(self):
        b = shirudo_like()
        t = B.BTF(b.to_bytes())
        self.assertEqual(len(t), len(b.types))
        bpf_map = t.find("bpf_map", B.STRUCT)
        self.assertIsNotNone(bpf_map)
        self.assertEqual([m.name for m in t.members(bpf_map)],
                         ["ops", "inner_map_meta", "key_size", "sha", "excl_prog_sha"])
        sha = t.member(bpf_map, "sha")
        self.assertEqual((sha.bit_offset, sha.bitfield_size), (160, 0))
        arr = t.unwrap(sha.type)
        self.assertEqual((arr.kind, arr.array_nelems), (B.ARRAY, 32))
        elem = t.unwrap(arr.array_elem)  # through const, u8, __u8
        self.assertEqual((elem.name, elem.size, elem.int_bits, elem.int_encoding), ("unsigned char", 1, 8, 0))
        self.assertIsNone(t.member(bpf_map, "nope"))
        self.assertTrue(t.has_func("bpf_lsm_tpm_command"))
        self.assertFalse(t.has_func("bpf_lsm_no_such_hook"))
        self.assertEqual(t.type(0).kind, B.UNKN)
        self.assertIsNone(t.type(len(t) + 1))
        self.assertIsNone(t.type(-1))

    def test_bitfields_with_kind_flag(self):
        t = B.BTF(shirudo_like(sha_bitfield=True).to_bytes())
        sha = t.member(t.find("bpf_map", B.STRUCT), "sha")
        self.assertEqual((sha.bit_offset, sha.bitfield_size), (160, 1))

    def test_every_kind_keeps_the_reader_aligned(self):
        b = BTFBuilder()
        i32 = b.int("int", 4, signed=True)
        b.add(B.FWD, "fwd_struct")
        b.enum("color", [("RED", 0), ("GREEN", -1)])
        b.enum64("big", [("HUGE", 1 << 40)])
        proto = b.func_proto(i32, [("a", i32), ("b", i32)])
        b.func("f", proto)
        b.add(B.VAR, "v", size_or_type=i32, extra=[("I", 1)])
        b.add(B.DATASEC, ".data", vlen=2, size_or_type=8, extra=[("III", i32, 0, 4), ("III", i32, 4, 4)])
        b.add(B.FLOAT, "double", size_or_type=8)
        b.add(B.DECL_TAG, "tag", size_or_type=i32, extra=[("i", -1)])
        b.mod(B.TYPE_TAG, i32, "user")
        b.mod(B.VOLATILE, i32)
        b.mod(B.RESTRICT, i32)
        last = b.struct("after_everything", 4, [("x", i32, 0)])
        t = B.BTF(b.to_bytes())
        self.assertEqual(t.find("after_everything", B.STRUCT).id, last)
        self.assertEqual(t.find("color", B.ENUM).vlen, 2)
        self.assertEqual(t.find(".data", B.DATASEC).size, 8)
        self.assertEqual(t.find("double", B.FLOAT).size, 8)

    def test_big_endian(self):
        little = B.BTF(shirudo_like().to_bytes("<"))
        big = B.BTF(shirudo_like().to_bytes(">"))
        self.assertEqual(big.byteorder, "big")
        self.assertEqual(len(big), len(little))
        sha = big.member(big.find("bpf_map", B.STRUCT), "sha")
        self.assertEqual(big.unwrap(sha.type).array_nelems, 32)

    def test_unwrap_stops_at_loops_and_bad_ids(self):
        b = BTFBuilder()
        # Two typedefs that point at each other: unwrap gives up after MAX_UNWRAP steps.
        b.typedef("a", 2)
        b.typedef("b", 1)
        b.typedef("dangling", 999)
        t = B.BTF(b.to_bytes())
        self.assertIsNone(t.unwrap(1))
        self.assertIsNone(t.unwrap(3))

    def test_first_of_duplicate_names_wins(self):
        b = BTFBuilder()
        first = b.struct("dup", 4, [])
        b.struct("dup", 8, [])
        self.assertEqual(B.BTF(b.to_bytes()).find("dup", B.STRUCT).id, first)


class MalformedTest(unittest.TestCase):
    def good(self):
        return bytearray(shirudo_like().to_bytes())

    def assertBad(self, data, msg):
        with self.assertRaises(B.BTFError) as cm:
            B.BTF(bytes(data))
        self.assertIn(msg, str(cm.exception))

    def test_short_and_wrong_magic(self):
        self.assertBad(b"\x9f\xeb", "too short")
        data = self.good()
        data[0:2] = b"\x00\x00"
        self.assertBad(data, "not BTF")

    def test_version_and_header_length(self):
        data = self.good()
        data[2] = 2
        self.assertBad(data, "unsupported BTF version 2")
        data = self.good()
        struct.pack_into("<I", data, 4, 8)
        self.assertBad(data, "bad header length")

    def test_sections_past_the_end(self):
        data = self.good()
        struct.pack_into("<I", data, 20, 10**6)  # str_len
        self.assertBad(data, "past the end")

    def test_truncated_and_misaligned_types(self):
        b = BTFBuilder()
        b.int("int", 4, signed=True)
        data = bytearray(b.to_bytes())
        type_len = struct.unpack_from("<I", data, 12)[0]
        struct.pack_into("<I", data, 12, type_len - 2)  # cut the int's encoding word short
        struct.pack_into("<I", data, 16, type_len - 2)  # strings now start earlier; keep str_off consistent
        self.assertBad(data, "truncated")

    def test_unknown_kind(self):
        b = BTFBuilder()
        b.add(25, "future")
        self.assertBad(b.to_bytes(), "unknown kind 25")

    def test_bad_names(self):
        b = BTFBuilder()
        b.types.append((500, B.STRUCT << 24, 0, []))
        self.assertBad(b.to_bytes(), "outside the string section")
        b = BTFBuilder()
        b.strings = bytearray(b"\0abc")  # no terminating NUL
        b.types.append((1, B.STRUCT << 24, 0, []))
        self.assertBad(b.to_bytes(), "unterminated")
        b = BTFBuilder()
        b.strings = bytearray(b"x\0")
        self.assertBad(b.to_bytes(), "must start with an empty string")

    def test_empty_blob_is_valid(self):
        b = BTFBuilder()
        b.strings = bytearray()
        self.assertEqual(len(B.BTF(b.to_bytes())), 0)


if __name__ == "__main__":
    unittest.main()
