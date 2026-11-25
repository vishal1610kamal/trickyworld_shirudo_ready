"""Build small BTF blobs for the tests, byte for byte as Documentation/bpf/btf.rst lays them out."""

import struct

from shirudoready import abi
from shirudoready import btf as B


class BTFBuilder:
    def __init__(self):
        self.types = []  # (name_off, info, size_or_type, extra bytes) per type; ids start at 1
        self.strings = bytearray(b"\0")
        self._offsets = {"": 0}

    def s(self, name):
        if name not in self._offsets:
            self._offsets[name] = len(self.strings)
            self.strings += name.encode() + b"\0"
        return self._offsets[name]

    def add(self, kind, name="", vlen=0, kflag=False, size_or_type=0, extra=()):
        info = (int(kflag) << 31) | (kind << 24) | vlen
        self.types.append((self.s(name), info, size_or_type, list(extra)))
        return len(self.types)

    # Each extra item is (struct format without byte order, values...).
    def int(self, name, size, bits=None, signed=False, char=False, offset=0):
        enc = (B.INT_SIGNED if signed else 0) | (B.INT_CHAR if char else 0)
        bits = size * 8 if bits is None else bits
        return self.add(B.INT, name, size_or_type=size, extra=[("I", (enc << 24) | (offset << 16) | bits)])

    def ptr(self, t):
        return self.add(B.PTR, size_or_type=t)

    def typedef(self, name, t):
        return self.add(B.TYPEDEF, name, size_or_type=t)

    def mod(self, kind, t, name=""):
        return self.add(kind, name, size_or_type=t)

    def array(self, elem, index, nelems):
        return self.add(B.ARRAY, extra=[("III", elem, index, nelems)])

    def struct(self, name, size, members, kind=B.STRUCT):
        """members: (name, type, bit_offset[, bitfield_size])"""
        kflag = any(len(m) > 3 and m[3] for m in members)
        extra = []
        for m in members:
            bits = m[3] if len(m) > 3 else 0
            off = ((bits << 24) | m[2]) if kflag else m[2]
            extra.append(("III", self.s(m[0]), m[1], off))
        return self.add(kind, name, vlen=len(members), kflag=kflag, size_or_type=size, extra=extra)

    def func_proto(self, ret, params=()):
        return self.add(B.FUNC_PROTO, vlen=len(params), size_or_type=ret,
                        extra=[("II", self.s(n), t) for n, t in params])

    def func(self, name, proto):
        return self.add(B.FUNC, name, size_or_type=proto)

    def enum(self, name, values, size=4):
        return self.add(B.ENUM, name, vlen=len(values), size_or_type=size,
                        extra=[("Ii", self.s(n), v) for n, v in values])

    def enum64(self, name, values):
        return self.add(B.ENUM64, name, vlen=len(values), size_or_type=8,
                        extra=[("III", self.s(n), v & 0xFFFFFFFF, v >> 32) for n, v in values])

    def to_bytes(self, order="<"):
        body = bytearray()
        for name_off, info, size_or_type, extra in self.types:
            body += struct.pack(order + "III", name_off, info, size_or_type)
            for fmt, *vals in extra:
                body += struct.pack(order + fmt, *vals)
        header = struct.pack(order + "HBBIIIII", B.MAGIC, 1, 0, 24, 0, len(body), len(body), len(self.strings))
        return header + bytes(body) + bytes(self.strings)


def shirudo_like(sha_nelems=32, sha_signed=False, sha_bitfield=False, sha_as_ptr=False, excl=True,
                 excl_bitfield=False, excl_pointee="char", excl_as_int=False, prog_aux=True, sig=True,
                 sig_union=False, serial_signed=True, type_size=1, verdict=True, tpm_hook=True, hooks=None,
                 modules=True, module_sig=True, bpf_map=True, sha=True):
    """A BTF shaped like a kernel with shirudo's signed-loader ABI; each argument breaks one part of it."""
    b = BTFBuilder()
    uchar = b.int("unsigned char", 1)
    schar = b.int("signed char", 1, signed=True)
    char = b.int("char", 1, char=True)
    u16 = b.int("unsigned short", 2)
    sint = b.int("int", 4, signed=True)
    uint = b.int("unsigned int", 4)
    u8 = b.typedef("u8", b.typedef("__u8", uchar))
    s32 = b.typedef("s32", b.typedef("__s32", sint))
    u32 = b.typedef("u32", uint)
    void_ptr = b.ptr(0)
    elem = b.mod(B.CONST, schar if sha_signed else u8)
    sha_t = b.ptr(u8) if sha_as_ptr else b.array(elem, u32, sha_nelems)
    pointee = {"char": char, "u16": u16}[excl_pointee]
    excl_t = u32 if excl_as_int else b.ptr(pointee)
    members = [("ops", void_ptr, 0), ("inner_map_meta", void_ptr, 64), ("key_size", u32, 128)]
    if sha:
        members.append(("sha", sha_t, 160, 1 if sha_bitfield else 0))
    if excl:
        members.append(("excl_prog_sha", excl_t, 448, 1 if excl_bitfield else 0))
    if bpf_map:
        b.struct("bpf_map", 64, members)
    else:
        b.struct("bpf_map_old", 64, members)
    sig_members = [("keyring_serial", s32 if serial_signed else u32, 0),
                   ("keyring_type", u8 if type_size == 1 else u16, 32)]
    if verdict:
        sig_members.append(("verdict", u8, 40))
    sig_t = b.struct("", 8, sig_members, kind=B.UNION if sig_union else B.STRUCT)
    aux_members = [("refcnt", u32, 0), ("used_map_cnt", u32, 32)]
    if sig:
        aux_members.append(("sig", sig_t, 64))
    if prog_aux:
        b.struct("bpf_prog_aux", 32, aux_members)
    proto = b.func_proto(sint, [("ctx", void_ptr)])
    for h in (abi.LSM_HOOKS if hooks is None else hooks):
        if h == "tpm_command" and not tpm_hook:
            continue
        b.func("bpf_lsm_" + h, proto)
    if modules:
        b.func("__module_address", proto)
    if module_sig:
        b.func("mod_verify_sig", proto)
    return b
