"""A small reader for raw BTF, the type format behind /sys/kernel/btf/vmlinux.

It reads what the checks need and skips the rest: every type's kind and name, struct and union members,
arrays, pointers, typedefs and integer encodings. It needs no libbpf and no privileges, because
/sys/kernel/btf/vmlinux is readable by every user. The format is described in Documentation/bpf/btf.rst
of the kernel tree.
"""

import struct

MAGIC = 0xEB9F

# Kinds, from include/uapi/linux/btf.h.
(UNKN, INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR,
 DATASEC, FLOAT, DECL_TAG, TYPE_TAG, ENUM64) = range(20)

KIND_NAMES = {
    UNKN: "void", INT: "int", PTR: "ptr", ARRAY: "array", STRUCT: "struct", UNION: "union", ENUM: "enum",
    FWD: "fwd", TYPEDEF: "typedef", VOLATILE: "volatile", CONST: "const", RESTRICT: "restrict", FUNC: "func",
    FUNC_PROTO: "func_proto", VAR: "var", DATASEC: "datasec", FLOAT: "float", DECL_TAG: "decl_tag",
    TYPE_TAG: "type_tag", ENUM64: "enum64",
}

# Integer encoding bits.
INT_SIGNED = 1 << 0
INT_CHAR = 1 << 1
INT_BOOL = 1 << 2

# What unwrap() looks through, as libbpf's btf_is_typedef() and btf_is_mod() do.
MODIFIERS = frozenset({TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG})
MAX_UNWRAP = 32

HEADER_LEN = 24
_SIZED = frozenset({INT, STRUCT, UNION, ENUM, DATASEC, FLOAT, ENUM64})
# Bytes of kind-specific data after the 12-byte common header: fixed, and per vlen item.
_FIXED = {INT: 4, ARRAY: 12, VAR: 4, DECL_TAG: 4}
_PER_ITEM = {STRUCT: 12, UNION: 12, ENUM: 8, FUNC_PROTO: 8, DATASEC: 12, ENUM64: 12}
_NO_DATA = frozenset({PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG})


class BTFError(ValueError):
    """The bytes are not BTF this reader understands."""


class Member:
    __slots__ = ("name", "type", "bit_offset", "bitfield_size")

    def __init__(self, name, type_id, bit_offset, bitfield_size):
        self.name = name
        self.type = type_id
        self.bit_offset = bit_offset
        self.bitfield_size = bitfield_size

    def __repr__(self):
        return f"Member({self.name!r}, type={self.type}, bit_offset={self.bit_offset}, bits={self.bitfield_size})"


class Type:
    __slots__ = ("id", "kind", "name", "vlen", "kflag", "size", "ref", "int_encoding", "int_offset", "int_bits",
                 "array_elem", "array_nelems", "_raw_members")

    def __init__(self, type_id, kind, name, vlen=0, kflag=False):
        self.id = type_id
        self.kind = kind
        self.name = name
        self.vlen = vlen
        self.kflag = kflag
        self.size = 0           # INT, STRUCT, UNION, ENUM, DATASEC, FLOAT, ENUM64
        self.ref = 0            # PTR, TYPEDEF, the modifiers, FUNC, VAR, DECL_TAG: the type referred to
        self.int_encoding = 0
        self.int_offset = 0
        self.int_bits = 0
        self.array_elem = 0
        self.array_nelems = 0
        self._raw_members = ()  # (name_off, type, offset) per member; names decoded on demand

    @property
    def kind_name(self):
        return KIND_NAMES.get(self.kind, str(self.kind))

    def __repr__(self):
        return f"Type(id={self.id}, {self.kind_name} {self.name!r})"


class BTF:
    """The types of one BTF blob. Type 0 is void, as in the kernel."""

    def __init__(self, data):
        data = bytes(data)
        if len(data) < HEADER_LEN:
            raise BTFError("too short for a BTF header")
        magic = struct.unpack_from("<H", data, 0)[0]
        if magic == MAGIC:
            e = "<"
        elif magic == 0x9FEB:
            e = ">"
        else:
            raise BTFError(f"not BTF: magic {magic:#06x}")
        version, _flags, hdr_len = struct.unpack_from(e + "BBI", data, 2)
        if version != 1:
            raise BTFError(f"unsupported BTF version {version}")
        if hdr_len < HEADER_LEN or hdr_len > len(data):
            raise BTFError(f"bad header length {hdr_len}")
        type_off, type_len, str_off, str_len = struct.unpack_from(e + "IIII", data, 8)
        t0, s0 = hdr_len + type_off, hdr_len + str_off
        t1, s1 = t0 + type_len, s0 + str_len
        if t1 > len(data) or s1 > len(data):
            raise BTFError("a section runs past the end of the file")
        self.byteorder = "little" if e == "<" else "big"
        self._strings = data[s0:s1]
        if self._strings and self._strings[0] != 0:
            raise BTFError("the string section must start with an empty string")
        self._names = {}
        self.types = [Type(0, UNKN, "")]
        self._index = {}
        self._parse(data, t0, t1, e)

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls(f.read())

    def __len__(self):
        return len(self.types) - 1

    def name_at(self, off):
        name = self._names.get(off)
        if name is not None:
            return name
        if off == 0 and not self._strings:
            return ""
        if off >= len(self._strings):
            raise BTFError(f"name offset {off} is outside the string section")
        end = self._strings.find(b"\0", off)
        if end < 0:
            raise BTFError(f"unterminated name at offset {off}")
        name = self._strings[off:end].decode("utf-8", "replace")
        self._names[off] = name
        return name

    def _parse(self, data, pos, end, e):
        common = struct.Struct(e + "III")
        word = struct.Struct(e + "I")
        type_id = 0
        while pos < end:
            if pos + 12 > end:
                raise BTFError(f"type {type_id + 1} is truncated")
            name_off, info, size_or_type = common.unpack_from(data, pos)
            pos += 12
            type_id += 1
            vlen = info & 0xFFFF
            kind = (info >> 24) & 0x1F
            kflag = bool(info >> 31)
            if kind in _FIXED:
                extra = _FIXED[kind]
            elif kind in _PER_ITEM:
                extra = _PER_ITEM[kind] * vlen
            elif kind in _NO_DATA:
                extra = 0
            else:
                raise BTFError(f"type {type_id} has unknown kind {kind}")
            if pos + extra > end:
                raise BTFError(f"type {type_id} ({KIND_NAMES[kind]}) is truncated")
            t = Type(type_id, kind, self.name_at(name_off), vlen, kflag)
            if kind in _SIZED:
                t.size = size_or_type
            else:
                t.ref = size_or_type
            if kind == INT:
                v = word.unpack_from(data, pos)[0]
                t.int_encoding = (v >> 24) & 0x0F
                t.int_offset = (v >> 16) & 0xFF
                t.int_bits = v & 0xFF
            elif kind == ARRAY:
                t.array_elem, _index_type, t.array_nelems = common.unpack_from(data, pos)
            elif kind in (STRUCT, UNION):
                t._raw_members = tuple(common.iter_unpack(data[pos:pos + extra]))
            pos += extra
            self.types.append(t)
            self._index.setdefault((t.name, kind), type_id)
        if pos != end:
            raise BTFError("the type section does not end on a type boundary")

    def type(self, type_id):
        """The type with this id, or None."""
        if 0 <= type_id < len(self.types):
            return self.types[type_id]
        return None

    def find(self, name, kind):
        """The first type of this name and kind, as libbpf's btf__find_by_name_kind() returns, or None."""
        type_id = self._index.get((name, kind))
        return self.types[type_id] if type_id else None

    def has_func(self, name):
        return self.find(name, FUNC) is not None

    def unwrap(self, type_id):
        """Follow typedefs and const/volatile/restrict/type_tag to the type underneath, or None."""
        for _ in range(MAX_UNWRAP):
            t = self.type(type_id)
            if t is None:
                return None
            if t.kind not in MODIFIERS:
                return t
            type_id = t.ref
        return None

    def members(self, t):
        """The members of a struct or union, in order."""
        out = []
        for name_off, type_id, offset in t._raw_members:
            if t.kflag:
                bits, bit_offset = offset >> 24, offset & 0xFFFFFF
            else:
                bits, bit_offset = 0, offset
            out.append(Member(self.name_at(name_off), type_id, bit_offset, bits))
        return out

    def member(self, t, name):
        """The first member of this name, or None."""
        for m in self.members(t):
            if m.name == name:
                return m
        return None
