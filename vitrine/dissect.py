"""Pure-stdlib static PE dissector. Reads bytes only; never loads or executes anything."""
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter

from .models import PEReport, Section

MAX_SIZE = 64 * 1024 * 1024
_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
PACKER_SECTION_NAMES = {"upx0", "upx1", "upx2", ".aspack", ".adata", "mpress1", "mpress2",
                        ".petite", ".nsp0", ".themida"}


class PEParseError(ValueError):
    pass


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def extract_strings(data: bytes, limit: int = 2000) -> list[str]:
    return [m.group().decode("ascii") for m in _STR_RE.finditer(data)][:limit]


def _u(fmt: str, data: bytes, off: int):
    if off < 0:
        raise PEParseError("negative offset")
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error as e:
        raise PEParseError(f"truncated at 0x{off:x}") from e


def _cstr(data: bytes, off: int, maxlen: int = 256) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, off + maxlen)
    return data[off : end if end != -1 else off + maxlen].decode("ascii", "replace")


def dissect(data: bytes) -> PEReport:
    if len(data) > MAX_SIZE:
        raise PEParseError("file too large")
    if data[:2] != b"MZ":
        raise PEParseError("missing MZ signature")
    (lfanew,) = _u("<I", data, 0x3C)
    if data[lfanew : lfanew + 4] != b"PE\0\0":
        raise PEParseError("missing PE signature")
    machine, nsec, ts, _, _, opt_size, chars = _u("<HHIIIHH", data, lfanew + 4)
    opt = lfanew + 24
    (magic,) = _u("<H", data, opt)
    if magic == 0x10B:
        image_base = _u("<I", data, opt + 28)[0]
        dd_off = opt + 96
    elif magic == 0x20B:
        image_base = _u("<Q", data, opt + 24)[0]
        dd_off = opt + 112
    else:
        raise PEParseError(f"unknown optional header magic 0x{magic:x}")
    entry = _u("<I", data, opt + 16)[0]
    subsystem = _u("<H", data, opt + 68)[0]
    imp_rva, _imp_size = _u("<II", data, dd_off + 8)

    if nsec > 96:
        raise PEParseError("too many sections")
    anomalies: list[str] = []
    sections: list[Section] = []
    st = opt + opt_size
    for i in range(nsec):
        name, vsize, va, rsize, roff, *_rest, ch = _u("<8sIIIIIIHHI", data, st + 40 * i)
        nm = name.rstrip(b"\0").decode("ascii", "replace")
        blob = data[roff : roff + rsize] if rsize else b""
        sections.append(Section(nm, va, vsize, rsize, roff, ch, round(entropy(blob), 4)))
        if ch & 0x20000000 and ch & 0x80000000:
            anomalies.append(f"section {nm} is writable+executable")
        if roff + rsize > len(data):
            anomalies.append(f"section {nm} raw data extends past end of file")

    def rva2off(rva: int) -> int:
        for s in sections:
            if s.raw_size and s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s.raw_offset + rva - s.virtual_address
        return -1

    if entry and not any(s.virtual_address <= entry < s.virtual_address + max(s.virtual_size, 1)
                         for s in sections):
        anomalies.append("entry point outside any section")

    imports: dict[str, list[str]] = {}
    doff = rva2off(imp_rva) if imp_rva else -1
    if doff >= 0:
        for i in range(256):
            ilt, _, _, name_rva, iat = _u("<IIIII", data, doff + 20 * i)
            if not (ilt or name_rva or iat):
                break
            dll = _cstr(data, rva2off(name_rva))
            funcs: list[str] = []
            toff = rva2off(ilt or iat)
            for j in range(4096 if toff >= 0 else 0):
                (th,) = _u("<I", data, toff + 4 * j)
                if th == 0:
                    break
                funcs.append(f"ord{th & 0xFFFF}" if th & 0x80000000 else _cstr(data, rva2off(th) + 2))
            imports[dll] = funcs

    parts = []
    for dll, fs in imports.items():
        base = dll.lower().rsplit(".", 1)[0]
        parts += [f"{base}.{f.lower()}" for f in fs]
    imphash = hashlib.md5(",".join(parts).encode()).hexdigest() if parts else ""

    return PEReport(
        sha256=hashlib.sha256(data).hexdigest(), size=len(data), machine=machine, timestamp=ts,
        entry_point=entry, image_base=image_base, subsystem=subsystem, is_dll=bool(chars & 0x2000),
        sections=sections, imports=imports, strings=extract_strings(data),
        overall_entropy=round(entropy(data), 4), imphash=imphash, anomalies=anomalies,
    )


def packing_signals(rep: PEReport) -> list[str]:
    sig = []
    names = {s.name.lower() for s in rep.sections}
    if names & PACKER_SECTION_NAMES:
        sig.append(f"packer section names: {sorted(names & PACKER_SECTION_NAMES)}")
    hi = [s.name for s in rep.sections if s.entropy > 7.2 and s.raw_size > 1024]
    if hi:
        sig.append(f"high-entropy sections: {hi}")
    if len(rep.import_names) <= 4 and {"LoadLibraryA", "GetProcAddress"} <= rep.import_names:
        sig.append("minimal import table with dynamic resolution (LoadLibraryA+GetProcAddress)")
    return sig


def is_packed(rep: PEReport) -> bool:
    return len(packing_signals(rep)) >= 2
