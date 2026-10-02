"""Pure-stdlib static PE dissector. Reads bytes only; never loads, maps or executes anything.

Supports PE32 and PE32+ (x64): headers, sections, imports (incl. ordinals and delay-load),
exports, resource types, data directories, overlay, strings, entropy and imphash. Every read
is bounds-checked; malformed input raises :class:`PEParseError` instead of crashing.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter

from .models import PEReport, Section

MAX_SIZE = 128 * 1024 * 1024
_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
PACKER_SECTION_NAMES = {"upx0", "upx1", "upx2", ".aspack", ".adata", "mpress1", "mpress2",
                        ".petite", ".nsp0", ".nsp1", ".themida", ".vmp0", ".vmp1", ".enigma1",
                        ".packed", "pec2", ".mpress1", ".mpress2"}
MAX_IMPORT_DLLS = 512
MAX_FUNCS_PER_DLL = 8192
MAX_TOTAL_IMPORTS = 20_000  # per file, import + delay-import entries combined
MAX_EXPORTS = 16384

DATA_DIRECTORY_NAMES = [
    "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE",
    "LOAD_CONFIG_TABLE", "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
]

RESOURCE_TYPE_NAMES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
    8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
    21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}


class PEParseError(ValueError):
    pass


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def extract_strings(data: bytes, limit: int = 2000) -> list[str]:
    out = []
    for m in _STR_RE.finditer(data):
        out.append(m.group().decode("ascii"))
        if len(out) >= limit:
            break
    return out


def _u(fmt: str, data: bytes, off: int):
    if off < 0:
        raise PEParseError("negative offset")
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error as e:
        raise PEParseError(f"truncated at 0x{off:x}") from e


def _cstr(data: bytes, off: int, maxlen: int = 4096) -> str:
    # 4096 bounds the scan but still fits long MSVC-mangled C++ export names (seen >256 chars in System32)
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
    machine, nsec, ts, _symptr, nsyms, opt_size, chars = _u("<HHIIIHH", data, lfanew + 4)
    opt = lfanew + 24
    (magic,) = _u("<H", data, opt)
    if magic == 0x10B:
        plus = False
        image_base = _u("<I", data, opt + 28)[0]
        heap_commit = _u("<I", data, opt + 84)[0]
        n_rva_off, dd_off = opt + 92, opt + 96
    elif magic == 0x20B:
        plus = True
        image_base = _u("<Q", data, opt + 24)[0]
        heap_commit = _u("<Q", data, opt + 96)[0]
        n_rva_off, dd_off = opt + 108, opt + 112
    else:
        raise PEParseError(f"unknown optional header magic 0x{magic:x}")
    (maj_link, min_link, size_code) = _u("<BBI", data, opt + 2)
    entry = _u("<I", data, opt + 16)[0]
    (maj_os, min_os, maj_img, min_img, maj_sub, min_sub) = _u("<6H", data, opt + 40)
    size_image, size_headers, checksum, subsystem, dll_chars = _u("<IIIHH", data, opt + 56)
    (n_rva,) = _u("<I", data, n_rva_off)
    n_dirs = min(n_rva, 16)
    dirs: list[tuple[int, int]] = []
    for i in range(16):
        if i < n_dirs and dd_off + 8 * i + 8 <= opt + opt_size:
            dirs.append(_u("<II", data, dd_off + 8 * i))
        else:
            dirs.append((0, 0))

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
                off = s.raw_offset + rva - s.virtual_address
                return off if off < len(data) else -1
        # RVAs inside the headers map 1:1
        return rva if 0 <= rva < min(size_headers or 0x400, len(data)) else -1

    entry_section = ""
    for s in sections:
        if s.virtual_address <= entry < s.virtual_address + max(s.virtual_size, s.raw_size, 1):
            entry_section = s.name
            break
    if entry and not entry_section:
        anomalies.append("entry point outside any section")

    thunk_fmt, thunk_sz, ord_flag = ("<Q", 8, 1 << 63) if plus else ("<I", 4, 1 << 31)

    budget = [MAX_TOTAL_IMPORTS]  # shared across import and delay-import tables
    seen_tables: set[int] = set()

    def read_thunks(toff: int) -> list[str]:
        funcs: list[str] = []
        if toff < 0 or toff in seen_tables:
            return funcs
        seen_tables.add(toff)
        for j in range(MAX_FUNCS_PER_DLL):
            if budget[0] <= 0:
                anomalies.append("import budget exhausted")
                break
            budget[0] -= 1
            try:
                (th,) = _u(thunk_fmt, data, toff + thunk_sz * j)
            except PEParseError:
                anomalies.append("import thunk table truncated")
                break
            if th == 0:
                break
            if th & ord_flag:
                funcs.append(f"ordinal{th & 0xFFFF}")
            else:
                hoff = rva2off(th & 0x7FFFFFFF)
                funcs.append(_cstr(data, hoff + 2) if hoff >= 0 else "")
        return funcs

    imports: dict[str, list[str]] = {}
    imp_rva = dirs[1][0]
    doff = rva2off(imp_rva) if imp_rva else -1
    if doff >= 0:
        for i in range(MAX_IMPORT_DLLS):
            try:
                ilt, _, _, name_rva, iat = _u("<IIIII", data, doff + 20 * i)
            except PEParseError:
                anomalies.append("import directory truncated")
                break
            if not (ilt or name_rva or iat):
                break
            dll = _cstr(data, rva2off(name_rva))
            if not dll:
                continue
            imports.setdefault(dll, []).extend(read_thunks(rva2off(ilt or iat)))

    delay: dict[str, list[str]] = {}
    d_rva = dirs[13][0]
    doff = rva2off(d_rva) if d_rva else -1
    if doff >= 0:
        for i in range(MAX_IMPORT_DLLS):
            try:
                attrs, name_rva, _hmod, _iat, int_rva, *_ = _u("<8I", data, doff + 32 * i)
            except PEParseError:
                break
            if not (name_rva or int_rva):
                break
            # attrs bit0 = RVA based (modern); legacy VA-based descriptors are rare, rebase them
            fix = (lambda v: v) if attrs & 1 else (lambda v: (v - image_base) & 0xFFFFFFFF)
            dll = _cstr(data, rva2off(fix(name_rva)))
            if dll:
                delay.setdefault(dll, []).extend(read_thunks(rva2off(fix(int_rva))))

    exports: list[str] = []
    e_rva = dirs[0][0]
    eoff = rva2off(e_rva) if e_rva else -1
    if eoff >= 0:
        try:
            n_names, _addr_rva, names_rva = _u("<III", data, eoff + 24)
            noff = rva2off(names_rva)
            if noff >= 0:
                for i in range(min(n_names, MAX_EXPORTS)):
                    (nrva,) = _u("<I", data, noff + 4 * i)
                    nm = _cstr(data, rva2off(nrva))
                    if nm:
                        exports.append(nm)
        except PEParseError:
            anomalies.append("export directory truncated")

    resource_types: list[str] = []
    r_rva = dirs[2][0]
    roff = rva2off(r_rva) if r_rva else -1
    if roff >= 0:
        try:
            n_named, n_id = _u("<HH", data, roff + 12)
            for i in range(min(n_named + n_id, 256)):
                (nid, _) = _u("<II", data, roff + 16 + 8 * i)
                if nid & 0x80000000:
                    (ln,) = _u("<H", data, roff + (nid & 0x7FFFFFFF))
                    raw = data[roff + (nid & 0x7FFFFFFF) + 2 : roff + (nid & 0x7FFFFFFF) + 2 + 2 * min(ln, 64)]
                    resource_types.append(raw.decode("utf-16-le", "replace"))
                else:
                    resource_types.append(RESOURCE_TYPE_NAMES.get(nid, str(nid)))
        except PEParseError:
            anomalies.append("resource directory truncated")

    end_of_image = max([s.raw_offset + s.raw_size for s in sections if s.raw_size] + [size_headers])
    cert_off, cert_size = dirs[4]  # certificate table uses a FILE offset, not an RVA
    overlay = max(0, len(data) - end_of_image)
    if cert_size and cert_off >= end_of_image:
        overlay = max(0, overlay - cert_size)

    parts = []
    for dll, fs in imports.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        parts += [f"{base}.{f.lower()}" for f in fs]
    imphash = hashlib.md5(",".join(parts).encode()).hexdigest() if parts else ""

    header = {
        "major_linker_version": maj_link, "minor_linker_version": min_link,
        "major_operating_system_version": maj_os, "minor_operating_system_version": min_os,
        "major_image_version": maj_img, "minor_image_version": min_img,
        "major_subsystem_version": maj_sub, "minor_subsystem_version": min_sub,
        "sizeof_code": size_code, "sizeof_headers": size_headers, "sizeof_heap_commit": heap_commit,
        "checksum": checksum,
    }
    return PEReport(
        sha256=hashlib.sha256(data).hexdigest(), size=len(data), machine=machine, timestamp=ts,
        entry_point=entry, image_base=image_base, subsystem=subsystem, is_dll=bool(chars & 0x2000),
        sections=sections, imports=imports, strings=extract_strings(data),
        overall_entropy=round(entropy(data), 4), imphash=imphash, anomalies=anomalies,
        pe32plus=plus, coff_characteristics=chars, dll_characteristics=dll_chars, header=header,
        data_directories=dirs[:15], exports=exports, delay_imports=delay,
        resource_types=resource_types, entry_section=entry_section, size_of_image=size_image,
        overlay_size=overlay, n_symbols=nsyms,
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
    ep = next((s for s in rep.sections if s.name == rep.entry_section), None)
    if ep is not None and ep.writable and ep.executable:
        sig.append(f"entry point in writable+executable section {ep.name}")
    return sig


def is_packed(rep: PEReport) -> bool:
    return len(packing_signals(rep)) >= 2
