"""Synthetic, inert PE fixture generator.

Produces structurally valid PE32 files whose "code" sections are filler bytes.
They contain NO executable logic and are safe to store, share, and commit. Import
tables merely *name* APIs (as real malware would) so static features carry signal.
"""
from __future__ import annotations

import random
import struct

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
HEADERS_SIZE = 0x400
IMAGE_BASE = 0x400000

CODE = 0x60000020  # CODE | EXECUTE | READ
DATA = 0xC0000040  # INITIALIZED | READ | WRITE
RDATA = 0x40000040
RWX = 0xE0000060


def _align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def _build_idata(imports: dict[str, list[str]], rva: int, wide: bool = False) -> tuple[bytes, int]:
    """Return (section bytes, size of import descriptor table). ``wide`` = PE32+ 8-byte thunks."""
    ts = 8 if wide else 4
    fmt = "<Q" if wide else "<I"
    dlls = list(imports)
    desc_size = 20 * (len(dlls) + 1)
    off = desc_size
    thunk_offs = {}
    for d in dlls:
        n = len(imports[d]) + 1
        thunk_offs[d] = (off, off + ts * n)  # ILT, IAT
        off += 2 * ts * n
    hn_offs = {}
    for d in dlls:
        for f in imports[d]:
            hn_offs[(d, f)] = off
            off += _align(2 + len(f) + 1, 2)
    name_offs = {}
    for d in dlls:
        name_offs[d] = off
        off += len(d) + 1
    buf = bytearray(_align(off, 4))
    for i, d in enumerate(dlls):
        ilt, iat = thunk_offs[d]
        struct.pack_into("<IIIII", buf, 20 * i, rva + ilt, 0, 0, rva + name_offs[d], rva + iat)
        for j, f in enumerate(imports[d]):
            struct.pack_into(fmt, buf, ilt + ts * j, rva + hn_offs[(d, f)])
            struct.pack_into(fmt, buf, iat + ts * j, rva + hn_offs[(d, f)])
            enc = f.encode()
            buf[hn_offs[(d, f)] + 2 : hn_offs[(d, f)] + 2 + len(enc)] = enc
        buf[name_offs[d] : name_offs[d] + len(d)] = d.encode()
    return bytes(buf), desc_size


def _build_edata(dll_name: str, names: list[str], rva: int, func_rva: int) -> bytes:
    """Export directory with every name pointing at ``func_rva`` (inert)."""
    names = sorted(names)
    n = len(names)
    off = 40
    eat, npt, ot = off, off + 4 * n, off + 8 * n
    off = ot + 2 * n
    name_offs = []
    strtab = bytearray()
    dll_off = off
    strtab += dll_name.encode() + b"\0"
    for nm in names:
        name_offs.append(off + len(strtab))
        strtab += nm.encode() + b"\0"
    buf = bytearray(off) + strtab
    struct.pack_into("<IIHHIIIIIII", buf, 0, 0, 0, 0, 0, rva + dll_off, 1, n, n, rva + eat, rva + npt, rva + ot)
    for i in range(n):
        struct.pack_into("<I", buf, eat + 4 * i, func_rva)
        struct.pack_into("<I", buf, npt + 4 * i, rva + name_offs[i])
        struct.pack_into("<H", buf, ot + 2 * i, i)
    return bytes(buf)


def build_pe(
    sections: list[tuple[str, bytes, int]],
    imports: dict[str, list[str]] | None = None,
    timestamp: int = 0x5F000000,
    is_dll: bool = False,
    overlay: bytes = b"",
    pe32plus: bool = False,
    exports: list[str] | None = None,
) -> bytes:
    imports = imports or {}
    rva = SECT_ALIGN
    layout = []
    for name, data, ch in sections:
        layout.append((name, data, ch, rva))
        rva += _align(max(len(data), 1), SECT_ALIGN)
    dirs = [(0, 0)] * 16
    if imports:
        idata, dsize = _build_idata(imports, rva, wide=pe32plus)
        layout.append((".idata", idata, RDATA, rva))
        dirs[1] = (rva, dsize)
        rva += _align(len(idata), SECT_ALIGN)
    if exports:
        edata = _build_edata("synthetic.dll", exports, rva, layout[0][3] if layout else 0)
        layout.append((".edata", edata, RDATA, rva))
        dirs[0] = (rva, len(edata))
        rva += _align(len(edata), SECT_ALIGN)
    size_of_image = rva

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    msg = b"This program cannot be run in DOS mode."
    dos[0x40 : 0x40 + len(msg)] = msg

    characteristics = 0x0002 | (0x0020 if pe32plus else 0x0100) | (0x2000 if is_dll else 0)
    entry = layout[0][3] if layout else 0
    if pe32plus:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 0, 0, 0, 0, entry, SECT_ALIGN,
            0x140000000, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, HEADERS_SIZE, 0, 2, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        assert len(opt) == 112
        machine = 0x8664
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 0, 0, 0, 0, entry, SECT_ALIGN, SECT_ALIGN,
            IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, HEADERS_SIZE, 0, 2, 0x8140,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        assert len(opt) == 96
        machine = 0x14C
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    coff = struct.pack("<HHIIIHH", machine, len(layout), timestamp, 0, 0, len(opt), characteristics)

    raw = HEADERS_SIZE
    table = b""
    body = b""
    for name, data, ch, srva in layout:
        rsize = _align(len(data), FILE_ALIGN)
        table += struct.pack("<8sIIIIIIHHI", name.encode()[:8], len(data), srva, rsize,
                             raw if rsize else 0, 0, 0, 0, 0, ch)
        body += data.ljust(rsize, b"\0")
        raw += rsize
    hdr = bytes(dos) + b"PE\0\0" + coff + opt + table
    assert len(hdr) <= HEADERS_SIZE
    return hdr.ljust(HEADERS_SIZE, b"\0") + body + overlay


# ---------------------------------------------------------------- families
BENIGN_STRINGS = [
    "Copyright (C) Example Corp", "Settings saved successfully", "Open File",
    "Help and Support", "version 1.2.3", "Visual C++ Runtime Library", "config.ini",
    "Unable to open document", "Print Preview", "About this application",
]


def _code_filler(rng: random.Random, n: int) -> bytes:
    """Inert filler with compiled-code-like byte statistics (moderate entropy)."""
    alphabet = bytes([0x55, 0x8B, 0xEC, 0x83, 0xC4, 0x5D, 0xC3, 0x90, 0x00, 0xFF, 0x50, 0x6A, 0xE8, 0x89, 0x45])
    return bytes(rng.choice(alphabet) for _ in range(n))


def _strs(items: list[str]) -> bytes:
    return b"\0".join(s.encode() for s in items) + b"\0"


FAMILIES: dict[str, dict] = {
    "benign": {
        "imports": {"KERNEL32.dll": ["GetModuleHandleA", "ExitProcess", "CreateFileA", "ReadFile", "CloseHandle"],
                    "USER32.dll": ["MessageBoxA", "CreateWindowExA", "GetMessageA"]},
        "strings": BENIGN_STRINGS,
        "packed": False,
    },
    "injector": {
        "imports": {"KERNEL32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                                     "CreateRemoteThread", "GetProcAddress", "LoadLibraryA"]},
        "strings": ["VTRN_FAMILY_INJ_marker_7Q", "target=explorer.exe", "inj-cfg-v2", "Global\\inj_mtx_31"],
        "packed": False,
    },
    "downloader": {
        "imports": {"KERNEL32.dll": ["CreateProcessA", "GetTempPathA"],
                    "WININET.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
                    "URLMON.dll": ["URLDownloadToFileA"]},
        "strings": ["http://payload.example.invalid/stage2.bin", "VTRN_FAMILY_DL_marker_K2",
                    "Mozilla/4.0 (dlr)", "%TEMP%\\upd_svc.exe"],
        "packed": False,
    },
    "keylogger": {
        "imports": {"USER32.dll": ["SetWindowsHookExA", "GetAsyncKeyState", "GetForegroundWindow", "GetWindowTextA"],
                    "KERNEL32.dll": ["CreateFileA", "WriteFile"]},
        "strings": ["VTRN_FAMILY_KL_marker_P9", "keys_%04d.log", "[BACKSPACE]", "[ENTER]"],
        "packed": False,
    },
    "packed": {
        "imports": {"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"]},
        "strings": ["VTRN_FAMILY_PK_marker_Z0"],
        "packed": True,
    },
}
MALICIOUS_FAMILIES = [f for f in FAMILIES if f != "benign"]


def make_sample(family: str, seed: int = 0) -> bytes:
    rng = random.Random(f"{family}:{seed}")
    spec = FAMILIES[family]
    imports = {d: list(fs) for d, fs in spec["imports"].items()}
    strs = list(spec["strings"])
    if family == "benign":
        rng.shuffle(strs)
        strs = strs[: rng.randint(5, len(strs))] + [f"doc_{rng.randint(0, 99999)}.txt"]
        extra = rng.sample(["GetTickCount", "Sleep", "GetLastError", "HeapAlloc", "lstrlenA"], rng.randint(1, 4))
        imports["KERNEL32.dll"] += extra
    else:
        strs += [f"id_{rng.getrandbits(32):08x}"] + rng.sample(BENIGN_STRINGS, 2)
    ts = rng.randint(0x50000000, 0x66000000)
    if spec["packed"]:
        payload = rng.randbytes(rng.randint(6000, 12000))
        sections = [("UPX0", b"", RWX), ("UPX1", payload, RWX), (".rsrc", _strs(strs), RDATA)]
        return build_pe(sections, imports, timestamp=ts)
    code = _code_filler(rng, rng.randint(3000, 8000))
    sections = [(".text", code, CODE), (".rdata", _strs(strs), RDATA),
                (".data", bytes(rng.randint(256, 1024)), DATA)]
    return build_pe(sections, imports, timestamp=ts)


def append_benign_section(pe: bytes, seed: int = 0) -> bytes:
    """Adversarial perturbation (demo): add a big benign-looking section and pad GUI imports.

    Rebuilt from the parsed report so the result is still a valid PE.
    """
    from .dissect import dissect

    rep = dissect(pe)
    rng = random.Random(seed)
    secs = []
    for s in rep.sections:
        if s.name == ".idata":
            continue
        secs.append((s.name, pe[s.raw_offset : s.raw_offset + s.virtual_size] if s.raw_size else b"",
                     s.characteristics))
    secs.append((".rsrc", _strs(BENIGN_STRINGS * 20) + _code_filler(rng, 20000), RDATA))
    imports = {d: list(f) for d, f in rep.imports.items()}
    imports.setdefault("USER32.dll", []).extend(["MessageBoxA", "CreateWindowExA", "GetMessageA"])
    imports.setdefault("GDI32.dll", []).extend(["TextOutA", "BitBlt"])
    return build_pe(secs, imports, timestamp=rep.timestamp)


def corpus(n_per_family: int = 20, seed: int = 0) -> list[tuple[str, bytes]]:
    """Labeled synthetic corpus: 3x benign, n per malicious family."""
    out = []
    for fam in FAMILIES:
        n = n_per_family * (3 if fam == "benign" else 1)
        out += [(fam, make_sample(fam, seed * 100000 + i)) for i in range(n)]
    return out
