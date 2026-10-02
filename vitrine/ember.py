"""EMBER (v2 feature schema) compatibility layer.

Two directions:

* :func:`raw_features` turns PE *bytes* into an EMBER-2018-schema raw-feature dict using
  VITRINE's own stdlib dissector (no LIEF), so a model trained on the public EMBER JSONL
  can score a real file on disk.
* :func:`vectorize` / :func:`vectorize_many` turn raw-feature dicts (from EMBER JSONL or from
  :func:`raw_features`) into the 2381-dim EMBER v2 vector. This is a clean-room port of the
  feature hashing in ``elastic/ember`` ``features.py`` (feature version 2): same blocks, same
  order, same hash widths. Batch vectorization hashes whole blocks at once (no speed figure is claimed;
  none is benchmarked in this repo). One known deviation: elastic/ember hashed the entry-section
  name as a bare string, which old scikit-learn split into characters; VITRINE hashes the whole
  name as one token by default (50 of 2,381 dims differ). ``entry_hash="chars"`` reproduces the
  reference behaviour.

Requires numpy and scikit-learn (``pip install vitrine[ml]``).
"""
from __future__ import annotations

import re
from collections.abc import Iterable

import numpy as np

from .dissect import DATA_DIRECTORY_NAMES, dissect

VECTOR_DIM = 2381
BLOCKS = [  # (name, width) in EMBER v2 order
    ("histogram", 256), ("byteentropy", 256), ("strings", 104), ("general", 10),
    ("header", 62), ("section", 255), ("imports", 1280), ("exports", 128), ("datadirectories", 30),
]
assert sum(w for _, w in BLOCKS) == VECTOR_DIM


def block_slices() -> dict[str, slice]:
    out, i = {}, 0
    for name, w in BLOCKS:
        out[name] = slice(i, i + w)
        i += w
    return out


# ---------------------------------------------------------------- bytes -> raw dict
_MACHINE = {0x14C: "I386", 0x8664: "AMD64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64",
            0x1C4: "ARMNT", 0x0: "UNKNOWN"}
_SUBSYS = {0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
           9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
           12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
_COFF_CHARS = [(0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"), (0x0004, "LINE_NUMS_STRIPPED"),
               (0x0008, "LOCAL_SYMS_STRIPPED"), (0x0010, "AGGRESSIVE_WS_TRIM"),
               (0x0020, "LARGE_ADDRESS_AWARE"), (0x0080, "BYTES_REVERSED_LO"), (0x0100, "CHARA_32BIT_MACHINE"),
               (0x0200, "DEBUG_STRIPPED"), (0x0400, "REMOVABLE_RUN_FROM_SWAP"), (0x0800, "NET_RUN_FROM_SWAP"),
               (0x1000, "SYSTEM"), (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI")]
_DLL_CHARS = [(0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"),
              (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"), (0x0800, "NO_BIND"),
              (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"),
              (0x8000, "TERMINAL_SERVER_AWARE")]
_SEC_CHARS = [(0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"),
              (0x00000080, "CNT_UNINITIALIZED_DATA"), (0x00000200, "LNK_INFO"), (0x00000800, "LNK_REMOVE"),
              (0x00001000, "LNK_COMDAT"), (0x00008000, "GPREL"), (0x01000000, "LNK_NRELOC_OVFL"),
              (0x02000000, "MEM_DISCARDABLE"), (0x04000000, "MEM_NOT_CACHED"), (0x08000000, "MEM_NOT_PAGED"),
              (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"), (0x40000000, "MEM_READ"),
              (0x80000000, "MEM_WRITE")]

_ALLSTR = re.compile(rb"[\x20-\x7f]{5,}")
_PATHS = re.compile(rb"c:\\", re.IGNORECASE)
_URLS = re.compile(rb"https?://", re.IGNORECASE)
_REG = re.compile(rb"HKEY_")
_MZ = re.compile(rb"MZ")


def _flags(v: int, table) -> list[str]:
    return [n for bit, n in table if v & bit]


def byte_histogram(a: np.ndarray) -> list[int]:
    return np.bincount(a, minlength=256).tolist()


def byte_entropy_histogram(a: np.ndarray, window: int = 2048, step: int = 1024) -> list[int]:
    """EMBER ByteEntropyHistogram (Saxe & Berlin 2015): 16 entropy bins x 16 high-nibble bins."""
    out = np.zeros((16, 16), dtype=np.int64)
    if a.size == 0:
        return out.ravel().tolist()
    if a.size < window:
        blocks = (a >> 4)[None, :]
        denom = window
    else:
        n = (a.size - window) // step + 1
        blocks = np.lib.stride_tricks.as_strided(a >> 4, shape=(n, window), strides=(step, 1))
        denom = window
    counts = np.zeros((blocks.shape[0], 16), dtype=np.int64)
    # chunk to bound memory on large files
    for i in range(0, blocks.shape[0], 1024):
        b = blocks[i : i + 1024]
        counts[i : i + 1024] = (b[:, :, None] == np.arange(16, dtype=np.uint8)).sum(axis=1)
    p = counts / denom
    with np.errstate(divide="ignore", invalid="ignore"):
        h = -np.where(counts > 0, p * np.log2(np.where(p > 0, p, 1)), 0).sum(axis=1) * 2
    hbin = np.minimum((h * 2).astype(int), 15)
    np.add.at(out, hbin, counts)
    return out.ravel().tolist()


def string_features(data: bytes) -> dict:
    strs = _ALLSTR.findall(data)
    if strs:
        lens = [len(s) for s in strs]
        dist = np.bincount(np.frombuffer(b"".join(strs), dtype=np.uint8) - 0x20, minlength=96)[:96]
        printables = int(dist.sum())
        p = dist / max(printables, 1)
        ent = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
        av = sum(lens) / len(lens)
    else:
        dist, printables, ent, av = np.zeros(96, dtype=int), 0, 0.0, 0.0
    return {"numstrings": len(strs), "avlength": av, "printabledist": dist.tolist(),
            "printables": printables, "entropy": ent, "paths": len(_PATHS.findall(data)),
            "urls": len(_URLS.findall(data)), "registry": len(_REG.findall(data)),
            "MZ": len(_MZ.findall(data))}


def raw_features(data: bytes, rep=None) -> dict:
    """EMBER-v2-schema raw features computed from bytes by VITRINE's dissector (never executes)."""
    return raw_from_report(rep or dissect(data), data)


def raw_from_report(rep, data: bytes | None = None) -> dict:
    """Raw dict from a :class:`PEReport`; byte-level blocks need ``data`` (zeros otherwise)."""
    a = np.frombuffer(data, dtype=np.uint8) if data is not None else np.zeros(0, dtype=np.uint8)
    if data is None:  # approximate string stats from the report's strings
        data = b"\0".join(s.encode() for s in rep.strings)
    dd = rep.data_directories or [(0, 0)] * 15
    has = lambda i: int(bool(dd[i][0] and dd[i][1])) if i < len(dd) else 0  # noqa: E731
    return {
        "sha256": rep.sha256,
        "histogram": byte_histogram(a),
        "byteentropy": byte_entropy_histogram(a),
        "strings": string_features(data),
        "general": {"size": rep.size, "vsize": rep.size_of_image, "has_debug": has(6),
                    "exports": len(rep.exports), "imports": sum(len(v) for v in rep.imports.values()),
                    "has_relocations": has(5), "has_resources": has(2), "has_signature": has(4),
                    "has_tls": has(9), "symbols": rep.n_symbols},
        "header": {
            "coff": {"timestamp": rep.timestamp, "machine": _MACHINE.get(rep.machine, f"0x{rep.machine:x}"),
                     "characteristics": _flags(rep.coff_characteristics, _COFF_CHARS)},
            "optional": {"subsystem": _SUBSYS.get(rep.subsystem, str(rep.subsystem)),
                         "dll_characteristics": _flags(rep.dll_characteristics, _DLL_CHARS),
                         "magic": "PE32_PLUS" if rep.pe32plus else "PE32",
                         **{k: v for k, v in rep.header.items() if k != "checksum"}},
        },
        "section": {"entry": rep.entry_section,
                    "sections": [{"name": s.name, "size": s.raw_size, "entropy": s.entropy,
                                  "vsize": s.virtual_size, "props": _flags(s.characteristics, _SEC_CHARS)}
                                 for s in rep.sections]},
        "imports": rep.imports,
        "exports": rep.exports,
        "datadirectories": [{"name": n, "size": dd[i][1], "virtual_address": dd[i][0]}
                            for i, n in enumerate(DATA_DIRECTORY_NAMES) if i < len(dd)],
    }


# ---------------------------------------------------------------- raw dict -> vector
def _hasher(n: int, input_type: str):
    from sklearn.feature_extraction import FeatureHasher

    return FeatureHasher(n, input_type=input_type)


def _h(n: int, input_type: str, rows: list) -> np.ndarray:
    return _hasher(n, input_type).transform(rows).toarray().astype(np.float32)


def vectorize_many(raws: Iterable[dict], entry_hash: str = "token") -> np.ndarray:
    """Vectorize raw-feature dicts into an (n, 2381) float32 matrix (EMBER feature version 2).

    Args:
        raws: EMBER v2 raw-feature dicts.
        entry_hash: ``"token"`` hashes the entry-section name as one token (VITRINE default, used for
            all committed results); ``"chars"`` hashes it per character like elastic/ember did.

    Returns:
        float32 array of shape (n, 2381).
    """
    if entry_hash not in ("token", "chars"):
        raise ValueError("entry_hash must be 'token' or 'chars'")
    raws = list(raws)
    n = len(raws)
    X = np.zeros((n, VECTOR_DIM), dtype=np.float32)
    sl = block_slices()
    if n == 0:
        return X

    hist = np.asarray([r["histogram"] for r in raws], dtype=np.float32)
    X[:, sl["histogram"]] = hist / np.maximum(hist.sum(axis=1, keepdims=True), 1e-12)
    be = np.asarray([r["byteentropy"] for r in raws], dtype=np.float32)
    X[:, sl["byteentropy"]] = be / np.maximum(be.sum(axis=1, keepdims=True), 1e-12)

    st = np.zeros((n, 104), dtype=np.float32)
    for i, r in enumerate(raws):
        s = r["strings"]
        pr = s["printables"] if s["printables"] > 0 else 1.0
        st[i, 0:3] = (s["numstrings"], s["avlength"], s["printables"])
        st[i, 3:99] = np.asarray(s["printabledist"], dtype=np.float32) / pr
        st[i, 99:104] = (s["entropy"], s["paths"], s["urls"], s["registry"], s["MZ"])
    X[:, sl["strings"]] = st

    gkeys = ["size", "vsize", "has_debug", "exports", "imports", "has_relocations", "has_resources",
             "has_signature", "has_tls", "symbols"]
    X[:, sl["general"]] = np.asarray([[r["general"][k] for k in gkeys] for r in raws], dtype=np.float32)

    coff = [r["header"]["coff"] for r in raws]
    opt = [r["header"]["optional"] for r in raws]
    okeys = ["major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
             "major_operating_system_version", "minor_operating_system_version", "major_subsystem_version",
             "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit"]
    X[:, sl["header"]] = np.hstack([
        np.asarray([[c["timestamp"]] for c in coff], dtype=np.float32),
        _h(10, "string", [[c["machine"]] for c in coff]),
        _h(10, "string", [list(c["characteristics"]) for c in coff]),
        _h(10, "string", [[o["subsystem"]] for o in opt]),
        _h(10, "string", [list(o["dll_characteristics"]) for o in opt]),
        _h(10, "string", [[o["magic"]] for o in opt]),
        np.asarray([[o[k] for k in okeys] for o in opt], dtype=np.float32),
    ])

    secs = [r["section"]["sections"] for r in raws]
    gen = np.asarray([[len(ss), sum(1 for s in ss if s["size"] == 0), sum(1 for s in ss if s["name"] == ""),
                       sum(1 for s in ss if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
                       sum(1 for s in ss if "MEM_WRITE" in s["props"])] for ss in secs], dtype=np.float32)
    X[:, sl["section"]] = np.hstack([
        gen,
        _h(50, "pair", [[(s["name"], s["size"]) for s in ss] for ss in secs]),
        _h(50, "pair", [[(s["name"], s["entropy"]) for s in ss] for ss in secs]),
        _h(50, "pair", [[(s["name"], s["vsize"]) for s in ss] for ss in secs]),
        _h(50, "string", [[r["section"]["entry"]] if entry_hash == "token" else list(r["section"]["entry"])
                          for r in raws]),
        _h(50, "string", [[p for s in ss for p in s["props"] if s["name"] == r["section"]["entry"]]
                          for r, ss in zip(raws, secs)]),
    ])

    X[:, sl["imports"]] = np.hstack([
        _h(256, "string", [list({lib.lower() for lib in r["imports"]}) for r in raws]),
        _h(1024, "string", [[lib.lower() + ":" + e for lib, el in r["imports"].items() for e in el] for r in raws]),
    ])
    X[:, sl["exports"]] = _h(128, "string", [list(r["exports"]) for r in raws])

    dd = np.zeros((n, 30), dtype=np.float32)
    for i, r in enumerate(raws):
        for j, d in enumerate(r["datadirectories"][:15]):
            dd[i, 2 * j] = d["size"]
            dd[i, 2 * j + 1] = d["virtual_address"]
    X[:, sl["datadirectories"]] = dd
    return X


def vectorize(raw: dict) -> np.ndarray:
    return vectorize_many([raw])[0]
