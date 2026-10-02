"""Adapter: EMBER feature-version-3 raw records (EMBER2024, ``thrember``/pefile) -> the
feature-version-2 raw schema (EMBER 2017/2018, LIEF 0.9) that the rest of VITRINE consumes.

The two extractors see the same PE structures but name and encode them differently. Everything
that has a one-to-one mapping is translated; a few fields can only be approximated and are listed
in ``APPROXIMATIONS`` (they are reported next to every cross-dataset number):

* v2 ``general`` flags (has_debug, has_tls, has_signature, has_resources, has_relocations) are
  derived from the v3 data directories (non-zero DEBUG / TLS / SECURITY / RESOURCE / BASERELOC).
* v2 ``general.vsize`` (LIEF virtual size) -> ``optional.sizeof_image``.
* v2 string IOC counters (paths ``c:\\``, urls, registry ``HKEY_``, ``MZ``) -> the closest v3
  regex counters (``file_path`` ``C:/``, ``url``, ``registry_key``, ``dos_msg``).
* v3 lower-cases section names; LIEF kept the case. Section-name hashes therefore differ for
  names that are not already lower-case (``UPX0`` vs ``upx0``). Not recoverable without binaries.
* v3 ordinal imports are ``dll:ordinalN``; v2 used ``ordinalN`` -- translated.
"""
from __future__ import annotations

MACHINE = {"IMAGE_FILE_MACHINE_I386": "I386", "IMAGE_FILE_MACHINE_AMD64": "AMD64",
           "IMAGE_FILE_MACHINE_ARM": "ARM", "IMAGE_FILE_MACHINE_ARMNT": "ARMNT",
           "IMAGE_FILE_MACHINE_ARM64": "ARM64", "IMAGE_FILE_MACHINE_IA64": "IA64"}
MAGIC = {0x10B: "PE32", 0x20B: "PE32_PLUS"}
DD_NAMES = {  # pefile name -> LIEF 0.9 name
    "EXPORT": "EXPORT_TABLE", "IMPORT": "IMPORT_TABLE", "RESOURCE": "RESOURCE_TABLE",
    "EXCEPTION": "EXCEPTION_TABLE", "SECURITY": "CERTIFICATE_TABLE", "BASERELOC": "BASE_RELOCATION_TABLE",
    "DEBUG": "DEBUG", "COPYRIGHT": "ARCHITECTURE", "GLOBALPTR": "GLOBAL_PTR", "TLS": "TLS_TABLE",
    "LOAD_CONFIG": "LOAD_CONFIG_TABLE", "BOUND_IMPORT": "BOUND_IMPORT", "IAT": "IAT",
    "DELAY_IMPORT": "DELAY_IMPORT_DESCRIPTOR", "COM_DESCRIPTOR": "CLR_RUNTIME_HEADER", "RESERVED": "RESERVED",
}
APPROXIMATIONS = [
    "general flags derived from data-directory sizes",
    "general.vsize := optional.sizeof_image",
    "string IOC counters mapped to nearest v3 regex (paths<-file_path, registry<-registry_key, MZ<-dos_msg)",
    "section names lower-cased by v3 (case lost)",
    "extractor differs (pefile vs LIEF 0.9): parse edge cases differ on malformed files",
]


def _strip(prefix: str, s: str) -> str:
    return s[len(prefix):] if isinstance(s, str) and s.startswith(prefix) else s


def to_v2(r: dict) -> dict:
    """Translate one EMBER v3 raw record to the v2 raw schema (new dict; input untouched)."""
    hdr = r.get("header") or {}
    coff = dict(hdr.get("coff") or {})
    opt = dict(hdr.get("optional") or {})
    coff["machine"] = MACHINE.get(coff.get("machine", ""), _strip("IMAGE_FILE_MACHINE_", coff.get("machine", "")))
    coff.setdefault("characteristics", [])
    opt["subsystem"] = _strip("IMAGE_SUBSYSTEM_", opt.get("subsystem", ""))
    opt["magic"] = MAGIC.get(opt.get("magic"), str(opt.get("magic", "")))
    opt.setdefault("dll_characteristics", [])
    for k in ("major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
              "major_operating_system_version", "minor_operating_system_version", "major_subsystem_version",
              "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit"):
        opt.setdefault(k, 0)
    coff.setdefault("timestamp", 0)

    dds = [d for d in (r.get("datadirectories") or []) if "name" in d]
    dd2 = [{"name": DD_NAMES.get(d["name"], d["name"]), "size": d["size"],
            "virtual_address": d["virtual_address"]} for d in dds]
    dsz = {d["name"]: d["size"] for d in dds}
    imports = {}
    for lib, fns in (r.get("imports") or {}).items():
        imports[lib] = [f.split(":", 1)[1] if f.startswith(lib + ":ordinal") else f for f in fns]
    exports = list(r.get("exports") or [])
    g3 = r.get("general") or {}
    general = {
        "size": g3.get("size", 0), "vsize": opt.get("sizeof_image", 0),
        "has_debug": int(dsz.get("DEBUG", 0) > 0), "exports": len(exports),
        "imports": sum(len(v) for v in imports.values()),
        "has_relocations": int(dsz.get("BASERELOC", 0) > 0), "has_resources": int(dsz.get("RESOURCE", 0) > 0),
        "has_signature": int(dsz.get("SECURITY", 0) > 0), "has_tls": int(dsz.get("TLS", 0) > 0),
        "symbols": coff.get("number_of_symbols", 0),
    }
    s3 = r.get("strings") or {}
    sc = s3.get("string_counts") or {}
    strings = {"numstrings": s3.get("numstrings", 0), "avlength": s3.get("avlength", 0.0),
               "printabledist": s3.get("printabledist") or [0] * 96, "printables": s3.get("printables", 0),
               "entropy": s3.get("entropy", 0.0), "paths": sc.get("file_path", 0), "urls": sc.get("url", 0),
               "registry": sc.get("registry_key", 0), "MZ": sc.get("dos_msg", 0)}
    sec = r.get("section") or {}
    sections = [{"name": s["name"], "size": s["size"], "entropy": s["entropy"], "vsize": s["vsize"],
                 "props": s.get("props", [])} for s in sec.get("sections", [])]
    return {
        "sha256": r.get("sha256"), "label": r.get("label"), "avclass": r.get("family") or "",
        "appeared": r.get("week_id"),
        "histogram": r.get("histogram") or [0] * 256, "byteentropy": r.get("byteentropy") or [0] * 256,
        "strings": strings, "general": general, "header": {"coff": coff, "optional": opt},
        "section": {"entry": sec.get("entry", ""), "sections": sections},
        "imports": imports, "exports": exports, "datadirectories": dd2,
    }
