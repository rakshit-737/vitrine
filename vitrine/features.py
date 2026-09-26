"""Interpretable, analyst-language static features.

Every feature is computed from an EMBER-v2-schema raw-feature dict, so the *same* code path
featurizes (a) the public EMBER JSONL corpus used for training and (b) a real PE on disk that
VITRINE's dissector turned into a raw dict. Each feature carries a template that renders its
value as a sentence an analyst can check by hand -- this is what SHAP attributions are
translated into.
"""
from __future__ import annotations

import math

from .capabilities import RULES, norm_api, tag_raw
from .models import PEReport

STANDARD_SECTIONS = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".pdata", ".bss", ".tls",
                     ".edata", ".crt", ".didat", "code", "data", ".code", "bss", ".itext", ".gfids",
                     ".00cfg", ".sxdata", ".xdata"}
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", "mpress1", "mpress2", ".petite",
                   ".nsp0", ".nsp1", ".themida", ".vmp0", ".vmp1", ".enigma1", ".packed", "pec2"}

API_GROUPS: dict[str, set[str]] = {
    "injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
                  "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC", "NtWriteVirtualMemory",
                  "RtlCreateUserThread", "OpenProcess"},
    "anti_debug": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                   "OutputDebugString", "GetTickCount", "QueryPerformanceCounter", "NtSetInformationThread"},
    "keyboard_hook": {"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "GetKeyState",
                      "RegisterRawInputDevices", "MapVirtualKey"},
    "network": {"InternetOpen", "InternetOpenUrl", "InternetReadFile", "HttpSendRequest", "URLDownloadToFile",
                "WinHttpOpen", "WinHttpSendRequest", "WSAStartup", "connect", "send", "recv", "socket",
                "gethostbyname", "getaddrinfo", "InternetConnect", "HttpOpenRequest"},
    "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext", "CryptImportKey",
               "BCryptEncrypt", "BCryptDecrypt", "CryptCreateHash"},
    "registry": {"RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx", "RegDeleteKey",
                 "RegDeleteValue", "RegOpenKey", "RegOpenKeyEx"},
    "process": {"CreateProcess", "WinExec", "ShellExecute", "ShellExecuteEx", "TerminateProcess",
                "CreateToolhelp32Snapshot", "Process32First", "Process32Next"},
    "dynamic_resolution": {"LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll",
                           "LdrGetProcedureAddress"},
    "privilege": {"AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
                  "ImpersonateLoggedOnUser", "DuplicateTokenEx"},
    "service": {"CreateService", "OpenSCManager", "StartService", "ControlService", "DeleteService"},
    "memory": {"VirtualAlloc", "VirtualProtect", "VirtualProtectEx", "HeapCreate", "NtProtectVirtualMemory"},
    "gui": {"CreateWindowEx", "CreateWindow", "GetMessage", "DispatchMessage", "MessageBox", "DialogBoxParam",
            "ShowWindow", "BeginPaint", "LoadIcon", "RegisterClassEx", "DefWindowProc"},
}
_API_GROUPS_NORM = {g: {norm_api(a) for a in apis} for g, apis in API_GROUPS.items()}

# name -> analyst-language template ({v} = value)
FEATURES: dict[str, str] = {
    # file level
    "size_kb": "file size {v:.0f} KB",
    "file_entropy": "whole-file byte entropy {v:.2f} bits/byte (packed/encrypted data approaches 8)",
    "high_entropy_window_frac": "{v:.0%} of 2 KB windows are high-entropy (>= 7 bits/byte)",
    "unaccounted_ratio": "{v:.0%} of the file lies outside headers+sections (overlay/appended data)",
    "vsize_to_size": "virtual image is {v:.1f}x the on-disk size",
    "has_signature": "Authenticode certificate table present: {v:.0f}",
    "has_debug": "debug directory present: {v:.0f}",
    "has_tls": "TLS directory present (TLS callbacks run before the entry point): {v:.0f}",
    "has_relocations": "base relocations present: {v:.0f}",
    "has_resources": "resource directory present: {v:.0f}",
    "is_dotnet": ".NET CLR header present: {v:.0f}",
    "has_load_config": "load-config directory present (CFG/SafeSEH metadata): {v:.0f}",
    "cert_kb": "certificate table size {v:.1f} KB",
    # header
    "is_dll": "file is a DLL: {v:.0f}",
    "is_x64": "64-bit (PE32+) image: {v:.0f}",
    "subsystem_gui": "GUI subsystem: {v:.0f}",
    "subsystem_native": "native (driver-style) subsystem: {v:.0f}",
    "aslr": "ASLR (DYNAMIC_BASE) enabled: {v:.0f}",
    "dep": "DEP (NX_COMPAT) enabled: {v:.0f}",
    "cfg": "Control Flow Guard enabled: {v:.0f}",
    "n_mitigations": "{v:.0f} exploit mitigations flagged in the header",
    "relocs_stripped": "relocations stripped (fixed image base): {v:.0f}",
    "timestamp_suspicious": "compile timestamp is zero, pre-1995 or in the future: {v:.0f}",
    "linker_major": "linker major version {v:.0f}",
    "os_major": "minimum OS major version {v:.0f}",
    "code_ratio": "code is {v:.0%} of the file",
    # sections
    "n_sections": "{v:.0f} sections",
    "max_section_entropy": "max section entropy {v:.2f} (compressed/encrypted data is > 7.2)",
    "mean_section_entropy": "mean section entropy {v:.2f}",
    "min_section_entropy": "min section entropy {v:.2f}",
    "n_high_entropy_sections": "{v:.0f} section(s) with entropy > 7.2",
    "n_wx_sections": "{v:.0f} writable+executable section(s)",
    "n_exec_sections": "{v:.0f} executable section(s)",
    "n_nonstandard_sections": "{v:.0f} non-standard section name(s)",
    "n_empty_name_sections": "{v:.0f} section(s) with an empty name",
    "n_virtual_only_sections": "{v:.0f} section(s) with no raw data but virtual size (unpack target)",
    "packer_section_name": "known packer section name present (UPX/ASPack/MPRESS/Themida/VMProtect): {v:.0f}",
    "entry_nonstandard": "entry point lies in a non-standard section: {v:.0f}",
    "entry_writable": "entry point section is writable: {v:.0f}",
    "entry_missing": "entry point is not inside any section: {v:.0f}",
    "entry_entropy": "entry-point section entropy {v:.2f}",
    "max_vsize_ratio": "largest virtual/raw size ratio of a section {v:.1f}",
    # imports / exports
    "n_dlls": "{v:.0f} imported DLLs",
    "n_imports": "{v:.0f} imported functions",
    "n_ordinal_imports": "{v:.0f} imports by ordinal only (hides API names)",
    "n_exports": "{v:.0f} exported functions",
    "imports_tiny": "tiny import table (<= 5 functions) typical of packers/loaders: {v:.0f}",
    **{f"api_{g}": f"{{v:.0f}} {g.replace('_', ' ')} API(s) imported" for g in API_GROUPS},
    # strings
    "n_strings": "{v:.0f} printable strings",
    "avg_string_len": "average string length {v:.1f}",
    "string_entropy": "string character entropy {v:.2f}",
    "n_urls": "{v:.0f} embedded URL(s)",
    "n_paths": "{v:.0f} embedded 'C:\\' path(s)",
    "n_registry": "{v:.0f} embedded registry path(s) (HKEY_)",
    "n_embedded_mz": "{v:.0f} 'MZ' markers (embedded executables are a dropper tell)",
    "printable_ratio": "{v:.0%} of bytes are in printable strings",
    # capabilities
    "capability_count": "{v:.0f} capability rule(s) matched",
    "high_risk_capabilities": "{v:.0f} high-risk capability rule(s) matched (injection/download/keylogging)",
    **{f"cap:{r.name}": f"capability '{r.name}' ({r.attack_id}) present: {{v:.0f}}" for r in RULES},
}
FEATURE_NAMES = list(FEATURES)


def _entropy_from_hist(hist: list[int]) -> float:
    n = sum(hist)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in hist if c)


def featurize_raw(raw: dict) -> dict[str, float]:
    g = raw["general"]
    coff = raw["header"]["coff"]
    opt = raw["header"]["optional"]
    secs = raw["section"]["sections"]
    entry = raw["section"]["entry"]
    st = raw["strings"]
    dds = {d["name"]: d for d in raw.get("datadirectories", [])}
    size = max(g["size"], 1)

    ents = [s["entropy"] for s in secs if s["size"]] or [0.0]
    esec = next((s for s in secs if s["name"] == entry), None)
    names = [s["name"].lower() for s in secs]
    imps = raw.get("imports", {})
    all_imps = [f for fs in imps.values() for f in fs]
    norm = {norm_api(f) for f in all_imps}
    caps = tag_raw(raw)
    cap_names = {c.name for c in caps}
    dllc = set(opt.get("dll_characteristics", []))
    ts = coff.get("timestamp", 0)
    be = raw.get("byteentropy") or [0] * 256
    be_rows = [sum(be[i * 16 : (i + 1) * 16]) for i in range(16)]
    sec_bytes = sum(s["size"] for s in secs) + opt.get("sizeof_headers", 0)
    cert = dds.get("CERTIFICATE_TABLE", {"size": 0})

    f: dict[str, float] = {
        "size_kb": g["size"] / 1024,
        "file_entropy": _entropy_from_hist(raw.get("histogram") or []),
        "high_entropy_window_frac": sum(be_rows[14:]) / max(sum(be_rows), 1),
        "unaccounted_ratio": max(0, g["size"] - sec_bytes - cert["size"]) / size,
        "vsize_to_size": g["vsize"] / size,
        "has_signature": g["has_signature"],
        "has_debug": g["has_debug"],
        "has_tls": g["has_tls"],
        "has_relocations": g["has_relocations"],
        "has_resources": g["has_resources"],
        "is_dotnet": int(dds.get("CLR_RUNTIME_HEADER", {"size": 0})["size"] > 0),
        "has_load_config": int(dds.get("LOAD_CONFIG_TABLE", {"size": 0})["size"] > 0),
        "cert_kb": cert["size"] / 1024,
        "is_dll": int("DLL" in coff.get("characteristics", [])),
        "is_x64": int(opt.get("magic") == "PE32_PLUS"),
        "subsystem_gui": int(opt.get("subsystem") == "WINDOWS_GUI"),
        "subsystem_native": int(opt.get("subsystem") == "NATIVE"),
        "aslr": int("DYNAMIC_BASE" in dllc),
        "dep": int("NX_COMPAT" in dllc),
        "cfg": int("GUARD_CF" in dllc),
        "n_mitigations": len(dllc & {"DYNAMIC_BASE", "NX_COMPAT", "GUARD_CF", "HIGH_ENTROPY_VA", "FORCE_INTEGRITY"}),
        "relocs_stripped": int("RELOCS_STRIPPED" in coff.get("characteristics", [])),
        "timestamp_suspicious": int(ts == 0 or ts < 788918400 or ts > 1893456000),
        "linker_major": opt.get("major_linker_version", 0),
        "os_major": opt.get("major_operating_system_version", 0),
        "code_ratio": opt.get("sizeof_code", 0) / size,
        "n_sections": len(secs),
        "max_section_entropy": max(ents),
        "mean_section_entropy": sum(ents) / len(ents),
        "min_section_entropy": min(ents),
        "n_high_entropy_sections": sum(1 for s in secs if s["entropy"] > 7.2 and s["size"] > 1024),
        "n_wx_sections": sum(1 for s in secs if "MEM_WRITE" in s["props"] and "MEM_EXECUTE" in s["props"]),
        "n_exec_sections": sum(1 for s in secs if "MEM_EXECUTE" in s["props"]),
        "n_nonstandard_sections": sum(1 for n in names if n not in STANDARD_SECTIONS),
        "n_empty_name_sections": sum(1 for n in names if not n),
        "n_virtual_only_sections": sum(1 for s in secs if s["size"] == 0 and s["vsize"] > 0),
        "packer_section_name": int(bool(set(names) & PACKER_SECTIONS)),
        "entry_nonstandard": int(bool(esec) and entry.lower() not in STANDARD_SECTIONS),
        "entry_writable": int(bool(esec) and "MEM_WRITE" in esec["props"]),
        "entry_missing": int(esec is None),
        "entry_entropy": esec["entropy"] if esec else 0.0,
        "max_vsize_ratio": max([s["vsize"] / max(s["size"], 512) for s in secs] or [0.0]),
        "n_dlls": len(imps),
        "n_imports": len(all_imps),
        "n_ordinal_imports": sum(1 for f in all_imps if f.startswith("ordinal")),
        "n_exports": g["exports"],
        "imports_tiny": int(len(all_imps) <= 5),
        **{f"api_{grp}": len(norm & apis) for grp, apis in _API_GROUPS_NORM.items()},
        "n_strings": st["numstrings"],
        "avg_string_len": st["avlength"],
        "string_entropy": st["entropy"],
        "n_urls": st["urls"],
        "n_paths": st["paths"],
        "n_registry": st["registry"],
        "n_embedded_mz": st["MZ"],
        "printable_ratio": st["printables"] / size,
        "capability_count": len(caps),
        "high_risk_capabilities": sum(1 for r in RULES if r.high_risk and r.name in cap_names),
    }
    for r in RULES:
        f[f"cap:{r.name}"] = int(r.name in cap_names)
    return {k: float(f[k]) for k in FEATURE_NAMES}


def featurize_raw_many(raws) -> list[list[float]]:
    return [vector_raw(r) for r in raws]


def vector_raw(raw: dict) -> list[float]:
    f = featurize_raw(raw)
    return [f[k] for k in FEATURE_NAMES]


def featurize(rep: PEReport, data: bytes | None = None) -> dict[str, float]:
    """Featurize a dissected PE. ``data`` (the file bytes) enables byte histograms."""
    from .ember import raw_from_report

    return featurize_raw(raw_from_report(rep, data))


def vector(rep: PEReport, data: bytes | None = None) -> list[float]:
    f = featurize(rep, data)
    return [f[k] for k in FEATURE_NAMES]


def describe(name: str, value: float) -> str:
    return FEATURES[name].format(v=value)
