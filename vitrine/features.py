"""EMBER-inspired + custom numeric features, each with an analyst-language template."""
from __future__ import annotations

from .capabilities import RULES, tag
from .dissect import is_packed
from .models import PEReport

SUSPICIOUS_APIS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "SetWindowsHookExA",
    "GetAsyncKeyState", "URLDownloadToFileA", "InternetOpenUrlA", "VirtualProtect", "GetProcAddress",
    "LoadLibraryA",
}
NETWORK_DLLS = {"wininet.dll", "urlmon.dll", "ws2_32.dll", "winhttp.dll"}
STANDARD_SECTIONS = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".pdata", ".bss", ".tls"}
GUI_APIS = {"CreateWindowExA", "CreateWindowExW", "GetMessageA", "MessageBoxA", "TextOutA", "BitBlt"}

# name -> analyst-language template ({v} = feature value)
FEATURES: dict[str, str] = {
    "max_section_entropy": "max section entropy {v:.2f} (compressed/encrypted data is > 7.2)",
    "mean_section_entropy": "mean section entropy {v:.2f}",
    "n_sections": "{v:.0f} sections",
    "n_imports": "{v:.0f} imported functions",
    "n_dlls": "{v:.0f} imported DLLs",
    "suspicious_api_count": "{v:.0f} injection/hooking/download-related APIs imported",
    "network_dll": "network DLL imported (wininet/urlmon/ws2_32): {v:.0f}",
    "wx_sections": "{v:.0f} writable+executable section(s)",
    "nonstandard_section_names": "{v:.0f} non-standard section name(s)",
    "packed": "packing heuristics fired: {v:.0f}",
    "n_strings": "{v:.0f} printable strings",
    "url_strings": "{v:.0f} embedded URL(s)",
    "capability_count": "{v:.0f} capability rule(s) matched",
    "gui_imports": "{v:.0f} GUI APIs (typical of desktop apps)",
    **{f"cap:{r.name}": f"capability '{r.name}' ({r.attack_id}) present: {{v:.0f}}" for r in RULES},
}
FEATURE_NAMES = list(FEATURES)


def featurize(rep: PEReport) -> dict[str, float]:
    ents = [s.entropy for s in rep.sections if s.raw_size] or [0.0]
    imps = rep.import_names
    caps = {c.name for c in tag(rep)}
    f = {
        "max_section_entropy": max(ents),
        "mean_section_entropy": sum(ents) / len(ents),
        "n_sections": len(rep.sections),
        "n_imports": len(imps),
        "n_dlls": len(rep.imports),
        "suspicious_api_count": len(imps & SUSPICIOUS_APIS),
        "network_dll": any(d.lower() in NETWORK_DLLS for d in rep.imports),
        "wx_sections": sum(1 for s in rep.sections if s.executable and s.writable),
        "nonstandard_section_names": sum(1 for s in rep.sections if s.name.lower() not in STANDARD_SECTIONS),
        "packed": is_packed(rep),
        "n_strings": len(rep.strings),
        "url_strings": sum(1 for s in rep.strings if "http://" in s or "https://" in s),
        "capability_count": len(caps),
        "gui_imports": len(imps & GUI_APIS),
    }
    for r in RULES:
        f[f"cap:{r.name}"] = r.name in caps
    return {k: float(f[k]) for k in FEATURE_NAMES}


def vector(rep: PEReport) -> list[float]:
    f = featurize(rep)
    return [f[k] for k in FEATURE_NAMES]


def describe(name: str, value: float) -> str:
    return FEATURES[name].format(v=value)
