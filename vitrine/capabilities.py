"""capa-style capability tagger: small declarative rules over static artifacts."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Capability, PEReport


@dataclass(frozen=True)
class Rule:
    name: str
    attack_id: str
    all_imports: frozenset[str] = frozenset()
    any_imports: frozenset[str] = frozenset()
    any_string_substr: tuple[str, ...] = ()


RULES = [
    Rule("process injection (remote thread)", "T1055.002",
         all_imports=frozenset({"WriteProcessMemory", "CreateRemoteThread"}),
         any_imports=frozenset({"VirtualAllocEx", "NtAllocateVirtualMemory"})),
    Rule("download file from internet", "T1105",
         any_imports=frozenset({"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW"})),
    Rule("keylogging via hook/polling", "T1056.001",
         any_imports=frozenset({"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"})),
    Rule("dynamic API resolution", "T1027.007", all_imports=frozenset({"LoadLibraryA", "GetProcAddress"})),
    Rule("create process", "T1106", any_imports=frozenset({"CreateProcessA", "CreateProcessW", "WinExec"})),
    Rule("modify memory protection", "T1055", any_imports=frozenset({"VirtualProtect", "VirtualProtectEx"})),
    Rule("embedded URL", "T1071.001", any_string_substr=("http://", "https://")),
]


def tag(rep: PEReport, rules: list[Rule] = RULES) -> list[Capability]:
    imps = rep.import_names
    out = []
    for r in rules:
        ev: list[str] = []
        if r.all_imports:
            if not r.all_imports <= imps:
                continue
            ev += [f"import {i}" for i in sorted(r.all_imports)]
        if r.any_imports:
            hit = sorted(r.any_imports & imps)
            if not hit:
                continue
            ev += [f"import {i}" for i in hit if f"import {i}" not in ev]
        if r.any_string_substr:
            hit = [s for s in rep.strings if any(x in s for x in r.any_string_substr)]
            if not hit:
                continue
            ev += [f"string {s!r}" for s in hit[:3]]
        out.append(Capability(r.name, r.attack_id, ev))
    return out
