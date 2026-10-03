"""capa-inspired capability tagger: small declarative rules over static artifacts.

Rules match on imported API names (case-insensitive, A/W suffix-agnostic) and, when the
actual strings are available, on string substrings. When only EMBER-style string *statistics*
are available (no raw strings), string rules fall back to the ``urls``/``registry``/``paths``
counters. Each rule maps to a MITRE ATT&CK technique and carries the evidence that fired it.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Capability, PEReport

_SUFFIX = re.compile(r"[AW]$")


def norm_api(name: str) -> str:
    """Canonical API name: case-folded, ANSI/Unicode ``A``/``W`` suffix dropped, Zw* folded to Nt*."""
    n = _SUFFIX.sub("", name)
    if n.startswith("Zw"):
        n = "Nt" + n[2:]
    return n.lower()


@dataclass(frozen=True)
class Rule:
    name: str
    attack_id: str
    all_imports: frozenset[str] = frozenset()
    any_imports: frozenset[str] = frozenset()
    any_string_substr: tuple[str, ...] = ()
    string_stat: str = ""  # EMBER strings counter used when raw strings are unavailable
    high_risk: bool = False

    def __post_init__(self):
        object.__setattr__(self, "all_imports", frozenset(norm_api(i) for i in self.all_imports))
        object.__setattr__(self, "any_imports", frozenset(norm_api(i) for i in self.any_imports))


def _r(name, attack, all_=(), any_=(), strs=(), stat="", high=False) -> Rule:
    return Rule(name, attack, frozenset(all_), frozenset(any_), tuple(strs), stat, high)


RULES: list[Rule] = [
    _r("process injection (remote thread)", "T1055.002", ["WriteProcessMemory", "CreateRemoteThread"],
       ["VirtualAllocEx", "NtAllocateVirtualMemory"], high=True),
    _r("process hollowing", "T1055.012", ["WriteProcessMemory", "SetThreadContext"],
       ["NtUnmapViewOfSection", "ResumeThread"], high=True),
    _r("APC injection", "T1055.004", ["QueueUserAPC", "WriteProcessMemory"], high=True),
    _r("download file from internet", "T1105", any_=["URLDownloadToFile", "InternetOpenUrl"], high=True),
    _r("keylogging via hook/polling", "T1056.001",
       any_=["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices"], high=True),
    _r("dynamic API resolution", "T1027.007", ["GetProcAddress"], ["LoadLibrary", "LoadLibraryEx", "LdrLoadDll"]),
    _r("create process", "T1106",
       any_=["CreateProcess", "WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcessAsUser"]),
    _r("modify memory protection", "T1055", any_=["VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"]),
    _r("anti-debugging checks", "T1622",
       any_=["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
             "OutputDebugString"]),
    _r("token privilege adjustment", "T1134", ["AdjustTokenPrivileges"],
       ["OpenProcessToken", "LookupPrivilegeValue", "OpenThreadToken"]),
    _r("service creation / persistence", "T1543.003", ["CreateService"], ["OpenSCManager"]),
    _r("registry modification", "T1112", any_=["RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx"]),
    _r("process enumeration", "T1057", ["CreateToolhelp32Snapshot"], ["Process32First", "Process32Next"]),
    _r("screen capture", "T1113", ["BitBlt", "GetDC"], ["CreateCompatibleBitmap", "GetDIBits"]),
    _r("clipboard data access", "T1115", any_=["GetClipboardData"]),
    _r("Windows crypto API usage", "T1486",
       any_=["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "CryptImportKey"]),
    _r("raw socket networking", "T1095", ["WSAStartup"], ["connect", "send", "recv", "socket"]),
    _r("HTTP client", "T1071.001", any_=["WinHttpOpen", "InternetOpen", "HttpSendRequest",
                                         "WinHttpSendRequest"]),
    _r("system shutdown/reboot", "T1529", any_=["ExitWindowsEx", "InitiateSystemShutdown"]),
    _r("embedded URL", "T1071.001", strs=("http://", "https://"), stat="urls"),
    _r("run-key persistence string", "T1547.001", strs=("CurrentVersion\\Run",), stat=""),
    _r("registry path strings", "T1012", strs=("HKEY_",), stat="registry"),
]
HIGH_RISK_ATTACK_IDS = {r.attack_id for r in RULES if r.high_risk}


# XML namespace / schema URLs in manifests are not network indicators (e.g. every signed Windows binary)
_NAMESPACE_URLS = ("xmlns", "schemas.microsoft.com", "www.w3.org/", "schemas.xmlsoap.org")
# Certificate-infrastructure URLs (CRL, OCSP, AIA certificates, CPS) from Authenticode signatures
_PKI_URL = re.compile(r"(?i)https?://(?:crl\d*|ocsp|cacerts?)\.|/pki(?:ops)?/|\.(?:crl|crt)(?:[^a-z0-9]|$)")


def _not_network_url(s: str) -> bool:
    return any(n in s for n in _NAMESPACE_URLS) or bool(_PKI_URL.search(s))


def tag_imports(import_names: Iterable[str], strings: list[str] | None = None,
                string_stats: dict | None = None, rules: list[Rule] = RULES,
                ignore_strings: Iterable[str] = ()) -> list[Capability]:
    """Tag capabilities from imported API names plus either raw strings or EMBER string stats.

    ``ignore_strings`` (e.g. strings from the certificate table) never count as URL evidence; neither do
    XML-namespace and certificate-infrastructure (CRL/OCSP/AIA) URLs.
    """
    ignore = set(ignore_strings)
    raw_names = sorted(set(import_names))
    by_norm: dict[str, str] = {}
    for n in raw_names:
        by_norm.setdefault(norm_api(n), n)
    imps = set(by_norm)
    out = []
    for r in rules:
        ev: list[str] = []
        if r.all_imports:
            if not r.all_imports <= imps:
                continue
            ev += [f"import {by_norm[i]}" for i in sorted(r.all_imports)]
        if r.any_imports:
            hit = sorted(r.any_imports & imps)
            if not hit:
                continue
            ev += [f"import {by_norm[i]}" for i in hit if f"import {by_norm[i]}" not in ev]
        if r.any_string_substr:
            if strings is not None:
                hit_s = [s for s in strings if any(x in s for x in r.any_string_substr)
                         and not (r.attack_id == "T1071.001" and (s in ignore or _not_network_url(s)))]
                if not hit_s:
                    continue
                ev += [f"string {s!r}" for s in hit_s[:3]]
            elif string_stats is not None and r.string_stat and string_stats.get(r.string_stat, 0) > 0:
                ev.append(f"{string_stats[r.string_stat]} '{r.string_stat}' string pattern(s)")
            else:
                continue
        out.append(Capability(r.name, r.attack_id, ev))
    return out


def tag(rep: PEReport, rules: list[Rule] = RULES) -> list[Capability]:
    names = set(rep.import_names) | {f for fs in rep.delay_imports.values() for f in fs}
    return tag_imports(names, strings=rep.strings, rules=rules, ignore_strings=rep.signature_strings)


def tag_raw(raw: dict, rules: list[Rule] = RULES) -> list[Capability]:
    """Tag an EMBER raw-feature dict (no raw strings: string rules use the counters)."""
    names = {f for fs in raw.get("imports", {}).values() for f in fs}
    return tag_imports(names, strings=None, string_stats=raw.get("strings", {}), rules=rules)
