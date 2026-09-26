import "pe"

rule vitrine_xtrat
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "xtrat"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 6 of (
            for any s in pe.sections : ( s.name == "nhgxrnnn" ),
            for any s in pe.sections : ( s.name == "zgwhklkc" ),
            pe.imphash() == "baa93d47220682c04d92f7797d9224ce",
            for any s in pe.sections : ( s.name == "        " ),
            for any s in pe.sections : ( s.name == "   " ),
            for any s in pe.sections : ( s.name == ".idata  " ),
            pe.imports("kernel32.dll", "lstrcpy")
        )
}

rule vitrine_installmonster
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "installmonster"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 2 of (
            pe.imports("winmm.dll", "sndPlaySoundW"),
            pe.imports("ntdll.dll", "NtUnmapViewOfSection")
        )
}

rule vitrine_zusy
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "zusy"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 3 of (
            pe.imphash() == "0a5325f51e3a6aca05e95af2c44e216f",
            pe.imports("shlwapi.dll", "UrlEscapeW"),
            pe.imports("shlwapi.dll", "UrlUnescapeW")
        )
}

rule vitrine_vtflooder
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "vtflooder"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 3 of (
            pe.imports("shlwapi.dll", "StrStrA"),
            for any s in pe.sections : ( s.name == "UPX2" ),
            pe.imports("ntdll.dll", "_wtoi"),
            pe.imphash() == "cd58d8c035263f0a89238148d230a79a",
            pe.imports("ntdll.dll", "memset"),
            pe.imphash() == "c8c94e9d3da30ce40dd6a40d9563b104"
        )
}

rule vitrine_fareit
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "fareit"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 3 of (
            pe.imphash() == "1348433f3361eb04dd3bc690f06b0856",
            pe.imports("comdlg32.dll", "PageSetupDlgA"),
            pe.imports("shfolder.dll", "SHGetFolderPathA")
        )
}

rule vitrine_ramnit
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "ramnit"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 1 of (
            for any s in pe.sections : ( s.name == ".rmnet" )
        )
}

rule vitrine_adposhel
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "adposhel"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 2 of (
            pe.imports("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptorA"),
            pe.imports("user32.dll", "InternalGetWindowText"),
            pe.imphash() == "5a92fdccff2ea908894680f0848f8d02"
        )
}

rule vitrine_sivis
{
    meta:
        author = "VITRINE structural synthesizer (analyst review required)"
        family = "sivis"
        sample_count = 400
        requires = "YARA >= 4.3 (boolean-expression sets)"
    condition:
        uint16(0) == 0x5A4D and 1 of (
            pe.imphash() == "a8f69eb2cf9f30ea96961c86b4347282",
            for any s in pe.sections : ( s.name == ".NewSec" )
        )
}
