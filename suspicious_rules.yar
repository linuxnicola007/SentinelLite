/*
    SentinelLite YARA Rules
    Detects common malware indicators in files
*/

rule PowerShell_Abuse {
    meta:
        description = "Detects suspicious PowerShell command line patterns"
        severity = "medium"
    strings:
        $ps = "powershell" nocase
        $enc = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $win = "-windowstyle hidden" nocase
        $exec = "iex" nocase
        $download = "downloadstring" nocase
        $webclient = "webclient" nocase
    condition:
        $ps and ( $enc or $enc2 or $win or $exec or $download or $webclient )
}

rule Encoded_Commands {
    meta:
        description = "Detects base64 encoded command strings"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/  // Long base64-like patterns
        $cmd = "cmd.exe" nocase
        $b64_flag = "/c echo" nocase
    condition:
        ($b64 and $cmd) or ($b64_flag and $b64)
}

rule Process_Injection_APIs {
    meta:
        description = "Detects API calls commonly used for process injection"
        severity = "high"
    strings:
        $cr = "CreateRemoteThread" ascii wide
        $wp = "WriteProcessMemory" ascii wide
        $va = "VirtualAllocEx" ascii wide
        $nq = "NtCreateThreadEx" ascii wide
        $qp = "QueueUserAPC" ascii wide
        $sc = "SetThreadContext" ascii wide
    condition:
        any of ($cr, $wp, $va, $nq, $qp, $sc)
}

rule Suspicious_Windows_Commands {
    meta:
        description = "Detects dangerous Windows command-line utilities"
        severity = "medium"
    strings:
        $reg = "reg add" nocase
        $sc = "sc config" nocase
        $net = "net user" nocase
        $wmic = "wmic process" nocase
        $bcdedit = "bcdedit" nocase
        $vssadmin = "vssadmin delete shadows" nocase
        $powershell_dl = "powershell -w hidden -c" nocase
    condition:
        any of ($reg, $sc, $net, $wmic, $bcdedit, $vssadmin, $powershell_dl)
}