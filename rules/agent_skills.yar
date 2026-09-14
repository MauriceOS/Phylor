rule Phylor_Detect_Reverse_Shell {
    meta:
        description = "Detects reverse shell attempts and remote payload execution in AI instructions"
        author = "Phylor Security"
        severity = "Critical"

    strings:
        $tcp_bash = "/dev/tcp/" nocase
        $nc_exec = "nc -e" nocase
        $nc_trad = "nc -c" nocase
        $python_pty = "pty.spawn" nocase
        $perl_socket = "IO::Socket::INET" nocase
        $curl_bash = /curl\s+(-\w+\s+)*https?:\/\/[^\s]+\s*\|\s*(bash|sh|zsh)/i
        $wget_bash = /wget\s+(-\w+\s+)*-O-\s+https?:\/\/[^\s]+\s*\|\s*(bash|sh|zsh)/i

    condition:
        any of them
}

rule Phylor_Detect_Credential_Exfiltration {
    meta:
        description = "Detects attempts to read and exfiltrate sensitive local developer files"
        author = "Phylor Security"
        severity = "Critical"

    strings:
        $tgt_aws = ".aws/credentials" nocase
        $tgt_ssh = ".ssh/id_rsa" nocase
        $tgt_env = ".env" nocase
        $tgt_npm = ".npmrc" nocase
        $tgt_gcp = "application_default_credentials.json" nocase
        $exfil_curl = /curl\s+.*-d\s+@[^\s]+/i
        $exfil_wget = /wget\s+--post-file/i
        $exfil_dns = /dig\s+\+short\s+[^\s]+\.[^\s]+/i

    condition:
        (any of ($tgt_*) and any of ($exfil_*)) or (3 of ($tgt_*))
}

rule Phylor_Detect_Obfuscated_Execution {
    meta:
        description = "Detects base64 encoded payloads piped directly to a shell"
        author = "Phylor Security"
        severity = "High"

    strings:
        $b64_pipe = /echo\s+['"][A-Za-z0-9+\/]+={0,2}['"]\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)/i
        $py_b64 = "base64.b64decode(" nocase
        $py_exec = "exec(" nocase
        $hidden_dir = "mkdir -p /tmp/." nocase

    condition:
        $b64_pipe or ($py_b64 and $py_exec) or $hidden_dir
}
