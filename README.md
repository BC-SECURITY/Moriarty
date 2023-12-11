# Moriarty
Moriarty is a comprehensive .NET tool that extends the functionality of [Watson](https://github.com/rasta-mouse/Watson) and [Sherlock](https://github.com/rasta-mouse/sherlock), originally developed by @_RastaMouse. It is designed to enumerate missing KBs, detect various vulnerabilities, and suggest potential exploits for Privilege Escalation in Windows environments. Moriarty combines the capabilities of Watson and Sherlock, adding enhanced scanning for newer vulnerabilities and integrating additional checks.

# Supported Versions
Windows 10 (Versions: 1507, 1511, 1607, 1703, 1709, 1803, 1809, 1903, 1909, 2004, 20H2, 21H1, 21H2, 22H2)
Windows 11 (Versions: 21H2, 22H2)
Server 2016, 2019, 2022

# Usage
```
C:\> Moriarty.exe
███    ███  ██████  ██████  ██  █████  ██████  ████████ ██    ██
████  ████ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██     ██  ██
██ ████ ██ ██    ██ ██████  ██ ███████ ██████     ██      ████
██  ██  ██ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██       ██
██      ██  ██████  ██   ██ ██ ██   ██ ██   ██    ██       ██

                                                 v1.0
                                                 BC Security

 [*] OS Build Number: 22000
 [*] Enumerating installed KBs...

 [!] CVE-2019-0836 : VULNERABLE
  [>] https://exploit-db.com/exploits/46718
  [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-system/

 [!] CVE-2021-1675 : VULNERABLE
  [>] https://attacker.net/exploits/cve-2021-1675
  [>] https://exploit-db.com/exploits/50000

 [!] CVE-2023-36664 : VULNERABLE
  [>] https://securityadvisories.example.com/cve-2023-36664

 [*] Finished. Found 3 potential vulnerabilities.
```