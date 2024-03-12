# Moriarty
Moriarty is a comprehensive .NET tool that extends the functionality of [Watson](https://github.com/rasta-mouse/Watson) and [Sherlock](https://github.com/rasta-mouse/sherlock), originally developed by [@_RastaMouse](https://twitter.com/_RastaMouse). It is designed to enumerate missing KBs, detect various vulnerabilities, and suggest potential exploits for Privilege Escalation in Windows environments. Moriarty combines the capabilities of Watson and Sherlock, adding enhanced scanning for newer vulnerabilities and integrating additional checks.

# Supported Versions
Windows 10 (Versions: 1507, 1511, 1607, 1703, 1709, 1803, 1809, 1903, 1909, 2004, 20H2, 21H1, 21H2, 22H1, 22H2)
Windows 11 (Versions: 21H2, 22H1, 22H2, 23H1)
Server 2016, 2019, 2022

# CVEs and Vulnerabilities
Moriarty scans for a variety of CVEs and vulnerabilities. Below is a table detailing each, along with a more detailed description and links to the CVE database.

| CVE/Vulnerability ID | Description | Link |
| -------------------- | ----------- | ---- |
| MS10-015 | Vulnerability in Windows Kernel related to privilege elevation, allowing attackers to execute arbitrary code. | [MS10-015](https://www.cve.org/CVERecord?id=MS10-015) |
| MS10-092 | Vulnerability in Windows Task Scheduler allowing for arbitrary code execution with escalated privileges. | [MS10-092](https://www.cve.org/CVERecord?id=MS10-092) |
| MS13-053 | Multiple vulnerabilities in Windows Kernel-Mode Drivers that could allow elevation of privilege. | [MS13-053](https://www.cve.org/CVERecord?id=MS13-053) |
| MS13-081 | Multiple vulnerabilities in Windows Kernel-Mode Drivers that could allow remote code execution. | [MS13-081](https://www.cve.org/CVERecord?id=MS13-081) |
| MS14-058 | Vulnerabilities in Kernel-Mode Driver that could allow remote code execution through specially crafted TrueType font files. | [MS14-058](https://www.cve.org/CVERecord?id=MS14-058) |
| MS15-051 | Vulnerability in Windows Kernel-Mode Drivers allowing for elevation of privilege by bypassing the security features of Windows. | [MS15-051](https://www.cve.org/CVERecord?id=MS15-051) |
| MS15-078 | Vulnerability in Windows Font Driver allowing remote code execution through maliciously crafted OpenType fonts. | [MS15-078](https://www.cve.org/CVERecord?id=MS15-078) |
| MS16-016 | Vulnerability in WebDAV that could allow elevation of privilege through improper handling of memory. | [MS16-016](https://www.cve.org/CVERecord?id=MS16-016) |
| MS16-032 | Vulnerability in Secondary Logon process that could allow elevation of privilege by running a specially crafted application. | [MS16-032](https://www.cve.org/CVERecord?id=MS16-032) |
| MS16-034 | Vulnerabilities in Windows Kernel-Mode Driver that could allow elevation of privilege due to the way kernel-mode drivers handle objects in memory. | [MS16-034](https://www.cve.org/CVERecord?id=MS16-034) |
| MS16-135 | Vulnerability in Windows Kernel-Mode Drivers that could allow elevation of privilege due to improper handling of certain types of objects in memory. | [MS16-135](https://www.cve.org/CVERecord?id=MS16-135) |
| CVE-2017-7199 | A privilege escalation vulnerability in Windows due to the way certain applications handle process tokens. | [CVE-2017-7199](https://www.cve.org/CVERecord?id=CVE-2017-7199) |
| CVE-2019-0836 | An elevation of privilege vulnerability in Windows due to the way the Win32k component handles objects in memory. | [CVE-2019-0836](https://www.cve.org/CVERecord?id=CVE-2019-0836) |
| CVE-2019-0841 | Elevation of privilege vulnerability in Windows AppX Deployment Server, allowing attackers to overwrite system files. | [CVE-2019-0841](https://www.cve.org/CVERecord?id=CVE-2019-0841) |
| CVE-2019-1064 | An elevation of privilege vulnerability in Windows due to improper handling of symbolic links. | [CVE-2019-1064](https://www.cve.org/CVERecord?id=CVE-2019-1064) |
| CVE-2019-1130 | An elevation of privilege vulnerability in Windows due to the way the Windows CSRSS handles certain requests. | [CVE-2019-1130](https://www.cve.org/CVERecord?id=CVE-2019-1130) |
| CVE-2019-1253 | Elevation of privilege vulnerability in Windows AppX Deployment Server due to improper permissions settings. | [CVE-2019-1253](https://www.cve.org/CVERecord?id=CVE-2019-1253) |
| CVE-2019-1315 | An elevation of privilege vulnerability in Windows Error Reporting (WER) due to improper handling of hard links. | [CVE-2019-1315](https://www.cve.org/CVERecord?id=CVE-2019-1315) |
| CVE-2019-1385 | Elevation of privilege vulnerability due to improper handling of objects in memory in Windows. | [CVE-2019-1385](https://www.cve.org/CVERecord?id=CVE-2019-1385) |
| CVE-2019-1388 | A vulnerability in Windows UAC that allows bypassing of the UAC dialog, leading to elevation of privilege. | [CVE-2019-1388](https://www.cve.org/CVERecord?id=CVE-2019-1388) |
| CVE-2019-1405 | An elevation of privilege vulnerability in Windows UPnP Service due to improper handling of objects in memory. | [CVE-2019-1405](https://www.cve.org/CVERecord?id=CVE-2019-1405) |
| CVE-2020-0668 | An elevation of privilege vulnerability due to improper handling of symbolic links in Windows. | [CVE-2020-0668](https://www.cve.org/CVERecord?id=CVE-2020-0668) |
| CVE-2020-0683 | Elevation of privilege vulnerability in Windows due to improper handling of file paths. | [CVE-2020-0683](https://www.cve.org/CVERecord?id=CVE-2020-0683) |
| CVE-2020-0796 | A remote code execution vulnerability in SMBv3 known as 'SMBGhost'. | [CVE-2020-0796](https://www.cve.org/CVERecord?id=CVE-2020-0796) |
| CVE-2020-1013 | A local privilege escalation vulnerability in Windows Update Orchestrator Service. | [CVE-2020-1013](https://www.cve.org/CVERecord?id=CVE-2020-1013) |
| CVE-2023-36664 | A command injection vulnerability in Ghostscript. | [CVE-2023-36664](https://www.cve.org/CVERecord?id=CVE-2023-36664) |
| CVE-2021-1675 | PrintNightmare, a remote code execution vulnerability in Windows Print Spooler. | [CVE-2021-1675](https://www.cve.org/CVERecord?id=CVE-2021-1675) |
| CVE-2021-26855 | ProxyLogon - A server-side request forgery (SSRF) vulnerability in Exchange Server allowing remote code execution. | [CVE-2021-26855](https://www.cve.org/CVERecord?id=CVE-2021-26855) |
| CVE-2021-26857 | A vulnerability in Exchange Server that could allow an attacker to perform remote code execution. | [CVE-2021-26857](https://www.cve.org/CVERecord?id=CVE-2021-26857) |
| CVE-2021-26858 | A post-authentication arbitrary file write vulnerability in Exchange Server. | [CVE-2021-26858](https://www.cve.org/CVERecord?id=CVE-2021-26858) |
| CVE-2021-27065 | A post-authentication arbitrary file write vulnerability in Exchange Server could lead to remote code execution. | [CVE-2021-27065](https://www.cve.org/CVERecord?id=CVE-2021-27065) |
| CVE-2021-44228 | Log4Shell, a remote code execution vulnerability in Apache Log4j. | [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228) |
| CVE-2021-36934 | HiveNightmare - A vulnerability that allows for local privilege escalation due to overly permissive Access Control Lists (ACLs) on system files, including the Security Accounts Manager (SAM). | [CVE-2021-36934](https://www.cve.org/CVERecord?id=CVE-2021-36934) |
| CVE-2022-40140 | A vulnerability in Microsoft Exchange Server leading to remote code execution. | [CVE-2022-40140](https://www.cve.org/CVERecord?id=CVE-2022-40140) |
| CVE-2022-22965 | Spring4Shell, a remote code execution vulnerability in Spring Framework. | [CVE-2022-22965](https://www.cve.org/CVERecord?id=CVE-2022-22965) |

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

 [*] OS Version: 22H2 (22621)
 [*] Enumerating installed KBs...
 [+] CVE-2023-36664 : VULNERABLE
  [>] https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

 [+] PrintNightmare (CVE-2021-1675, CVE-2021-34527) : VULNERABLE
  [>] https://github.com/xbufu/PrintNightmareCheck/tree/main

 [*] Vulnerabilities found: 2/30
 [+] Scan Complete!
```
