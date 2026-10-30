# INCIDENT REPORT: TryHackMe Boogeyman-3
- **Date of Analysis:** 15-10-2026
- **Source:** `tryhackme.com`
- **Analysis Basis:** endpoint logs (Sysmon and Windows Security events in Elastic)

---

## Summary

- The CEO (`evan.hutchinson`) opened an attachment, a double-extension file `ProjectFinancialSummary_Q3.pdf.hta`, on WKSTN-0051. It spawned `mshta.exe`, which copied `review.dat` from `D:\` to Temp (through `xcopy.exe`), loaded and executed it with `rundll32.exe`, and ran a command that creates a scheduled task (`Review`) to run `review.dat` through `rundll32.exe` for persistence (seen in the command line only). How `review.dat` reached the host is not visible in the logs.
  - The loaded process re-executed itself and ran basic discovery (`whoami`, `net users`, `net localgroup administrators`).
  - The attacker hijacked the `ms-settings` registry key and launched `fodhelper.exe` to bypass UAC and get high integrity without a prompt. `fodhelper.exe` then ran an encoded PowerShell stager that was stored in the registry.
  - The stager creates a WebClient with a fake user agent, connects to the C2 server `cdn.bananapeelparty[.]net`, then decrypts and executes the commands it receives.
  - Through the stager, PowerView was loaded in memory to map the domain, and mimikatz was downloaded and run to read credentials from memory (LSASS access is suspected, because Sysmon EID 10 was not available). A pass-the-hash (PTH) command was then run with the `itadmin` hash. It was executed, but its success is not confirmed.
  - The attacker then looked for shared resources and read `IT_Automation.ps1` from the `ITFiles` share on WKSTN-1327. About 30 seconds later the `allan.smith` plaintext password was used with `Invoke-Command`, so the script most likely contained it (suspected, from timing).

- With the `allan.smith` credentials, the attacker moved to WKSTN-1327 over WinRM (EID 4624 type 3, `wsmprovhost.exe`). The first `whoami` attempt most likely failed and the second worked. The stager then ran on WKSTN-1327.
  - After a long idle period, mimikatz was downloaded again and PTH was run with the `itadmin` hash. The attacker then read credentials from memory again (`sekurlsa::logonpasswords`), and right after that PTH was run for `Administrator`. The `Administrator` hash appears in the logs for the first time after this memory read. PTH for `Administrator` was run three more times later on this host.
  - In total five PTH logon events (type 9, `seclogo`) were recorded on this host, one for `itadmin` and four for `Administrator`. They show PTH was executed, but acceptance by a remote system is not confirmed.
  - The attacker then tried to reach DC01 with `Invoke-Command`. The first two attempts had a typo (`Invoke-Comand`) and most likely failed. A DCSync attempt from this host left no EID 4662 events and most likely failed.
  - A second `Invoke-Command` from WKSTN-0051 ran the stager on WKSTN-1327 again. A scheduled task `Updater` (SYSTEM) was created that runs a payload stored in the registry. It was seen in the command line only, so it is suspected persistence.

- Sessions as `Administrator` then appeared on DC01, where `wsmprovhost.exe` ran `hostname.exe` and the stager. The host these sessions came from could not be verified.
  - On DC01 mimikatz was downloaded and DCSync was run against `backupda` and `administrator`. Both succeeded (EID 4662 success events). The credentials returned are not visible in the logs, so both accounts are treated as compromised.
  - `ransomboogey.exe` was downloaded from `ff.sillytechninja[.]io` and run. It created 9 files with the `.boogey` extension in `C:\Users\Administrator\Downloads` and then terminated. Whether the contents were actually encrypted was not verified.

- From DC01 the attacker then used `Invoke-Command` to run commands on the workstations and to try to spread the ransomware.
  - On WKSTN-1327 `ransomboogey.exe` was started three times. Each run ended within a second and created no files.
  - On WKSTN-0051 the file was downloaded (DNS query and file creation seen) but no execution was observed. The stager was run there from DC01, and then made attempts against WKSTN-0051 itself and WKSTN-1327.
  - Several other `hostname` and download attempts left no process events on the target, so it is unknown whether they failed or were not logged.

---

## Key Findings

| # | Finding | Status |
|---|---|---|
| 1 | The malicious `.pdf.hta` attachment ran through `mshta.exe` on the CEO workstation and started the attack | Confirmed |
| 2 | UAC was bypassed with `fodhelper.exe` by hijacking `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Confirmed |
| 3 | Mimikatz was downloaded and run on WKSTN-0051, WKSTN-1327 and DC01. Access to LSASS is inferred (no EID 10) | Confirmed (run), Suspected (LSASS access) |
| 4 | The `allan.smith` plaintext password was used for WinRM lateral movement to WKSTN-1327. Its source (`IT_Automation.ps1`) is inferred from timing | Confirmed (use), Suspected (source) |
| 5 | DCSync on DC01 succeeded for `backupda` and `administrator` (EID 4662). The credentials returned are not visible | Confirmed (success), Not confirmed (what was returned) |
| 6 | `Administrator` sessions ran commands on DC01, but the host they came from was not identified | Not confirmed |
| 7 | Two scheduled tasks (`Review`, `Updater`) were created for persistence. Only the command lines were seen | Suspected |
| 8 | `ransomboogey.exe` created 9 `.boogey` files on DC01. Encryption was not verified. It had no visible effect on WKSTN-1327 and was only downloaded to WKSTN-0051 | Confirmed (file creation), Not confirmed (encryption) |

---

## Timeline (UTC)

PTH = pass-the-hash. A type 9 logon (`seclogo`) shows PTH was executed, not that a remote system accepted the hash.

| Time (2023) | Host | User | Event |
|---|---|---|---|
| 08-29 23:51 | WKSTN-0051 | evan.hutchinson | `ProjectFinancialSummary_Q3.pdf.hta` opened and run through `mshta.exe`. `review.dat` copied from `D:\` to Temp and loaded with `rundll32.exe`. Scheduled task `Review` (daily 06:00) created |
| 08-29 23:53 to 23:54 | WKSTN-0051 | evan.hutchinson | Discovery: `whoami /all`, `net users`, `net localgroup administrators`, `whoami /groups` |
| 08-29 23:54 | WKSTN-0051 | evan.hutchinson | UAC bypass: `ms-settings` registry key set, then `fodhelper.exe` launched. An encoded payload read from the registry runs as a PowerShell stager (`cdn.bananapeelparty[.]net`) |
| 08-29 23:55 to 08-30 00:09 | WKSTN-0051 | evan.hutchinson | Domain discovery with PowerView loaded in memory (computers, domain, users) |
| 08-30 00:09 to 00:11 | WKSTN-0051 | evan.hutchinson | Mimikatz downloaded and extracted. `sekurlsa::logonpasswords` run (LSASS access not logged) |
| 08-30 00:13 | WKSTN-0051 | evan.hutchinson | **PTH (first):** `sekurlsa::pth` for `itadmin`, new PowerShell spawned. Success unconfirmed |
| 08-30 00:14 to 00:19 | WKSTN-0051 | evan.hutchinson | Share discovery, then `IT_Automation.ps1` read from `\\WKSTN-1327.quicklogistics.org\ITFiles` |
| 08-30 00:20 to 00:21 | WKSTN-0051 to WKSTN-1327 | evan.hutchinson | `Invoke-Command` with the `allan.smith` password: `whoami` (00:20:23, 00:20:56), then the encoded stager (00:21:52) |
| 08-30 00:20 to 00:21 | WKSTN-1327 | allan.smith | WinRM logons (EID 4624 type 3, Kerberos). `wsmprovhost.exe` runs `whoami.exe`, then the stager |
| 08-30 00:22 to 01:28 | WKSTN-1327 | allan.smith | `hostname` and `whoami /all`, then no process creation for 66 minutes |
| 08-30 01:29 | WKSTN-1327 | allan.smith | Mimikatz downloaded again (01:29:09) and extracted (01:29:39) |
| 08-30 01:30 | WKSTN-1327 | allan.smith | **PTH 1 of 5:** `sekurlsa::pth` for `itadmin` (01:30:25), type 9 logon at 01:30:26. Then `sekurlsa::logonpasswords` (01:30:51) |
| 08-30 01:31 | WKSTN-1327 | allan.smith | **PTH 2 of 5:** `sekurlsa::pth` for `Administrator` (01:31:39), type 9 logon at 01:31:39. First appearance of the `Administrator` hash |
| 08-30 01:33 to 01:34 | WKSTN-1327 | allan.smith | `Invoke-Comand` typos against DC01 (likely failed), then `ls \\DC01.quicklogistics.org\c$` |
| 08-30 01:35 | WKSTN-1327 | allan.smith | DCSync attempt (01:35:15), no EID 4662 on DC01, likely failed |
| 08-30 01:35 | WKSTN-1327 | allan.smith | **PTH 3 of 5:** `sekurlsa::pth` for `Administrator` (01:35:54), type 9 logon at 01:35:54 |
| 08-30 01:36 to 01:37 | WKSTN-1327 to DC01 | allan.smith | `Invoke-Command hostname` against DC01 (01:36:40, 01:37:01) |
| 08-30 01:40 | WKSTN-0051 to WKSTN-1327 | evan.hutchinson | Second `Invoke-Command` with the `allan.smith` password. The stager runs again on WKSTN-1327 (01:40:38, new session `0x81f1da`) |
| 08-30 01:41 | WKSTN-1327 | allan.smith | **PTH 4 of 5:** `sekurlsa::pth` for `Administrator` (01:41:34), type 9 logon at 01:41:35, run from the new session |
| 08-30 01:42 | WKSTN-1327 | allan.smith | `schtasks /Create` for task `Updater` (SYSTEM, on idle) that runs a payload stored in `HKLM:\Software\Microsoft\Network`, value `debug` |
| 08-30 01:43 | WKSTN-1327 | allan.smith | `Invoke-Command hostname -ComputerName DC01` (01:43:36). `Invoke-Command hostname` without a computer name ran locally (01:43:45) |
| 08-30 01:43 | WKSTN-1327 | allan.smith | **PTH 5 of 5:** `sekurlsa::pth` for `Administrator` (01:43:57), type 9 logon at 01:43:57 |
| 08-30 01:45 | DC01 | Administrator | `wsmprovhost.exe` runs `hostname.exe` (01:45:02). Source of the session unverified |
| 08-30 01:45 | WKSTN-1327 to DC01 | allan.smith | `Invoke-Command hostname -ComputerName DC01` (01:45:12) |
| 08-30 01:45 | DC01 | Administrator | `wsmprovhost.exe` runs `hostname.exe` (01:45:19), then the stager (01:45:41). Source of the sessions unverified |
| 08-30 01:46 to 01:48 | DC01 | Administrator | Mimikatz downloaded. `net localgroup administrators`. DCSync for `backupda` (01:47:57) and `administrator` (01:48:04), both with EID 4662 success events |
| 08-30 01:49 to 01:50 | DC01 to WKSTN-1327 and WKSTN-0051 | Administrator | `Invoke-Command hostname` attempts |
| 08-30 01:53 | DC01 | Administrator | `ransomboogey.exe` downloaded from `ff.sillytechninja[.]io` (01:53:13) and run (01:53:33). 9 `.boogey` files created in `C:\Users\Administrator\Downloads` (01:53:34 to 01:53:38), then the process ended |
| 08-30 01:54 to 01:57 | DC01 to WKSTN-1327 and WKSTN-0051 | Administrator | `hostname` attempts (01:54:11 to WKSTN-1327, 01:54:24 to WKSTN-0051) and download-and-run attempts on WKSTN-1327. `ransomboogey.exe` started three times on WKSTN-1327 (01:56:06, 01:56:42, 01:57:54) and ended within a second, no files created |
| 08-30 01:59 to 02:02 | DC01 to WKSTN-0051 | Administrator | Download to `C:\Users\itadmin\` (01:59:36, no event on target). `hostname` (02:00:57). Download to `C:\Users\evan.hutchinson\` confirmed (02:01:14, file created, not executed). Stager (02:02:09) |
| 08-30 02:06 | WKSTN-0051 | Administrator | The stager runs encoded command attempts against WKSTN-0051 (itself) and WKSTN-1327 |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Status | Basis |
|---|---|---|---|---|
| Initial Access | T1566 Phishing | T1566.001 Spearphishing Attachment | Suspected | Attachment opened by the CEO (given in the scenario). The email was not analyzed |
| Execution | T1204 User Execution | T1204.002 Malicious File | Confirmed | `explorer.exe` opened the `.hta` |
| Execution | T1218 System Binary Proxy Execution | T1218.005 Mshta, T1218.011 Rundll32 | Confirmed | `mshta.exe` ran the HTA. `rundll32.exe` loaded `review.dat` |
| Execution | T1059 Command and Scripting Interpreter | T1059.001 PowerShell | Confirmed | Encoded stager, `Invoke-Command`, PowerView |
| Defense Evasion | T1036 Masquerading | T1036.007 Double File Extension | Confirmed | `.pdf.hta` |
| Defense Evasion | T1027 Obfuscated Files or Information | n/a | Confirmed | Base64 `-enc` commands, payload stored in the registry |
| Defense Evasion | T1112 Modify Registry | n/a | Confirmed | EID 13 on `ms-settings\Shell\Open\command` |
| Defense Evasion | T1562 Impair Defenses | T1562.001 Disable or Modify Tools | Suspected | The `fodhelper` payload appears to tamper with AMSI and ETW, not analyzed in depth |
| Privilege Escalation | T1548 Abuse Elevation Control Mechanism | T1548.002 Bypass User Account Control | Confirmed | `fodhelper.exe` chain spawning the PowerShell stager |
| Persistence | T1053 Scheduled Task/Job | T1053.005 Scheduled Task | Suspected | `Review` and `Updater` seen in command lines, no task creation events |
| Discovery | T1033, T1087, T1069, T1018, T1135, T1082 | T1087.001, T1087.002, T1069.001 | Confirmed | `whoami`, `net users`, `net localgroup`, PowerView, `Invoke-ShareFinder`, `hostname` |
| Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | Suspected | `sekurlsa::logonpasswords` ran. No EID 10, so access is inferred |
| Credential Access | T1003 OS Credential Dumping | T1003.006 DCSync | Confirmed | `lsadump::dcsync` plus EID 4662 success events |
| Credential Access | T1552 Unsecured Credentials | T1552.001 Credentials in Files | Suspected | `allan.smith` password used 30 seconds after `IT_Automation.ps1` was read |
| Lateral Movement | T1550 Use Alternate Authentication Material | T1550.002 Pass the Hash | Confirmed (executed), Not confirmed (accepted) | `sekurlsa::pth` and type 9 logons show execution. Acceptance by a remote system was not seen |
| Lateral Movement | T1021 Remote Services | T1021.006 Windows Remote Management | Confirmed | EID 4624 type 3, `wsmprovhost.exe` |
| Lateral Movement | T1078 Valid Accounts | T1078.002 Domain Accounts | Confirmed | `allan.smith` logons on WKSTN-1327 |
| Command and Control | T1071 Application Layer Protocol | T1071.001 Web Protocols | Suspected | Stager decodes to an HTTP request to `cdn.bananapeelparty[.]net:80`. No network capture |
| Command and Control | T1105 Ingress Tool Transfer | n/a | Confirmed | `Invoke-WebRequest` downloads of mimikatz, PowerView and `ransomboogey.exe` |
| Impact | T1486 Data Encrypted for Impact | n/a | Suspected | `.boogey` files created on DC01. Encryption not verified |

---

## Indicators of Compromise (IOCs)

### Network

| Indicator | Context | Status |
|---|---|---|
| `cdn.bananapeelparty[.]net` | Stager C2, port 80, paths `/admin/get.php` and `/news.php`. The stager uses a generic IE11 User-Agent and a static cookie | Confirmed |
| `ff.sillytechninja[.]io` | Source of `ransomboogey.exe` (DNS query seen on WKSTN-0051) | Confirmed |
| `hxxp://ff.sillytechninja[.]io/ransomboogey.exe` | Ransomware download URL | Confirmed |
| `165.232.170[.]151` | Outbound connection on port 80 from `rundll32.exe` (4672) at 23:51:17 | Suspected |

### Host

| Indicator | Context | Status |
|---|---|---|
| `ProjectFinancialSummary_Q3.pdf.hta` | Malicious attachment | Confirmed |
| `review.dat` | DLL-like payload (`D:\review.dat`, `%TEMP%\review.dat`) | Confirmed |
| `ransomboogey.exe`, `*.boogey` | Ransomware and the extension it creates | Confirmed |
| `mimi.zip`, `mimikatz.exe` | `C:\Windows\Temp\m\` (WKSTN-0051), `C:\Users\allan.smith\Documents\mimi\` (WKSTN-1327), `C:\Users\Administrator\Documents\mimi\` (DC01) | Confirmed |
| `Review`, `Updater` | Scheduled tasks on WKSTN-0051 and WKSTN-1327 | Suspected |
| `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Registry key used for the UAC bypass | Confirmed |
| `HKCU\Software\Microsoft\Windows Update`, value `Update` | Registry value that stores the stager payload | Confirmed |
| `HKLM\Software\Microsoft\Network`, value `debug` | Registry value run by `Updater`, seen only in the `schtasks` command line | Suspected |

---

## Impact / Recommendation

### Impact
- **Severity: High.** Three hosts were affected, including a domain controller.
- **Domain credentials:** DCSync succeeded for `backupda` and `administrator`. The credentials returned are not visible, so both accounts should be treated as compromised.
- **Credential exposure:** the `allan.smith` password was most likely stored in `IT_Automation.ps1` (suspected, from timing), and the hashes of `itadmin` and `Administrator` were used.
- **Persistence:** the two scheduled tasks and the registry-stored payloads should be assumed to be in place until removed.
- **Ransomware:** 9 `.boogey` files were created on DC01. No effect was seen on WKSTN-1327, and the file was only downloaded to WKSTN-0051.
- **Data theft:** not observed, but it cannot be ruled out because there is no network data.
- **Affected accounts:** `evan.hutchinson` (initial victim), `allan.smith` (plaintext password used), `itadmin` and `Administrator` (hashes used), `backupda` and `administrator` (DCSync targets).

### Recommendations

**Immediate**
- Isolate WKSTN-0051, WKSTN-1327 and DC01. Take memory and disk images before rebuilding.
- Block `cdn.bananapeelparty[.]net`, `ff.sillytechninja[.]io` and `165.232.170[.]151` at DNS, proxy and firewall.
- Disable and reset `allan.smith`, `itadmin`, `Administrator` and `backupda`. Reset `evan.hutchinson` too.
- Check `IT_Automation.ps1` and the other scripts on the `ITFiles` share for plaintext credentials and remove them.
- Find the phishing email in the mail gateway and remove it from all mailboxes.

**Eradication and recovery**
- Remove the `Review` and `Updater` tasks, the registry values (`Update`, `debug`), the `ms-settings` key, and the files listed in the IOC table.
- Rebuild DC01, or restore it from a backup taken before Aug 29 23:51. Cleaning it in place cannot be verified after a successful DCSync.
- Reimage WKSTN-0051 and WKSTN-1327.
- Reset the `krbtgt` password twice, with replication time between the resets. Reset all privileged and service accounts.
- Restore the `.boogey` files from backup and check whether the originals were actually encrypted.

**Detection and hardening**
- Hunt across the environment for:
  - `wsmprovhost.exe` spawning `powershell.exe -enc`
  - `mshta.exe` spawning `rundll32.exe` or `powershell.exe`
  - `rundll32.exe` loading a `.dat` file
  - Sysmon EID 13 on `ms-settings\Shell\Open\command`
  - EID 4662 with the replication GUIDs from a non-DC account
  - EID 4624 type 9 with `seclogo`
  - command lines with `sekurlsa::` or `lsadump::`
  - the `.boogey` extension and traffic to the two domains
- Block double-extension and `.hta` attachments at the mail gateway. Restrict `mshta.exe` with AppLocker or an ASR rule.
- Protect credentials: LSA protection and Credential Guard, Protected Users group for privileged accounts, and no plaintext passwords in scripts.
- Limit WinRM and RDP to a small set of admin hosts. Workstations should not reach DC01 with `Administrator`.
- Turn on the logging that was missing: Sysmon EID 10 on `lsass.exe`, PowerShell script block logging (4104) and scheduled task creation (4698).

---

## Limitations

- **Initial access:** the phishing email, the attachment and the contents of the `.hta` and `review.dat` were not analyzed. No process in the logs created `review.dat`, and its source (the `D:\` path suggests removable or mounted media) is unknown.
- **Credential theft:** no Sysmon EID 10, so LSASS access is inferred. The PTH logon events show execution, not acceptance by a remote system. The link between `IT_Automation.ps1` and the `allan.smith` password is based on timing.
- **DCSync:** it succeeded (EID 4662), but the credentials returned and any later use of them are not visible, so the exposure is inferred. The earlier attempt from WKSTN-1327 is assumed to have failed because it left no EID 4662 events.
- **Source of the DC01 sessions:** the `Administrator` sessions on DC01 do not match the `allan.smith` attempts from WKSTN-1327, and no matching events were found on the workstations. The origin is unverified.
- **Ransomware:** encryption was not verified, and the binary was not analyzed. Several remote `hostname` attempts left no process events on the target, so it is unknown whether they failed or were not logged.
- **Not analyzed:** the AMSI/ETW code in the `fodhelper` payload, `more.com` on WKSTN-1327 at 01:28:22, and the process that wrote the `Update` and `debug` registry values. The scheduled tasks come from command lines.
- **C2 and scope:** no network capture was available, so the content returned by the C2 server is unknown. Only logs from the three hosts were available, so the scope beyond them is unknown.
- **File hashes:** no file hashes were collected for the attacker files, so the IOC table lists names and paths only. File names can be changed by an attacker and are weaker indicators than hashes.