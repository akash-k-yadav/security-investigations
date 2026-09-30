# INCIDENT REPORT: Fake Authenticator C2

- **Date of Analysis:** 15-07-2026
- **Source:** `www.malware-traffic-analysis.net`
- **Analysis Basis:** Full packet capture (PCAP) only. No host logs, endpoint telemetry, or SIEM data were available for this investigation.

---

## Summary
- User shutchenson searched for Google Authenticator and reached a site impersonating it (google-authenticator[.]burleson-appliance.net). The mechanism that led the user to this specific site is not confirmed from the capture.
- A DNS query to a second domain (authenticatoor[.]org) followed one second later. The relationship between the two domains is not confirmed, as timing is the only link and the related traffic was encrypted.
- Roughly 20 seconds after the first DNS query, the host sent an HTTP request directly to 5.252.153[.]241, which returned a scriptlet containing a hidden PowerShell command to download and run a beacon script. The traffic to the impersonation domains was encrypted, so it is not confirmed what triggered this request.
- The host established recurring HTTP beaconing to the C2 server (5.252.153[.]241) every 5 seconds and downloaded five files, including two PowerShell scripts and a trojanized TeamViewer package (legitimate exe + malicious DLL). The decoded pas.ps1 downloads the TeamViewer files and creates a Startup folder shortcut to TeamViewer.exe, consistent with persistence via DLL sideloading. The script reported success back to the C2, but the shortcut itself was not observed.
- Two additional IPs seen in related activity could not be confirmed as C2 infrastructure since that traffic was encrypted (TLS) and no decryption key was available.

---

## MITRE ATT&CK
- **Tactic:** Execution (TA0002)
- **Technique:** T1059.001 - PowerShell
- **Tactic:** Command and Control (TA0011)
- **Technique:** T1105 - Ingress Tool Transfer
- **Technique:** T1071.001 - Web Protocols
- **Tactic:** Persistence (TA0003)
- **Technique:** T1547.001 - Registry Run Keys / Startup Folder
- **Tactic:** Defense Evasion (TA0005)
- **Technique:** T1574.002 - DLL Side-Loading (unconfirmed, binaries not analysed)

---

## Key Findings

| Question | Answer | Confidence |
|---|---|---|
| Infected machine IP | 10.1.17[.]215 | Confirmed |
| Infected machine MAC | 00:d0:b7:26:4a:74 | Confirmed |
| Compromised hostname | DESKTOP-L8C5GJ | Confirmed |
| Compromised user account | shutchenson | Confirmed |
| Impersonation domains | google-authenticator[.]burleson-appliance.net, authenticatoor[.]org | Suspected, flagged on VirusTotal, no traffic observed linking them to the C2 |
| C2 server IP | 5.252.153[.]241 | Confirmed |
| Additional suspected C2 IPs | 2 unidentified | Unconfirmed, traffic encrypted, no decryptor available |
| Files delivered by C2 | pas.ps1, 29842.ps1, TeamViewer.exe, Teamviewer_Resource_fr.dll, TV.dll | Confirmed |
| Persistence mechanism | Startup shortcut to TeamViewer.exe, per decoded pas.ps1 logic (success reported by the script itself, shortcut not observed) | Suspected |

---

## Timeline (UTC, 22-01-2025)

| Time | Event |
|---|---|
| 19:45:34 | DNS query to google-authenticator[.]burleson-appliance.net |
| 19:45:35 | DNS query to authenticatoor[.]org, one second later (relationship to the first domain not confirmed) |
| 19:45:56 | Host sends HTTP GET to C2 server (5.252.153[.]241), receives .sct scriptlet |
| 19:45:58 | Host requests 29842.ps1 from C2 |
| 19:47:01 to 19:47:05 | Host requests TeamViewer, Teamviewer_Resource_fr, TV and pas.ps1 from C2, in the same order as the file list in the decoded pas.ps1 |
| 19:47:05 | Callback to C2 reporting "startup shortcut created" |
| 19:55:07 | Recurring HTTP GET beaconing to C2 begins (about every 5 seconds) |
| 19:59:38 | Callback to C2 reporting "PS process started" (repeated at 20:25:09 and 20:27:54) |
| 20:38:18 | Last C2 beacon request in the capture |

---

## Attack Chain
- **First Observed Activity:** Host resolved a domain impersonating Google Authenticator, and about 20 seconds later requested a scriptlet directly from the C2 server. What triggered that request is not confirmed, as the traffic to the impersonation domains was encrypted.
- **Execution:** A delivered scriptlet triggered hidden PowerShell, which downloaded and ran a beacon script.
- **Command and Control:** HTTP based beaconing to 5.252.153[.]241 every 5 seconds. C2 sent further file delivery through this channel.
- **Persistence:** A second script (pas.ps1) is coded to download a TeamViewer package (TeamViewer.exe, TV.dll, Teamviewer_Resource_fr.dll) and create a Startup folder shortcut to TeamViewer.exe. This is consistent with DLL sideloading, but the binaries were not analysed, so sideloading is not confirmed.

---

## Indicators of Compromise (IOCs)

| Type | Indicator | VirusTotal |
|---|---|---|
| Impersonation Domain | google-authenticator[.]burleson-appliance.net | 6/91 |
| Impersonation Domain | authenticatoor[.]org | 11/91 |
| C2 Server IP | 5.252.153[.]241 | 13/91 |

| File | SHA-256 | VirusTotal |
|---|---|---|
| 29842.ps1 | `b8ce40900788ea26b9e4c9af7efab533e8d39ed1370da09b93fcf72a16750ded` | 29/60 |
| pas.ps1 | `a833f27c2bb4cad31344e70386c44b5c221f031d7cd2f2a6b8601919e790161e` | 28/60 |
| Teamviewer_Resource_fr.dll | `9634ecaf469149379bba80a745f53d823948c41ce4e347860701cbdff6935192` | 0/67 |
| TeamViewer.exe | `904280f20d697d876ab90a1b74c0f22a83b859e8b0519cb411fda26f1642f53e` | 0/67 |
| TV.dll | `3448da03808f24568e6181011f8521c0713ea6160efd05bff20c43b091ff59f7` | 45/70 |

*Malicious files are not uploaded to this repository. Hashes are provided for reference and can be searched on VirusTotal or any threat intelligence platform.*

---

## Impact / Recommendation
Reimage the affected host (DESKTOP-L8C5GJ) and reset credentials for the user account (shutchenson).

---

## Limitations
- This investigation used PCAP data only. No host logs, endpoint telemetry, or SIEM data were available. Findings are limited to what could be directly observed or reasonably inferred from network traffic.
- The mechanism that led the user to the initial impersonation domain (ad click, search result, direct link) is not confirmed from the capture.
- The redirect between the two impersonation domains is based on DNS query timing only, not independently confirmed.
- Two additional IPs seen in related activity could not be confirmed as C2 infrastructure due to TLS encryption with no available decryption key.
- The actual binary contents of TeamViewer.exe, TV.dll, and Teamviewer_Resource_fr.dll were not extracted or reverse engineered. Decoding these binaries would require deeper malware analysis than the scope of this investigation, so conclusions about them (DLL sideloading, persistence) rely on file naming, VirusTotal detections, and the pas.ps1 script logic, not direct binary analysis.