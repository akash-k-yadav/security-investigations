# INCIDENT REPORT: Fake Authenticator C2

- **Date of Analysis:** 15-07-2026
- **Source:** `www.malware-traffic-analysis.net`
- **Analysis Basis:** Full packet capture (PCAP) only. No host logs, endpoint telemetry, or SIEM data were available for this investigation.

---

## Summary
- User shutchenson searched for Google Authenticator and reached a site impersonating it (google-authenticator[.]burleson-appliance.net). The mechanism that led the user to this specific site is not confirmed from the capture.
- A DNS query to a second domain (authenticatoor[.]org) one second later suggests a redirect between the two impersonation domains, but this is based on timing correlation only, not independently confirmed.
- The malicious site delivered a scriptlet that triggered PowerShell to download and execute a beacon script from a C2 server.
- The host established recurring HTTP beaconing to the C2 server (5.252.153[.]241) every 5 seconds and downloaded five files, including two PowerShell scripts and a trojanized TeamViewer package (legitimate exe + malicious DLL). A second script (pas.ps1) confirmed this was used to establish persistence via a Startup folder shortcut, consistent with DLL sideloading.
- Post-compromise, the host performed SAMR enumeration and accessed the domain controller's SYSVOL share, reading Group Policy files. This is consistent with domain reconnaissance, possibly credential hunting through Group Policy Preferences.
- Two additional IPs seen in related activity could not be confirmed as C2 infrastructure since that traffic was encrypted (TLS) and no decryption key was available.

---

## Key Findings

| Question | Answer | Confidence |
|---|---|---|
| Infected machine IP | 10.1.17[.]215 | Confirmed |
| Infected machine MAC | 00:d0:b7:26:4a:74 | Confirmed |
| Compromised hostname | DESKTOP-L8C5GJ | Confirmed |
| Compromised user account | shutchenson | Confirmed |
| Malicious domains | google-authenticator[.]burleson-appliance.net, authenticatoor[.]org | Confirmed |
| C2 server IP | 5.252.153[.]241 | Confirmed |
| Additional suspected C2 IPs | 2 unidentified | Unconfirmed, traffic encrypted, no decryptor available |
| Files delivered by C2 | pas.ps1, 29842.ps1, TeamViewer.exe, TeamViewer_Resource_fr.dll, TV.dll | Confirmed |
| Persistence mechanism | Startup shortcut to TeamViewer.exe, created by pas.ps1 | Confirmed |

---

## Timeline

| Time | Event |
|---|---|
| 19:45 | DNS query to google-authenticator[.]burleson-appliance.net |
| 19:45 | DNS query to authenticatoor[.]org, one second later (possible redirect) |
| 19:46 | Host connects to C2 server (5.252.153[.]241), receives .sct scriptlet in response |
| 19:46 | Scriptlet triggers hidden PowerShell to download 29842.ps1 and four additional files from C2 |
| 19:47 | Five malicious files downloaded from C2 via HTTP |
| 19:47 | TeamViewer.exe, TV.dll, and TeamViewer_Resource_fr.dll delivered. DLL sideloading, likely persistence/remote access mechanism |
| 19:47 | pas.ps1 executed: downloads TeamViewer.exe, TV.dll, TeamViewer_Resource_fr.dll, and creates Startup shortcut to TeamViewer.exe (persistence confirmed via decoded script) |
| 19:53 | SAMR enumeration performed against domain controller |
| 19:56 | SYSVOL accessed via SMB, Group Policy files enumerated |
| 19:59 | C2 beaconing confirmed, HTTP GET every 5 seconds |
| 20:25 | Last C2 communication observed in capture |

---

## Attack Chain
- **Initial Access:** Host reached a site impersonating Google Authenticator. How the user got to this specific site is not confirmed. Timing suggests a possible redirect to a second impersonation domain.
- **Execution:** A delivered scriptlet triggered hidden PowerShell, which downloaded and ran a beacon script.
- **Command and Control:** HTTP based beaconing to 5.252.153[.]241 every 5 seconds. C2 sent further file delivery through this channel.
- **Persistence:** A second script (pas.ps1) downloaded a trojanized TeamViewer package and created a Startup folder shortcut to TeamViewer.exe. Consistent with DLL sideloading, confirmed via decoded script logic.
- **Discovery:** SAMR enumeration and SYSVOL/GPO file access via SMB, consistent with domain reconnaissance.

---

## Indicators of Compromise (IOCs)

| Type | Indicator | VirusTotal |
|---|---|---|
| Malicious Domain | google-authenticator.burleson-appliance[.]net | 6/91 |
| Malicious Domain | authenticatoor[.]org | 11/91 |
| C2 Server IP | 5.252.153[.]241 | 16/91 |

| File | SHA-256 | VirusTotal |
|---|---|---|
| 29842.ps1 | `b8ce40900788ea26b9e4c9af7efab533e8d39ed1370da09b93fcf72a16750ded` | 29/60 |
| pas.ps1 | `a833f27c2bb4cad31344e70386c44b5c221f031d7cd2f2a6b8601919e790161e` | 28/60 |
| TeamViewer_Resource_fr.dll | `9634ecaf469149379bba80a745f53d823948c41ce4e347860701cbdff6935192` | 0/67 |
| TeamViewer.exe | `904280f20d697d876ab90a1b74c0f22a83b859e8b0519cb411fda26f1642f53e` | 0/67 |
| TV.dll | `3448da03808f24568e6181011f8521c0713ea6160efd05bff20c43b091ff59f7` | 45/70 |

*Malicious files are not uploaded to this repository. Hashes are provided for reference and can be searched on VirusTotal or any threat intelligence platform.*

---

## Impact / Recommendation
Reimage the affected host (DESKTOP-L8C5GJ) and reset credentials for the user account (shutchenson). Block the identified malicious domains and confirmed C2 IP at the network perimeter. Review GPO/SYSVOL access logs on the domain controller for any sign of credential exposure through Group Policy Preferences.

---

## Limitations
- This investigation used PCAP data only. No host logs, endpoint telemetry, or SIEM data were available. Findings are limited to what could be directly observed or reasonably inferred from network traffic.
- The mechanism that led the user to the initial impersonation domain (ad click, search result, direct link) is not confirmed from the capture.
- The redirect between the two impersonation domains is based on DNS query timing only, not independently confirmed.
- Two additional IPs seen in related activity could not be confirmed as C2 infrastructure due to TLS encryption with no available decryption key.
- The SMB authentication method (NTLM vs Kerberos) used to access the domain controller was not determined.
- The actual binary contents of TeamViewer.exe, TV.dll, and TeamViewer_Resource_fr.dll were not extracted or reverse engineered. Decoding these binaries would require deeper malware analysis than the scope of this investigation, so conclusions about them (DLL sideloading, persistence) rely on file naming, VirusTotal detections, and the pas.ps1 script logic, not direct binary analysis.