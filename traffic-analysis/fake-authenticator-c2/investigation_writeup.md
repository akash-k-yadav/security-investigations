# Investigation Writeup: Fake Authenticator C2

## Objective
To investigate a suspicious file download from a site impersonating Google Authenticator, and reconstruct the resulting infection chain.

---

## Methodology

### Step 1: Initial Traffic Overview
**Protocol Hierarchy**
- TCP carries 93.2% of traffic.
  - TLS: 61.4% (HTTPS traffic).
  - HTTP: 3.2%. Small but worth examining, since modern networks mostly use HTTPS for confidentiality, and attackers sometimes prefer plain HTTP for C2 or exfiltration since maintaining and purchasing certificates is extra overhead.
  - SMB1 and SMB2 packets are present, raising the possibility of post-exploitation discovery, remote command execution, or lateral movement.

**Conversations**
- Many conversations exist, but a few stand out as worth checking:
  - 20+ conversations between internal IP 10.1.17[.]215 and the domain controller (10.1.17[.]2).
  - 3 conversations between 10.1.17[.]215 and external IP 5.252.153[.]241 over TCP/80 (HTTP), with data transfers of roughly 1MB, 1KB, and 5MB.
- A large amount of TCP/443 (HTTPS) traffic is also present, but no decryption key was available, which is a limitation on this investigation (see Limitations).

### Step 2: Identifying the Suspicious Domain
From the background, the user searched for Google Authenticator and was redirected to a site impersonating it. To find this domain:
- Wireshark filter used: `dns matches "google" or dns matches "authenticator"`
- This surfaced a DNS request to `google-authenticator[.]burleson-appliance.net`.
- VirusTotal score: 6/91.
- Immediately after, a second DNS query appears to `authenticatoor[.]org` within the same second, suggesting a possible redirect between the two domains (based on timing only, not independently confirmed).
- VirusTotal score for the second domain: 11/91.
- After this point, traffic to related IPs becomes encrypted (TLS), and could not be analyzed further without a decryption key.

### Step 3: Analyzing the Suspicious Outbound Connection over TCP/80
Following the HTTP stream to 5.252.153[.]241 (`tcp.stream eq 60`) showed the first request returning an `.sct` scriptlet (VBScript wrapped in a `<component>` tag). The script:
- Opens a decoy legitimate site (`azure.microsoft.com`) in the foreground.
- Simultaneously launches hidden PowerShell to download and execute `29842.ps1` from the same C2 server.

This two-part behavior (visible decoy + hidden payload execution) suggests the scriptlet was designed to avoid drawing user attention while the actual payload runs in the background.

### Step 4: Extracting and Decoding the Beacon Script (29842.ps1)
The downloaded file (`29842.ps1`) was base64-decoded using CyberChef. The decoded script:
- Reads the C: drive's volume serial number and converts it to a numeric ID, used as a unique identifier for the infected host.
- Builds a callback URL from the C2 IP and this ID.
- Enters a loop that repeatedly attempts to download content from this URL and immediately executes whatever is returned, using `Invoke-Expression`.
- On failure, waits 5 seconds and retries.

This is a lightweight PowerShell-based C2 beacon: it gives the C2 operator the ability to send arbitrary commands to the infected host at any time, and explains the 5-second polling interval observed in later traffic.

### Step 5: Extracting and Decoding the Persistence Script (pas.ps1)
`pas.ps1`, delivered by the C2 shortly after the beacon script, was also decoded. This script:
- Downloads four files (TeamViewer.exe, TV.dll, TeamViewer_Resource_fr.dll, and pas.ps1 itself) into `C:\ProgramData\huo\`.
- Calls a `Create-Shortcut` function to place a `.lnk` file pointing to `TeamViewer.exe` in the current user's Startup folder.
- Returns a success message (`'startup shortcut created'`) once complete, which is sent back to the C2 via a follow-up HTTP request.

This directly confirms the persistence mechanism observed in traffic: the "startup shortcut created" message seen in the beacon's C2 callback is not just a self-reported status string, it reflects an actual, verifiable action taken by this script. TeamViewer.exe will now launch automatically on every login/reboot, giving the attacker a durable remote access channel through the sideloaded malicious DLL.

### Step 6: VirusTotal Verification
All five files delivered by the C2 were hashed and checked against VirusTotal:

| File | Detections | Notes |
|---|---|---|
| 29842.ps1 | 29/60 | Flagged as PowerShell trojan/downloader; sandbox-evasion tags (checks-cpu-name, long-sleeps) |
| pas.ps1 | 28/60 | Same family/behavior as above |
| TeamViewer.exe | 0/67 | Undetected; signed but with a revoked certificate |
| TV.dll | 45/70 | Flagged as trojan.doina/dlloader |
| TeamViewer_Resource_fr.dll | 0/67 | Undetected |

The pairing of a clean, signed TeamViewer.exe with a flagged TV.dll is consistent with DLL sideloading: a legitimate executable loading a malicious DLL placed alongside it, used here to deliver persistent remote access under the cover of a trusted, signed program.

### Step 7: Post-Compromise Activity
Following the file delivery, the infected host initiated SMB sessions to the domain controller (10.1.17[.]2):
- **SAMR enumeration** (19:53:39 to 19:55:39): domain, user, and group lookups via SAMR operations (EnumDomain, LookupNames, GetGroupsForUser, GetAliasMemberships).
- **SYSVOL/GPO enumeration** (19:56:00 to 20:06:17): access to the SYSVOL share, including `gpt.ini`, `GptTmpl.inf`, and `Registry.pol`.

This activity is consistent with domain reconnaissance, and potentially credential hunting via Group Policy Preferences, though no evidence of credential extraction was directly observed in this capture.

---

## Raw Traffic Timeline
19:45:34 DNS query to google-authenticator[.]burleson-appliance.net
- 19:45:35 DNS query to authenticatoor[.]org (possibility of redirection)

### First Conversation with C2 Server
- 19:45:56 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /api/file/get-file/264872
- 19:45:56 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

### Second Conversation with C2 Server: 19:45:58 to 19:53:38
- 19:45:58 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /api/file/get-file/29842.ps1
- 19:45:58 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 19:47:01 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /api/file/get-file/TeamViewer
- 19:47:01 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 19:47:04 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /api/file/get-file/TeamViewer_Resource_fr
- 19:47:04 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 19:47:05 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /api/file/get-file/pas.ps1
- 19:47:05 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 19:47:05 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /1517096937?k=message%20=%20startup%20shortcut%20created;%20%20status%20=%20success;
- 19:47:05 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

### SAMR Enumeration: 19:53:39 to 19:55:39
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , Session Setup Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , Tree Connect Request \\WIN-GSH54QLW48D.bluemoontuesday.com\IPC$
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , EnumDomain Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , LookupDomain Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , OpenDomain Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , LookupNames Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , OpenUser Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , GetGroupsForUser Request
- 19:53:39 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , GetAliasMemberships Request

### Network Shared Object Accessed on Domain Controller (SYSVOL): 19:56:00 to 20:06:17
- 19:56:00 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , Session Setup Request
- 19:56:00 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , Tree Connect \\WIN-GSH54QLW48D.bluemoontuesday.com\IPC$
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , Tree Connect \\WIN-GSH54QLW48D.bluemoontuesday.com\SYSVOL
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
- 19:56:02 , 10.1.17[.]215 --> 10.1.17[.]2 , SMB , File Access bluemoontuesday.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Registry.pol

### Third Conversation with C2 Server: 19:55:06 to 20:25:09
- GET requests from the infected host to the C2 server every five seconds,
receiving HTTP 404 Not Found responses except for the below requests
(confirmed C2 beaconing).

- 19:59:38 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /1517096937?k=script:%20RunRH,%20status:%20OK,%20message:%20PS%20process%20started
- 19:59:39 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 20:25:09 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /1517096937?k=script:%20RunRH,%20status:%20OK,%20message:%20PS%20process%20started
- 20:25:09 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

- 20:20:27 , 10.1.17[.]215 --> 5.252.153[.]241 , HTTP GET /1517096937?k=script:%20RunRH,%20status:%20OK,%20message:%20PS%20process%20started
- 20:20:07 , 5.252.153[.]241 --> 10.1.17[.]215 , HTTP/1.1 200 OK

---

## Evidence
### Protocol Hierarchy
![Protocol Hierarchy](/traffic-analysis/fake-authenticator-c2/snapshots/protocol_heirarchy.png)
### Conversations
![Conversations](/traffic-analysis/fake-authenticator-c2/snapshots/conversation.png)
### Domain Identification
![Domain Identification](/traffic-analysis/fake-authenticator-c2/snapshots/malicious_domain.png)
### First Connection with C2
![First Connection with C2](/traffic-analysis/fake-authenticator-c2/snapshots/convo_id_60.png)
### File Extracted 29842.ps1
![File extracted :- 29842.ps1](/traffic-analysis/fake-authenticator-c2/snapshots/29842ps1.png)
### Persistence Script 
![Persistence script decoded :- pas.ps1](/traffic-analysis/fake-authenticator-c2/snapshots/Powershell-Script-Extracted-From-HTTP-Stream.png)
### Virus Total Score for file TeamViewer.exe
![Virus Total Score for File TeamViewer.exe](/traffic-analysis/fake-authenticator-c2/snapshots/teamviewer_virus_total.png)
### Virus Total Score for file TeamViwer_resource.dll
![Virus Total Score for File TeamViewer_resource.dll](/traffic-analysis/fake-authenticator-c2/snapshots/Team_viewer_resource_Fr_virustotal.png)
### Virus Total Score for file TV
![Virus Total Score for File TV](/traffic-analysis/fake-authenticator-c2/snapshots/tv_virustotal.png)
### Virus Total Score for file pas.ps1
![Virus Total Score for File pas.ps1](/traffic-analysis/fake-authenticator-c2/snapshots/pas_ps1_virus_total.png)
### Virus Total Score for file 29842.ps1
![Virus Total Score for File 29842.ps1](/traffic-analysis/fake-authenticator-c2/snapshots/29842_psi_virus_total.png)

---

## Conclusions
This investigation traced a full infection chain from a fake Google Authenticator page through to post-compromise domain reconnaissance:

1. The infected host (10.1.17[.]215, DESKTOP-L8C5GJ, user shutchenson) reached a site impersonating Google Authenticator. The exact mechanism that led the user there was not confirmed from this capture.
2. The site (or a related domain reached moments later) served an `.sct` scriptlet that silently triggered a PowerShell-based C2 beacon.
3. This beacon (`29842.ps1`) used the host's volume serial number as a unique ID and polled the C2 server every 5 seconds for further commands.
4. The C2 delivered a second script (`pas.ps1`) that downloaded a trojanized TeamViewer package and created a Startup folder shortcut, confirming persistence via DLL sideloading.
5. The host then performed SAMR and SYSVOL enumeration against the domain controller, consistent with post-compromise domain reconnaissance.

The two assigned questions this investigation could not fully resolve (additional C2 IPs, and the precise initial redirect mechanism) are detailed in Limitations below.

---

## Limitations
- This investigation used PCAP data only. No host logs, endpoint telemetry, or SIEM data were available.
- The exact mechanism that led the user to the initial impersonation domain (ad click, search result, or direct link) could not be confirmed.
- The relationship between the two impersonation domains is based on DNS query timing only, not independently verified.
- A large volume of TCP/443 traffic could not be analyzed due to TLS encryption with no available decryption key. This includes two additional IPs that could not be confirmed as C2 infrastructure.
- The SMB authentication method used to access the domain controller (NTLM vs. Kerberos) was not determined.
- The actual binary contents of TeamViewer.exe, TV.dll, and TeamViewer_Resource_fr.dll were not extracted or reverse engineered. Decoding these binaries would require deeper malware analysis than the scope of this investigation, so conclusions about them (DLL sideloading, persistence) rely on file naming, VirusTotal detections, and the pas.ps1 script logic, not direct binary analysis.