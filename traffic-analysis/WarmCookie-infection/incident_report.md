# INCIDENT REPORT: WarmCookie Infection
- **Date of Analysis:** 2026-10-10
- **Source:** `www.malware-traffic-analysis.net`
- **Analysis Basis:** Packet capture (PCAP) and alerts only. No host logs, endpoint telemetry, or SIEM data were available for this investigation.

---

## Summary
- On 2024-08-15 at 00:10:58 UTC, the host `DESKTOP-H8ALZBV` (10.8.15[.]133, user account `plucero`) connected to the suspicious domain `quote.checkfedexexp[.]com` and downloaded a supicious invoice-named zip file (2,767,804 bytes).
- The zip file contains an obfuscated JavaScript (JS) file filled with junk code.
  - The JS file contains a URL on `business.checkfedexexp[.]com`, a different subdomain of the same suspicious parent domain.
  - About 20 seconds after the zip download, the host connected to `business.checkfedexexp[.]com`. The connection was encrypted, so the traffic could not be analyzed.
- The host then connected to 72.5.43[.]29 and downloaded a malicious DLL.
  - According to ThreatFox, 72.5.43[.]29 is a command and control (C2) server for the WarmCookie malware.
  - VirusTotal labels the DLL with the WarmCookie family, and it matches WarmCookie YARA rules.
  - Three HTTP POST requests were then sent to the same IP with 124, 305,148 and 732 bytes of data. The data was encoded or encrypted, so its content is unknown.
  - 302 HTTP GET requests followed at intervals of about 3 to 9 seconds, with one 52.6 second gap, consistent with C2 beaconing.

---

## Key Findings

| Question | Answer | Confidence |
|---|---|---|
| Host machine IP | 10.8.15[.]133 | Confirmed |
| Host machine MAC | 00:1c:bf:03:54:82 | Confirmed |
| Hostname | DESKTOP-H8ALZBV | Confirmed |
| Windows user account | plucero | Confirmed |
| Initial zip file downloaded | `Invoice 876597035_003.zip` | Confirmed |
| Extracted obfuscated JS file | `Invoice-876597035-003-8331775-8334138.js` | Confirmed |
| Malicious DLL | `lab17a` (DLL, name per VirusTotal) | Confirmed |
| Malicious domains | quote.checkfedexexp[.]com and business.checkfedexexp[.]com | Confirmed |
| C2 server IP address | 72.5.43[.]29 | Confirmed |

---

## Timeline (UTC)

| Time | Event |
|---|---|
| 2024-08-15 00:10:55 | DNS query for `quote.checkfedexexp[.]com` |
| 2024-08-15 00:10:58 | Outbound connection to `quote.checkfedexexp[.]com` |
| 2024-08-15 00:11:04 | Malicious zip file containing the JS file was downloaded |
| 2024-08-15 00:11:23 | DNS query for `business.checkfedexexp[.]com` |
| 2024-08-15 00:11:24 to 00:11:52 | Outbound connection to `business.checkfedexexp[.]com`, about 1.4 MB received and 650 KB sent, content unknown due to encryption |
| 2024-08-15 00:11:59 | HTTP HEAD request for the DLL |
| 2024-08-15 00:12:00 | Malicious DLL downloaded |
| 2024-08-15 00:13:00 | HTTP GET request to the C2 |
| 2024-08-15 00:13:00 | HTTP POST request to the C2, 124 bytes |
| 2024-08-15 00:13:02 | HTTP POST request to the C2, 305,148 bytes |
| 2024-08-15 00:13:02 | HTTP POST request to the C2, 732 bytes |
| 2024-08-15 00:13:07 to 00:42:25 | 302 HTTP GET requests to the C2 at intervals of about 3 to 9 seconds, with one 52.6 second gap |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Confidence | Basis |
|---|---|---|---|---|
| Execution | T1204 User Execution | T1204.002 Malicious File | Suspected | A user must open the JS file; the PCAP does not show this |
| Execution | T1059 Command and Scripting Interpreter | T1059.007 JavaScript | Suspected | JS execution is not observed in the PCAP |
| Stealth | T1027 Obfuscated Files or Information | T1027.016 Junk Code Insertion | Confirmed | Junk text inserted as comments in the JS file |
| Stealth | T1027 Obfuscated Files or Information | T1027.010 Command Obfuscation | Confirmed | URL and `GET` built from split string fragments in the JS file |
| Stealth, Persistence | T1197 BITS Jobs | None | Suspected | DLL downloaded with user agent `Microsoft BITS/7.8`; only the download is observed, not persistence |
| Command and Control | T1071 Application Layer Protocol | T1071.001 Web Protocols | Confirmed | HTTP communication with the C2 |
| Command and Control | T1105 Ingress Tool Transfer | None | Confirmed | DLL downloaded from the C2 server |

---

## Indicators of Compromise (IOCs)

| Indicator | Type | Context | Confidence |
|---|---|---|---|
| Invoice 876597035_003.zip (`798563fcf7600f7ef1a35996291a9dfb5f9902733404dd499e2e736ea1dc6fc5`) | File | Malicious zip file that contains the JS file | Confirmed |
| Invoice-876597035-003-8331775-8334138.js (`dab98819d1d7677a60f5d06be210d45b74ae5fd8cf0c24ec1b3766e25ce6dc2c`) | File | Extracted obfuscated JS file | Confirmed |
| lab17a (`b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6`) | File | Malicious DLL downloaded from the C2 server (name per VirusTotal) | Confirmed |
| 72.5.43[.]29 | IP address | C2 server IP address | Confirmed |
| quote.checkfedexexp[.]com | Domain | Domain from which the zip file was downloaded | Confirmed |
| business.checkfedexexp[.]com | Domain | Domain contained in the URL found in the JS file | Confirmed |
| `hxxp://quote.checkfedexexp[.]com/managements?16553a25e45250a41fd5&endeds=MIGpq&JStx=59bf050d37df88a9-ade43358-eaa1220b-0571422b-0f33e6aa150e86bafd0ed4&Ld=9d7502d88d752a27b1d00587309184b5a215` | URL | URL from which the zip file was downloaded | Confirmed |
| `hxxp://72.5.43[.]29/data/0f60a3e7baecf2748b1c8183ed37d1e4` | URL | URL from which the DLL was downloaded | Confirmed |
| `hxxps://business.checkfedexexp[.]com/data-privacy?zj=ZzqRKxVRQ&pOd=GEokiOXFwH&sourcedp=tQMQJlIo&Tfocontent=IxGTZjXqxJ&Jr_cid=9464552&L=8174388` | URL | URL embedded in the JS file, reconstructed from string fragments, not observed on the wire | Confirmed |

---

## Impact / Recommendation
- From the infected endpoint, investigate what triggered the connection to `quote.checkfedexexp[.]com` and what was received from the encrypted connection to `business.checkfedexexp[.]com`.
- From endpoint logs, check what data was sent to the C2.
- Isolate the infected host to prevent lateral movement or discovery.
- Block the IOC domains, URLs and the C2 IP at the firewall, proxy and DNS.
- Reset the password of the `plucero` account.

---

## Limitations
- This investigation used PCAP and alert data only. No host logs, endpoint telemetry, or SIEM data were available. Findings are limited to what could be directly observed or reasonably inferred from network traffic.
- The content received from the encrypted connection to `business.checkfedexexp[.]com` is unknown, as no decryption key is available.
- The mechanism that triggered the connection to `quote.checkfedexexp[.]com` is unknown.
- The content of the data sent to the C2 is unknown, as no endpoint logs were provided and the data was encoded or encrypted.
- Execution of the JS file and of the DLL is not observed in the PCAP.