# INCIDENT REPORT: Phishing Email Impersonating SSA, Redirect to icci-sa.com

- **Date of Analysis:** 24-09-2026
- **Source:** `www.malware-traffic-analysis.net`
- **Analysis Basis:** Packet capture (PCAP) and email (EML) only. No host logs, endpoint telemetry, or SIEM data were available for this investigation.

---

## Summary
- An employee in the organization received an email from the allsecured[.]net domain impersonating the Social Security Administration. The email contained a hyperlink claiming to link to a social security statement download.
- Upon further investigation it was confirmed the email was spoofed, and the hyperlink contained in the email redirected to a completely different domain.
- Both the sender domain and the domain in the hyperlink are legitimate domains. The sender's domain (allsecured[.]net) is owned by a company that provides security services and is based in Ohio, USA. The redirected domain (icci-sa[.]com) belonged to a construction business based in France.
- The user interacted with the link in the email body and downloaded content of approximately 13 MB. What was actually downloaded is not confirmed, due to the traffic being encrypted.
- A DNS query for check.screenconnect[.]com was observed, followed by a DNS query for instance-udppxf-relay.screenconnect[.]com. A network outbound connection was then observed to the IP resolved from the second query (15.204.43[.]235). VirusTotal shows 0/89 detections for this IP; a community comment from 8 months prior describes a similar chain (phishing → fake download → abuse of old ScreenConnect → RAT), consistent with the pattern observed here. This is unconfirmed, based on a single anonymous submission.

---

## Key Findings

| Question | Answer | Confidence |
|---|---|---|
| Host machine IP | 10.9.14[.]101 | Confirmed |
| Host machine MAC | 00:08:02:1c:47:ae | Confirmed |
| Hostname | Not recoverable from this capture | Unconfirmed |
| Sender Domain | `allsecured[.]net`, **Spoofed** | Confirmed |
| Uri (hyperlink) | `https[:]//t[.]co/LPz3zzwREa` | Confirmed |
| Redirected Uri | `https[:]//icci-sa[.]com/xgov/` | Confirmed |

---

## Timeline (UTC)

| Time | Event |
|---|---|
| 13-09-2026 14:05:44 | User received the phishing email |
| 14-09-2026 20:37:28 | User clicked the malicious hyperlink in the email |
| 14-09-2026 20:37:29 | Redirection to domain |
| 14-09-2026 20:37:29 to 20:39:41 | Data transfer from domain, 13 MB |
| 14-09-2026 20:43:01 | DNS query for check.screenconnect[.]com |
| 14-09-2026 20:43:14 | DNS query for instance-udppxf-relay.screenconnect[.]com |
| 14-09-2026 20:43:17 | Network outbound connection to IP 15.204.43[.]235 (associated with instance-udppxf-relay.screenconnect[.]com) |

---

## MITRE ATT&CK Mapping
- **Tactic:** Initial Access (TA0001)
- **Technique:** T1566 - Phishing
- **Sub-technique:** T1566.002 - Spearphishing Link
- **Tactic:** Execution (TA0002)
- **Technique:** T1204 - User Execution
- **Sub-technique:** T1204.001 - Malicious Link

---

## Indicators of Compromise (IOCs)

| Indicator | Type | Context | Confidence |
|---|---|---|---|
| https[:]//t[.]co/LPz3zzwREa | URL | Hyperlink in phishing email body, Twitter/X URL shortener used to obfuscate the actual redirect destination | Confirmed |
| 23.227.202[.]93 | IP | Email sender IP | Confirmed |
| https[:]//icci-sa[.]com/xgov/ | URL | Redirect target from shortlink | Confirmed |
| 15.204.43[.]235 | IP | Outbound connection target, resolved from instance-udppxf-relay.screenconnect[.]com, 0/89 VT detections | Confirmed |

---

## Impact / Recommendation
- From the infected endpoint, investigate what was actually received.
- Investigate post-infection network outbound connections from endpoint logs to check for any data exfiltration or C2 commands received.
- Isolate the infected host to prevent lateral movement or discovery.

---

## Limitations
- This investigation used PCAP and email data only. No host logs, endpoint telemetry, or SIEM data were available. Findings are limited to what could be directly observed or reasonably inferred from network traffic and the email itself.
- The actual data content received from the redirected domain is unknown, as the traffic was encrypted and no decryption key is available.
- The mechanism that triggered the network outbound connection immediately after content was received from the redirected domain is unknown, as the connection was encrypted and no decryptor is provided.
- The outbound connection observed was encrypted, and no decryption key was available, so its exact content could not be analyzed. This would require endpoint logs or a decryptor.
