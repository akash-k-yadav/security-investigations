# INCIDENT REPORT: Spearphishing Link Credential Theft knu.edu.af

- **Date of Analysis:** 25-07-2026
- **Source:** `www.malware-traffic-analysis.net`
- **Analysis Basis:** Packet capture (PCAP) and email (EML) only. No host logs, endpoint telemetry, or SIEM data were available for this investigation.

---

## Summary
- An employee in the organization received an email from `noreply@domain[.]com`. Upon review, the email was classified as malicious, containing a hyperlink to a fake login page designed for credential harvesting.
- The user clicked the malicious hyperlink in the email body and submitted their credentials (email address and password).
- A network outbound connection was identified a few seconds after the hyperlink was clicked. The domain involved in this connection was flagged as malicious on VirusTotal.

---

## Key Findings

| Question | Answer | Confidence |
|---|---|---|
| Host machine IP | 10.5.5[.]102 | Confirmed |
| Host machine MAC | 00:08:02:1c:47:ae | Confirmed |
| Hostname | Not recoverable from this capture | Unconfirmed |
| Malicious domains | knu.edu[.]af, undependable-hangar.000webhostapp[.]com | Confirmed |
| IPs associated with malicious domains | 68.183.103[.]170 (knu.edu.af), 145.14.144[.]129 (000webhostapp.com) | Confirmed |
| Credentials submitted | Yes , HTTP POST with `login` and `passwd` fields captured in PCAP | Confirmed |

---

## Timeline (UTC)

| Time | Event |
|---|---|
| 05-05-2020 09:06:05 | User received the malicious email |
| 05-05-2020 18:34:01 | User clicked the malicious hyperlink in the email |
| 05-05-2020 18:34:02 | Network outbound connection to 145.14.144[.]129 |
| 05-05-2020 18:35:06 | User submitted their credentials (email address and password) |

---

## MITRE ATT&CK Mapping
- **Tactic:** Initial Access (TA0001)
- **Technique:** T1566 — Phishing
- **Sub-technique:** T1566.002 — Spearphishing Link

---

## Indicators of Compromise (IOCs)

| Type | Indicator | VirusTotal |
|---|---|---|
| Malicious Domain | knu.edu[.]af | 1/89 |
| Malicious Domain | undependable-hangar.000webhostapp[.]com | 8/89 |
| Associated IP | 68.183.103[.]170 | 0/89 (clean) |
| Associated IP | 145.14.144[.]129 | 1/89 |
| URI | `http://knu.edu.af/upgrade/vbd/a-l-l/admin_system/rules_404_sys/2o19_nile_moves/ok_excute_2-2-1/now_g-a-m-e_starts/all-28-05-19/index.php?email=brad@malware-traffic-analysis[.]net` | — |

*Note: The submitted password value observed in the PCAP (`this-is-not-a-real-password`) is a deliberate placeholder used by the sample's author and does not represent a real credential.*

---

## Impact / Recommendation
- Reset the credentials of the affected email account.
- Review the account's logon activity for any signs of unauthorized use following the credential submission.
- Provide phishing awareness training to employees to reduce the likelihood of similar incidents.

---

## Limitations
- This investigation used PCAP and email data only. No host logs, endpoint telemetry, or SIEM data were available. Findings are limited to what could be directly observed or reasonably inferred from network traffic and the email itself.
- No SPF, DKIM, or DMARC authentication headers were present in the email source, so sender authentication results could not be evaluated directly. The hyperlink domain differs from the sender's domain, and the sending IP does not match the sender domain's current SPF record. That said, this sample is nearly six years old, sending infrastructure IPs are not static over that timeframe, and this mismatch alone does not confirm spoofing. A compromised legitimate account is an alternative explanation; the available evidence does not distinguish between the two.
- The mechanism that triggered the network outbound connection immediately after the hyperlink click was not independently confirmed .
- The outbound connection observed was encrypted, and no decryption key was available, so its exact content could not be analyzed. This would require endpoint logs or a decryptor.
