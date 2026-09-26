# Investigation Writeup: Phishing Email Impersonating SSA, Redirect to icci-sa.com

## Objective
- To analyze the phishing email and the network traffic associated with it

---

## MITRE ATT&CK
- **Tactic:** Initial Access (TA0001)
- **Technique:** T1566 - Phishing
- **Sub-technique:** T1566.002 - Spearphishing Link
- **Tactic:** Execution (TA0002)
- **Technique:** T1204 - User Execution
- **Sub-technique:** T1204.001 - Malicious Link

---

## Phishing Email Analysis

### Email Body Analysis
- The first step of this investigation is to analyze the email body (.eml).

![Email body](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/email_body.png)

- **Sender Email:-** Information@allsecured[.]net
- The email body contains a hyperlink claiming to link to a Social Security statement download. This is one of the classic techniques adversaries use when crafting phishing emails, impersonating a trusted entity to bait the victim into downloading malicious documents or software.
- The email originates from `allsecured[.]net`, and the body claims to be the Social Security Administration, which is suspicious and a red flag, indicating a possibility of spoofing.
- Let's research the sender domain using a simple Google query and an AI chatbot to determine whether this domain is legitimate or malicious.

![Claude response](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/claude_response_allsecureddotnet.png)

![Google query](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/google_query_for_allsecureddotnet.png)

- From `claude.ai` and `google.com`, after cross-verifying them and visiting their legitimate site (`https://allsecured[.]net`), it belongs to a business based in Ohio, USA, that provides security services.

### Email Header Analysis
Now let's analyze the email header to understand where the email actually originated and the actual hyperlink present in the email.

![Email Headers](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/email_headers.png)

### Email headers

**Return-Path:-** Information@allsecured[.]net
**SPF:-** Softfail
**DMARC:-** Fail, policy=quarantine
**DKIM:-** None
**Received-from:-** 23.227.202[.]93

- The SPF result is softfail. Let's look at the official SPF record of this domain using `https://mxtoolbox.com/`. The official SPF policy is softfail, and after manually checking and expanding all `include:` mechanisms, the sender IP still does not match any valid IP in the SPF record. A softfail here means the sender isn't in the authorized list, but the email isn't rejected, only treated as suspicious.

![Official spf policy](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/official_spf_record_of_allsecureddotnet.png)

- DKIM is none, and DMARC failed in the email header, with a policy of quarantine, meaning the email isn't rejected but is diverted to the junk or spam folder.

### Email Sender IP Address Analysis
- Now let's analyze the sender SMTP server IP address, `23.227.202[.]93`.
- First we will look at the reputation of this IP address on `https://virustotal.com`.

![Virus total reputation of 23.227.202[.]93](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/Email_sender_ip_address_virustotal.png)

- On VirusTotal, 2 out of 89 vendors flag this IP as Malicious, with additional vendors marking it Suspicious and Spam. Combined with the SPF softfail and DMARC failure above, this supports the assessment that the email is spoofed and sent from an untrustworthy source.

### Hyperlink and Domain in It
- Let's analyze the hyperlink contained in the email body. In the message source, we can see the actual URI in the hyperlink.

![Hyperlink](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/hyperlink.png)

- Hyperlink = `https[:]//t[.]co/LPz3zzwREa`
- This is a Twitter (now X) link shortener. Using `https://urlscan.io`, we find it redirects to an entirely different domain, `icci-sa[.]com`, which is totally unrelated to the Social Security Administration.
- **Redirected URI:-** `https[:]//icci-sa[.]com/xgov`

![Hyperlink](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/urlscanio_hyplerlink.png)

- Further analysis of this URL cannot be done at this time, as the webpage is currently showing `Not Found`. A query on `phishtank` was also attempted, but what was actually hosted on the redirected URI still cannot be determined.

- Let's check the domain age using `https://whois.domaintools.com/`. The domain is 6 years old, hosted on IP address `159.198.35[.]37`.

![Whoislookup of icci-sa[.]com](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/whoislookup_icci-sadotcom.png)

- Checking `icci-sa[.]com` itself on VirusTotal, no vendors flag the domain as malicious.

![Virus total score of icci-sa[.]com](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/virus_total_score_for_domain_in_hyplerlink.png)

- Now let's check the reputation of the hosting IP, `159.198.35[.]37`, separately. On VirusTotal, the aggregate score shows 0 out of 89, but one vendor (Criminal IP) still flags it as Suspicious, so it isn't fully clean. The Relations tab shows one communicating file, a Win32 EXE named `1xsnu.exe`, flagged by 62 out of 71 vendors as malicious.

![Virus total reputation](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/ip159-198-35-37.png)


![Communicating file for 159.198.35.37](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/159-198-35-37-vt_communicating-with-file.png)

- Checking the ASN using `https://bgp.tools`, this IP range (Namecheap, Inc.) is tagged as a VPN Host and Tor service. This tag applies to the broader netblock rather than confirming this specific IP is an active VPN/Tor node, but infrastructure on ranges tagged this way is commonly favored by threat actors since it obscures the true origin and operator of a server, unlike typical legitimate business hosting.

![BGP/ASN info for 159.198.35.37](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/bgptool-159-198-35-37.png)

- Finally, let's try the Wayback Machine to see if there's any captured snapshot of the webpage from around the time the email was received, September 13, 2026.

- On the Wayback Machine, there are no captured snapshots near the time the email was received. The last capture goes back to July 12, 2025.

![Wayback machine captured snapshot](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/icci-sa-waybackmachine.png)

- Looking at the actual capture from July 12, 2025, the webpage is in French and the website is about a construction business.

- So far, we have an email received from `allsecured[.]net`, a security-providing company based in the United States, claiming to be the Social Security Administration, that redirects to a domain which previously hosted a webpage for a construction business based in France, and is now hosted on infrastructure tagged as VPN/Tor-associated with one confirmed-malicious communicating file.

---

## Traffic Analysis
- We also have the traffic associated with this email. Let's analyze it to determine whether the receiver interacted with the hyperlink or downloaded something.

![Dns queries for T[.]co](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/dnsquery-for-tdotco.png)

- Opening the pcap file in Wireshark, we can clearly see the DNS query for the domain in the hyperlink, `t[.]co`.

![Dns queries for icci-sa[.]com](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/dnsquery-for-iccisadotdom.png)

- After some packets, we can see the DNS query for the domain in the redirected URL, `icci-sa[.]com`. This confirms the user interacted with the URL presented in the hyperlink.

- We can then see a long connection to `icci-sa[.]com`. This connection is encrypted, so we cannot determine what was actually received over it, but we can see how much data was transferred in Wireshark. To do this, right-click a packet in the stream and select Conversation Filter -> TCP to isolate it, then go to Statistics -> Conversations to see the totals. This shows a total data transfer of **13 MB**, confirming something was downloaded, though what it was remains unknown. Confirming this would require a decryption key or endpoint logs, neither of which are available.

![Conversation between host and ip](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/conversation-bw-host-and-ip.png)

### Analyzing Post-Connection DNS Queries

- There are also DNS queries observed for `screenconnect[.]com` after this connection. In Wireshark, we can see DNS queries for `check.screenconnect[.]com` and `instance-udppxf-relay.screenconnect[.]com`. `check.screenconnect[.]com` is a valid, legitimate subdomain for ScreenConnect, while the second is a specific relay instance.

![Observe Dns queries](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/dnsqueries-for-screenconnect.png)

- After the second DNS query, we also observe a network outbound connection to IP address `15.204.43[.]235`, associated with that query.

![Network outbound connection](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/network_outbound_connection_in_pcap.png)

- Looking further in the capture, the connection to `check.screenconnect[.]com` closes with an RST shortly after, while the connection to `15.204.43[.]235` stays open and is kept alive with repeated TCP keep-alive packets well past the end of the visible capture window. This is a persistence indicator, the connection remained open with repeated keep-alives rather than closing like the check-in connection did.

![TCP keep-alive on relay connection](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/network-outbound-connection-tcpkeepalive.png)

**Let's analyze the reputation of this IP address**
- Analyzing the reputation of `15.204.43[.]235` on VirusTotal, it comes back clean, but the Relations tab shows this IP communicating with 119 files, the majority named `ScreenConnect.ClientSetup.msi` or similar variants, several flagged by multiple vendors. This is consistent with the IP being used as ScreenConnect distribution/relay infrastructure. It's possible the 13 MB received in the earlier connection to icci-sa[.]com was one of these files, but this is not confirmed.

![Virus total relation tab of the 15.204.43[.]235](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/15-204-43-235_virus_total_relation.png)

- Checking the ASN on `https://bgp.tools`, this IP (OVH SAS) is also tagged as a VPN Host and Tor service, the same pattern seen on the icci-sa[.]com hosting IP. Two separate IPs in this attack chain sitting on infrastructure tagged this way is a more notable pattern than either alone.

![BGP/ASN info for 15.204.43.235](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/bgptools-15-204-43-235.png)

- Also, looking at the Community tab on VirusTotal, there is a comment stating: "Phishing campign -> Fake zoom download -> Abusing old screenconnect ->rat" [sic]. This comment was posted 8 months ago, and the attack pattern looks similar to this one. This can't be confirmed from a single comment, but it is consistent with the pattern observed here.

![Virus total community tab of the 15.204.43[.]235](/phishing-analysis/phishing-ssa-impersonation_icci-sa-com/snapshots/network_outbound_connection_virustotal_community.png)

---

## Timeline of Events (UTC)

| Time | Source | Destination | Event |
|---|---|---|---|
| 2026-09-13 14:05:44 | allsecured[.]net (23.227.202[.]93) | N/A | Phishing email received |
| 2026-09-14 20:37:28 | 10.9.14.101 | 10.9.14.1 | DNS query for t[.]co (user clicked hyperlink) |
| 2026-09-14 20:37:29 | 10.9.14.101 | 159.198.35[.]37 | DNS resolution and connection to icci-sa[.]com |
| 2026-09-14 20:37:29 to 20:39:41 | 10.9.14.101 | 159.198.35[.]37 | Data transfer over TLS, 13 MB received, connection closed (RST) |
| 2026-09-14 20:43:01 | 10.9.14.101 | 10.9.14.1 | DNS query for check.screenconnect[.]com |
| 2026-09-14 20:43:17 | 10.9.14.101 | 10.9.14.1 | DNS query for instance-udppxf-relay.screenconnect[.]com |
| 2026-09-14 20:43:17 | 10.9.14.101 | 15.204.43[.]235 | Outbound TCP connection established to relay IP |
| 2026-09-14 20:45:14 | 10.9.14.101 | 184.194.97[.]23 | Connection to check.screenconnect[.]com closed (RST); connection to relay IP (15.204.43[.]235) remains open with TCP keep-alives |

---

## Conclusions

1. The email was spoofed. SPF returned softfail and DMARC failed (policy=quarantine), and the sending IP (23.227.202[.]93) does not appear in allsecured[.]net's published SPF record.
2. The sender IP (23.227.202[.]93) is flagged by multiple VirusTotal vendors as Malicious/Suspicious/Spam, indicating prior involvement in malicious activity.
3. The hyperlink used a t[.]co shortlink to obscure the actual redirect target, icci-sa[.]com, an abandoned legitimate domain unrelated to the impersonated SSA, now hosted on infrastructure tagged as VPN/Tor-associated.
4. The user interacted with the link and received approximately 13 MB of encrypted content from icci-sa[.]com. The content itself could not be identified due to encryption, though the hosting IP is confirmed to communicate with at least one malicious file (`1xsnu.exe`, 62/71 detections).
5. DNS activity and a subsequent outbound connection to 15.204.43[.]235 show behavior consistent with a ScreenConnect RMM client connecting to a relay instance. This connection persisted with keep-alives after the initial check-in connection closed, and the relay IP is associated with 119 communicating files, predominantly ScreenConnect installers.
6. Whether the 13 MB download was a ScreenConnect installer, and whether the outbound connection constitutes malicious C2 activity, is not confirmed by this investigation. Traffic was encrypted and no endpoint or host telemetry was available.

See the [Incident Report](./incident_report.md) for a high-level summary of this investigation.

---

## Limitations
- This investigation used the PCAP and email (.eml) file only. No host logs, endpoint telemetry, or SIEM data were available, so findings are limited to what could be directly observed or reasonably inferred from network traffic and the email itself.
- The capture does not include information identifying the hostname of the affected machine.
- All traffic to icci-sa[.]com and to the ScreenConnect relay IP (15.204.43[.]235) was TLS-encrypted. Without a decryption key or endpoint telemetry, this investigation cannot confirm what was contained in the 13 MB transfer, nor what data, if any, was exchanged over the persistent connection to the relay IP. Any conclusion about payload identity or C2 activity is inference from DNS/connection metadata only, not confirmed content inspection.