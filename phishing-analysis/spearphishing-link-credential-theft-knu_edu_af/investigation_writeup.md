# Investigation Writeup: Spearphishing Link Credential Theft knu.edu.af

## Objective
- To analyze the phishing email and the network traffic associated with it

---
## MITRE ATT&CK
- **Tactic:** Initial Access (TA0001)
- **Technique:** T1566 — Phishing
- **Sub-technique:** T1566.002 — Spearphishing Link

## Phishing Email Analysis

### Email Body Analysis
- The first step of this investigation is to analyze the email body (.eml)

![Phishing Email body](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/main_index.png)
- **Sender Email:-** noreply@domain.com
- The body contains a hyperlink (URI) asking the recipient to verify information in order to continue receiving pending emails. This is a classic phishing pattern, where the email is designed to create a sense of urgency to harvest information such as credentials
- The email claims to originate from the domain `domain[.]com`. Checking this using Claude AI and the tool `https://whois.domaintools.com/`, this domain is roughly 32 years old, registered in 1994, and offers services such as web hosting and website building. Given this, there's a chance the email has been spoofed using a legitimate, long-standing domain

![domain[.]com Claude AI Lookup](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/ai_output_for_domain_dot_com.png)

![domain[.]com WHOIS Lookup](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/whoislook_for_domaindotcom.png)

### Email Header Analysis
- Now let's analyze the email header to understand where the email actually originated

![Email Headers](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/emails_headers.png)

- We can see that authentication headers are not present in the email source (SPF, DKIM, DMARC). It's unusual for an email to lack authentication headers, there are a few reasons this could happen:
    - The receiving mail server never performed the checks. This isn't very common, since organizations prefer these authentication header checks as they're one way to verify the authenticity and integrity of an email
    - Headers were stripped when the sample was packaged for public distribution. This may be the reason the author removed the headers, but it's unlikely, since the purpose of the exercise given by the author is to build familiarity with the workflow of analyzing phishing emails
    - The sender simply never attempted authentication. Adversaries using their own infrastructure to send emails may not bother maintaining DKIM keys and certificates, since the sending server requires signing the email with a private key
    - Hence, the absence of authentication headers alone doesn't prove the email was spoofed
- **Return-Path:-** no return path
- **Received:-** the chain contains the IP address of the sender's mail exchange server, `38.68.46[.]250`

### Official SPF Policy of Sender Domain
- Let's look at the official SPF policy of the sender domain using the `https://mxtoolbox.com/` tool

![SPF Record for domain.com](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/spf_record_domaindotcom.png)

- This is the list of IP addresses authorized to send email for `domain[.]com`. After manually expanding each `include:` mechanism (Outlook, hostedemail, websitewelcome, salesforce, google, qualtrics) and checking all resulting ranges, `38.68.46.250` still does not match any authorized range. However, this sample is roughly six years old, and mail server IP assignments are not static over that timeframe, so this mismatch alone does not confirm spoofing
- I also checked the reputation of this IP address on `virustotal.com`, and it comes back clean (0/89 detections)
![VirusTotal Score for Sending IP 38.68.46.250](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/38-68-46-250_virustotal_score.png)
- **Checking ASN Record:-** to check what this IP address is actually used for, I checked it using the tool `https://bgp.tools/`

![ASN record check](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/bgptools_main.png)

![ASN 396073](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/bgptools_main_first_asn.png)

![ASN 174](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/bgptools_main_second_asn.png)

- This shows that this IP address is generally used for server hosting, which could be used by both adversaries and legitimate businesses or individuals

### Hyperlink
- Let's analyze the hyperlink contained in the email body. In the message source, we can see the actual URI in the hyperlink

![Hyperlink](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/hyperlink.png)

- Hyperlink = `https://knu.edu[.]af/upgrade/vbd/a-l-l/admin_system/rules_404_sys/2o19_nile_moves/ok_excute_2-2-1/now_g-a-m-e_starts/all-28-05-19/index.php?email=brad@malware-traffic-analysis[.]net`
- The URI redirects to a third-party domain (`knu.edu[.]af`), entirely different from the sender domain (`domain[.]com`). This is a strong indicator of a malicious phishing email, and increases the possibility that this email spoofed a legitimate service to fool users
*Note:- there's a limitation in analyzing the actual URL further, since the email sample is 6 years old and the author has changed the actual parameters to dummy values. To analyze the URL, we could otherwise use a tool like `urlscan.io`*

### Analyzing Domain in Hyperlink
- The domain in the hyperlink is `knu.edu[.]af`. Using `virustotal.com`, we can check the reputation of this domain

![Virus Total For Domain Knu.edu.af](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/virus_total_knu_edu.png)

- Vendors flag this domain as malicious and suspicious (Chong Lua Dao: Malicious, alphaMountain.ai: Suspicious), consistent with the credential harvesting behavior observed in this investigation



---
## Traffic Analysis
- We also have the traffic associated with this email, let's analyze it to determine whether the receiver interacted with the hyperlink or submitted their credentials

![Network Traffic](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/packets_1.png)

- Opening the pcap file in Wireshark, we can clearly see the DNS queries for the domain in the hyperlink, `knu.edu[.]af`, and an **HTTP GET** request to that domain. This proves that the receiver interacted with, or clicked, the hyperlink present in the email

- **Now let's check whether the receiver submitted credentials.** To check this, we can use this Wireshark filter to isolate POST requests to `knu.edu.af`
- Wireshark filter = `http.host == "knu.edu.af" and http.request.method == POST`

![Http Post Request](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/http_post_request.png)

- There's one POST request, and we can see the HTML form-encoded data containing the submitted credentials. This proves the receiver submitted their credentials to the fake login page
    - Submitted credentials:
        - **login:-** brad@malware-traffic-analysis.net
        - **Password:-** this-is-not-a-real-password

### Extracting the Login Page from PCAP
- Using Wireshark, we can also extract the actual HTML page designed for credential harvesting. To extract the page, do this in Wireshark:
`File --> Export Objects --> HTTP Object List --> Save All`
- Upon opening the folder where all objects were saved, we can open the `.php` files to see the actual login page

![Main Page](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/web_page.png)

![Login Page for Credential Harvesting](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/Login_page_credential_harvesting.png)

### Analyzing Network Outbound Connection
- In the pcap, within one second of the first HTTP GET request, we can also see a network outbound connection to another domain (`undependable-hangar.000webhostapp[.]com`, IP address `145.14.144[.]129`)

![Network Outbound Connection](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/network_outbound_connection_traffic.png)

- The connection occurring within less than a second of the first request suggests a possible redirection from the first domain, but this is not confirmed
- The connection itself is encrypted, and no decryptor is available, so its actual content cannot be analyzed
- Two confirmed network connections were identified in the pcap for the domain `undependable-hangar.000webhostapp[.]com`

**Let's analyze the reputation of this domain and the IP address associated with it**

![Virus Total For Domain undependable-hangar.000webhostapp[.]com](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/virus_total_undependable-hangardot000webhostappdotcom.png)

- The domain is flagged as phishing, with 8 vendors flagging it as such

![Virus Total Score for IP address 145.14.144[.]129 associated with domain](/phishing-analysis/spearphishing-link-credential-theft-knu_edu_af/snapshots/145-14-144-129_virus_total.png)

- The IP address associated with it is also flagged as phishing by 1 vendor

---
## Timeline of Events (UTC)

### Email Delivery and Hyperlink Interaction

| Time | Source | Destination | Event |
|---|---|---|---|
| 2020-05-05 09:06:05 | — | — | Email received by recipient |
| 2020-05-05 18:34:01.566 | 10.5.5.102 | 10.5.5.1 | DNS query for `knu.edu.af` |
| 2020-05-05 18:34:01.651 | 10.5.5.1 | 10.5.5.102 | DNS response: `knu.edu.af` → 68.183.103.170 |
| 2020-05-05 18:34:01.721 | 10.5.5.102 | 68.183.103.170 | HTTP GET `index.php?email=brad@malware-traffic-analysis.net` |
| 2020-05-05 18:34:01.863 | 10.5.5.102 | 68.183.103.170 | HTTP GET `images/e1.jpg` |
| 2020-05-05 18:34:08.911 | 10.5.5.102 | 68.183.103.170 | HTTP GET `english.php?email=brad@malware-traffic-analysis.net` |
| 2020-05-05 18:35:06.690 | 10.5.5.102 | 68.183.103.170 | HTTP POST `process.php` (form-urlencoded, credentials submitted) |

### Outbound Connection to Secondary Domain

| Time | Source | Destination | Event |
|---|---|---|---|
| 2020-05-05 18:34:02.037 | 10.5.5.102 | 10.5.5.1 | DNS query for `undependable-hangar.000webhostapp.com` |
| 2020-05-05 18:34:02.478 | 10.5.5.1 | 10.5.5.102 | DNS response → 145.14.144.129 |
| 2020-05-05 18:34:02.480 | 10.5.5.102 | 145.14.144.129 | TCP SYN, port 49927 (first connection) |
| 2020-05-05 18:34:02.520 | 10.5.5.102 | 145.14.144.129 | TCP SYN, port 49928 (second connection) |

Both connections complete a TLS handshake shortly after (Client Hello with SNI `undependable-hangar.000webhostapp.com`), after which the content is encrypted and could not be analyzed further.

## Conclusions
This investigation analyzed the email, hyperlink, associated domains, and traffic capture.

1. From evidence such as the lack of authentication headers, the mismatch between the sender domain and the domain in the hyperlink, the VirusTotal reputation results, and the extracted login page, we can conclude that this email is phishing, containing a hyperlink that redirects to a credential harvesting page

2. From the lack of authentication headers and the SPF record mismatch, taking into account the six-year-old limitation of this sample, it's not confirmed whether the email was spoofed or sent from a legitimate but compromised account. Based on the available evidence, there's a higher possibility of spoofing rather than a compromised legitimate account

3. From the pcap HTTP POST request, we can conclude and confirm that the user interacted with the hyperlink present in the email body and submitted their credentials

See the [Incident Report](./incident_report.md) for a high-level summary of this investigation.

---

## Limitations
- This investigation used the PCAP and email (.eml) file only. No host logs, endpoint telemetry, or SIEM data were available, so findings are limited to what could be directly observed or reasonably inferred from network traffic and the email itself
- The email sample is roughly six years old. SPF records, WHOIS data, mail server IPs, and ASN ownership can change significantly over that timeframe, so any mismatch or reputation result reflects current infrastructure, not necessarily what existed at the time the email was sent
- The outbound connection to `undependable-hangar.000webhostapp[.]com` was encrypted (TLS), and no decryption key was available, so its actual content could not be analyzed
- The mechanism that triggered this outbound connection, immediately after the first HTTP GET request, was not independently confirmed. Confirming whether it was a script-based redirect, an embedded resource load, or something else would require endpoint logs, which were not available for this investigation
- The capture does not include information identifying the hostname of the affected machine 