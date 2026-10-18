# Investigation Writeup: WarmCookie Infection

## Objective
- To analyze the alerts and the PCAP

---

## Understanding the Alerts

- The first step is to understand what each alert means. The official rule text is not given, so some of my interpretation could be wrong. The notes below are my first interpretation before looking at the traffic. Alerts 1 to 6 are checked against the PCAP in the section Analyzing the Remaining Alerts (1 to 6).

![Alert image given by author](/traffic-analysis/WarmCookie-infection/snapshots/2024-08-15-traffic-analysis-exercise-alerts.jpg)

- This alert image is given by the author. It shows the alerts, counts and severity level. The author also gives a text file with more information, such as the actual timing.

### Alerts

- **1. ET DNS Standard query response, Name Error**: A DNS server replied with response code 3 (NXDOMAIN), meaning the domain does not exist. This is a generic rule and does not look at the domain itself.
- **2. ET INFO Terse Request for .txt - Likely Hostile**: An HTTP GET for a .txt URL with very few headers (browsers normally send User-Agent, Accept, Accept-Language, etc.). Scripts and malware that build requests by hand often skip them.
- **3. ET INFO Microsoft Connection Test**: Windows NCSI check. It requests a known file (`connecttest.txt`) over plain HTTP to decide if the machine has internet access. Alert 2 probably fired on this same request because the shape matches (my guess, check timestamps). It still alerts because IDS rules match patterns, not intent.
- **4. ET POLICY TLSv1.0 Used in Session**: The TLS handshake (sent in cleartext) showed version 1.0, which is deprecated. This is a policy alert, not a malware signature.
- **5. GPL RPC kerberos principal name overflow TCP**: An old Snort rule looking for an oversized Kerberos principal name (buffer overflow pattern). I am not sure of the exact pattern. My guess is that it can false positive on normal Windows Kerberos traffic. Not confirmed.
- **6. GPL ICMP_INFO Destination Unreachable Port Unreachable**: ICMP type 3 code 3. A host sent a packet (usually UDP) to a port where nothing was listening.

- **7. ET POLICY Binary Download Smaller than 1 MB Likely Hostile**: The HTTP response body starts with `MZ` (Windows executable signature) and is under 1 MB. Small executables are typical of droppers, but legitimate small utilities can match too.
- **8. ET TROJAN Possible Windows executable sent when remote host claims to send html content**: The `Content-Type` says `text/html` but the body is a Windows executable. Legitimate downloads normally label the content type correctly, so the mismatch is the signal.
- **9. ET POLICY PE EXE or DLL Windows file download HTTP**: A PE file (EXE or DLL) was transferred over HTTP. This is the broad one. Alerts 7 and 8 add size and content type conditions, so all of them may have fired on the same download.
- **10. ET INFO SUSPICIOUS Dotted Quad Host MZ Response**: The client requested from a server by bare IP in the `Host` header and got an `MZ` response. Downloading from a bare IP skips DNS, so there is no domain to block. I believe it fires on the response side.

- **11. ETPRO INFO Incorrect Spacing of UA Variable M3**: Something about the spacing in the User-Agent header is wrong. It is an ET Pro rule, so the text is not public and I cannot verify it. I do not know what M3 means (guess: variant label). Malware often hardcodes a fake browser User-Agent, and typing it by hand can introduce spacing differences (see the user agent in the traffic analysis below).
- **12. ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1**: An HTTP POST to a bare IP with a User-Agent that looks like a browser but is judged fake. Unlike alerts 7 to 10 (data coming down), this is data going up, which is what check-in traffic to a C2 looks like. I am not sure how the rule defines "fake" (see the user agent in the traffic analysis below).

---

## Analyzing Traffic

- Let's take the highest severity alert first and investigate the traffic related to it. I am taking alert 9, `ET POLICY PE EXE or DLL Windows file download HTTP`.

### Analyzing Traffic Related to Alert 9: ET POLICY PE EXE or DLL Windows file download HTTP

- Now using this Wireshark filter `ip.addr == 72.5.43.29 and http` to isolate the HTTP traffic related to the external IP in the alert.

![Traffic Related to First Alert](/traffic-analysis/WarmCookie-infection/snapshots/isolated_traffic_75-5-43-29.png)

- To this IP, we can see first an HTTP HEAD request to the URL `hxxp://72.5.43[.]29/data/0f60a3e7baecf2748b1c8183ed37d1e4`. A HEAD request is used to get metadata about a resource. The user agent is `Microsoft BITS/7.8`.
- Following this, the next request is an HTTP GET to the same URL, with the same user agent (`Microsoft BITS/7.8`). Looking at the response to this GET request in the next packet:
  - status code: 200
  - content-type: text/html
  - content-length: 159,232 bytes

![HTTP Stream](/traffic-analysis/WarmCookie-infection/snapshots/http_stream_for_dll.png)

- **Microsoft BITS/7.8:** is the user agent that the Windows Background Intelligent Transfer Service (BITS) puts in its HTTP requests. BITS is a built-in Windows service that transfers files over HTTP/HTTPS in the background. It is generally used by legitimate Windows services and applications such as Windows Update, Defender updates, the Microsoft Store, etc. Here the destination is not a Microsoft host, which is the anomaly. The user agent alone is not malicious; the destination and the content delivered are what make this suspicious.
- The content type says `text/html` but the content starts with `MZ`. "MZ" is the magic number at the very start of every DOS/Windows executable (.exe, .dll, .sys), and "This program cannot be run in DOS mode." is the DOS stub, a tiny leftover program embedded in every PE file. If someone ran the file in plain DOS, it would just print this message and exit. This is suspicious because the content type and the content delivered do not match. The binary is also downloaded from a bare IP used as the host (not a domain), which is what alert 10 detects. The size of the file received is approximately `155.5 KB`.
- Alerts 7 to 10 all fired on this one response (same source `72.5.43[.]29:80` and destination `10.8.15.133:49810` in the alert table). Each one matches a different part of it:
  - **Alert 7 (Binary Download Smaller than 1 MB):** the response body starts with `MZ` and is 159,232 bytes (about 155.5 KB), which is under 1 MB.
  - **Alert 8 (Possible Windows executable sent when remote host claims to send html content):** the `Content-Type` is `text/html` but the body is a Windows executable.
  - **Alert 9 (PE EXE or DLL Windows file download HTTP):** the body is a PE file (`MZ` header and DOS stub), and VirusTotal identifies it as a DLL.
  - **Alert 10 (Dotted Quad Host MZ Response):** the request used the bare IP `72.5.43[.]29` in the `Host` header and the response is an `MZ` file.

### Checking the Downloaded Binary Hash

- Let's check the SHA256 hash of the downloaded file on https://virustotal.com. To do this, we first need to export the binary from the PCAP. To export the binary in Wireshark:
  - `File --> Export Objects --> HTTP`, then select the one with packet number `10762`
  - then in Kali Linux, use this command `sha256sum 0f60a3e7baecf2748b1c8183ed37d1e4`
  - the computed hash of the downloaded binary is `b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6`
- Now checking the reputation of the file on https://virustotal.com

![Virus total reputation of the downloaded binary](/traffic-analysis/WarmCookie-infection/snapshots/content-from-75-543-29-virustotal.png)

- On VirusTotal, this file is flagged as malicious by 60 vendors out of 71 and the file type is DLL.
- It also matches three YARA rules on VirusTotal: `Windows_Trojan_WarmCookie_7d32fa90` and `Windows_Trojan_WarmCookie_e8cd480d` (both by Elastic Security), and `Quickbind` (CAPEv2). ThreatFox lists Quickbind as an alias of WarmCookie. This supports that the binary downloaded from `72.5.43[.]29` is a malicious DLL associated with the WarmCookie malware family.
- The user agent `Microsoft BITS/7.8` was used to download the malicious DLL. This is consistent with the known living off the land technique, where adversaries use trusted Windows components to blend in with normal traffic.
- After the malicious DLL was downloaded, there are also HTTP POST requests to the same IP address in Wireshark.

![HTTP Post Request to C2 server](/traffic-analysis/WarmCookie-infection/snapshots/http_post_request_to_c2.png)

- There are three POST requests in total, carrying 124, 305,148 and 732 bytes of data. The response to all three requests is `400 Bad Request`. The server received the requests, since it replied, but we do not know whether it accepted or used the data. The data sent was encoded or encrypted, so we do not know what was actually sent.
- The user agent in the POST requests is `Mozilla / 5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705)`. IE 6 and Windows XP have been unsupported for over a decade, so a real user is very unlikely to be using them at the time of capture (2024).
  - The string is internally inconsistent: it starts with `Mozilla/5.0`, which IE 6 never sent (real IE 6 sent `Mozilla/4.0`). That mismatch suggests a hand-written or hardcoded string rather than a real browser.
  - There is also a space around the slash (`Mozilla / 5.0`). Real browsers do not format it that way, so this is another sign of a fake or sloppily built string.
- After the POST requests, there are many GET requests to `hxxp://72.5.43[.]29/`. The response to all of these requests is `400 Bad Request`. There is a 3 to 9 second interval between these requests, with one 52 second gap. This could be beaconing (the machine repeatedly trying to reach the attacker's server).

![C2 server Beaconing (HTTP GET request)](/traffic-analysis/WarmCookie-infection/snapshots/c2_server_beaconing.png)

- The user agent in the GET requests is also `Mozilla / 5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705)`
- Filtering with `ip.addr == 72.5.43.29 and http.request.method == "GET" and http.request.uri == "/"` returns 303 requests (1 with status code `200 OK` at `2024-08-15 00:13:00`, and 302 with status code `400 Bad Request`).

![HTTP GET requests to the C2 server (beaconing)](/traffic-analysis/WarmCookie-infection/snapshots/http_response_c2_communication.png)

- Filtering with `http.response.code == 400 and ip.src == 72.5.43.29` returns 305 responses (3 for the POST requests and 302 for the beacon GET requests).

![HTTP 400 responses from the C2 server](/traffic-analysis/WarmCookie-infection/snapshots/http_response_code400_c2_communication.png)

- Alerts 11 and 12 match this traffic:
  - **Alert 11 (Incorrect Spacing of UA Variable M3):** the User-Agent has spaces around the slash (`Mozilla / 5.0`), which is most likely what the rule flags (the ET Pro rule text is not public). The alert count (307) is within one of the 306 requests using this user agent (3 POST and 303 GET, filter `http.user_agent contains "MSIE 6.0"`), so it fired on the beacon GET requests too, not only on the POST requests.
  - **Alert 12 (GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1):** the three POST requests go to the bare IP `72.5.43[.]29` (in the `Host` header) with a User-Agent that claims to be a browser (Mozilla, MSIE) but is inconsistent, as shown above. This is why it is judged a fake browser.

### Checking the Reputation of the IP Address

- Using VirusTotal to check the reputation of the IP address.

![Virus total reputation of ip address](/traffic-analysis/WarmCookie-infection/snapshots/72-5-43-29_virustotal_score.png)

- 15 out of 92 vendors flagged this IP address as malicious.
- And on the ThreatFox threat intel platform:

![Threat fox abuse result for ip address](/traffic-analysis/WarmCookie-infection/snapshots/72-5-43-29_threat_fox_abuse.png)

- ThreatFox lists this IP address as an IOC with the threat type command and control server (`botnet_cc`) associated with the WarmCookie malware. ThreatFox lists Badspace, Carrotstick and Quickbind as aliases of WarmCookie. The confidence is moderate.
- The first seen date on ThreatFox is `2024-08-14 20:41:41 UTC`, about 3.5 hours before the host first contacted this IP (`2024-08-15 00:11:59 UTC`).
- The malicious DLL downloaded from this IP address matches the YARA rules `Windows_Trojan_WarmCookie_7d32fa90`, `Windows_Trojan_WarmCookie_e8cd480d` and `Quickbind`, which indicates a WarmCookie campaign.
- Now let's check what happened before this activity.

### Checking Before Activity

- There is also one more HTTP (TCP/80) outbound connection, to the IP `104.21.55[.]70` and the domain `hxxp://quote.checkfedexexp[.]com`. There is only one conversation with this IP.

![Outbound connection](/traffic-analysis/WarmCookie-infection/snapshots/104-21-55-70_http_convo.png)

- There is an HTTP GET request to the URL `hxxp://quote.checkfedexexp[.]com/managements?16553a25e45250a41fd5&endeds=MIGpq&JStx=59bf050d37df88a9-ade43358-eaa1220b-0571422b-0f33e6aa150e86bafd0ed4&Ld=9d7502d88d752a27b1d00587309184b5a215`
- This is followed by an HTTP response code 200 OK. The response content type is `application/octet-stream`, the file name is **Invoice 876597035_003.zip**, and a file of 2,767,804 bytes is downloaded.

### Exporting and Analyzing the Downloaded Zip File

- To export this file in Wireshark, go to `File --> Export Objects --> HTTP` and select the respective packet number, which is 8659 in our case.
- Compute the SHA256 hash of the file with this command: `sha256sum "Invoice 876597035_003.zip"`
- The computed hash is `798563fcf7600f7ef1a35996291a9dfb5f9902733404dd499e2e736ea1dc6fc5`
- Check the hash on VirusTotal.

![ZIP file downloaded reputation](/traffic-analysis/WarmCookie-infection/snapshots/file_download_from_104-21-55-70-virus_total.png)

- On VirusTotal, 27 vendors out of 64 flag this file as malicious. The threat labels are downloader and trojan.

### Extracting and Analyzing the Zip File

- Extract the file in the VM using this command: `unzip "Invoice 876597035_003.zip"`
- The extracted file is named `Invoice-876597035-003-8331775-8334138.js`. Compute its SHA256 hash using this command: `sha256sum Invoice-876597035-003-8331775-8334138.js`, and check the hash on VirusTotal.
- The computed hash is `dab98819d1d7677a60f5d06be210d45b74ae5fd8cf0c24ec1b3766e25ce6dc2c`

![Js file reputation virus total](/traffic-analysis/WarmCookie-infection/snapshots/Extracted_js_file_from_bussiness_subdomain.png)

- 21 vendors out of 61 flag this file as malicious, and it matches the Sigma rule `Outbound Network Connection Initiated By Script Interpreter`.
- Open this file in a text editor (make sure to open it using `open with text_editor_name`; I am using Mousepad for this. Do not open it with a double click).

![Junk code inside the Js file](/traffic-analysis/WarmCookie-infection/snapshots/js_file_junkcode.png)

- The file is filled with junk code. We can see that it is a paragraph inside comments. The purpose of this is to make the file harder to analyze.
- At the end of the file there is a URL. The URL is divided into multiple strings. It is on `business.checkfedexexp[.]com`, which has the same parent domain (`checkfedexexp[.]com`) as the first domain but a different subdomain (`business`). This is consistent with the Sigma rule `Outbound Network Connection Initiated By Script Interpreter` that VirusTotal matched for this file.

![URL in the Js file](/traffic-analysis/WarmCookie-infection/snapshots/url_contain_in_js_file.png)

- Full URL (reconstructed by joining the string fragments): `hxxps://business.checkfedexexp[.]com/data-privacy?zj=ZzqRKxVRQ&pOd=GEokiOXFwH&sourcedp=tQMQJlIo&Tfocontent=IxGTZjXqxJ&Jr_cid=9464552&L=8174388`
- Now let's hunt for outbound connections to this subdomain.
- To check for outbound connections, we can use this Wireshark filter: `dns.qry.name == "business.checkfedexexp.com"`. There is a DNS query followed by a response about 20 seconds after the malicious zip file was downloaded.

![Dns query to business subdomain](/traffic-analysis/WarmCookie-infection/snapshots/dns_query_to_business_subdomain.png)

- There is an outbound connection, but the traffic was encrypted, so we cannot analyze what was downloaded from or sent to this domain. We can, however, see how much data was received and sent in Wireshark. First, isolate the stream by right-clicking on any packet of the connection and selecting `Conversation Filter --> TCP`, then go to `Statistics --> Conversations`.

![Conversation tab](/traffic-analysis/WarmCookie-infection/snapshots/network_outbound_connection_business_subdomain.png)

- The connection is TLS 1.3. The Client Hello contains the SNI `business.checkfedexexp.com`, which ties this connection to the subdomain found in the JS file.

![TLS Client Hello with SNI](/traffic-analysis/WarmCookie-infection/snapshots/tls_client_hello_business.png)

- About 1.4 MB (1,417,204 bytes of TCP payload) was received from this domain and 650 bytes were sent. The Conversations tab shows 1 MB and 7 kB because it counts whole frames, including ACK-only packets, and rounds the values.
- The server sent all of this data within about 1 second of the handshake. The host then sent nothing more except ACKs and ended the connection with a TCP RST, ACK after about 27 seconds.
- After this connection, the next activity was communication with the C2 server, which we already analyzed earlier.

### Analyzing Reputation of Domain

- Checking the reputation of `quote.checkfedexexp[.]com`

![Virus total reputation of Domain](/traffic-analysis/WarmCookie-infection/snapshots/quote_checkfedexexp_com_virus_total.png)

- 13 vendors out of 92 flag this domain as malicious on VirusTotal.
- Checking the reputation of `business.checkfedexexp[.]com`, the subdomain found in the JS file

![Virus total reputation of the business subdomain](/traffic-analysis/WarmCookie-infection/snapshots/virus_total_business_subdomain.png)

- 14 vendors out of 92 flag this domain as malicious on VirusTotal.

![Whois look up for domain](/traffic-analysis/WarmCookie-infection/snapshots/who_islookup_for_fedex_domain.png)

- The WHOIS lookup record of this domain shows that it was created on `2025-08-19`, but this sample is from `2024-08-15`, which is a gap of nearly 1 year. This could be because the domain expired and was re-registered later. The domain was already resolving in the PCAP in 2024, so it existed at the time of capture.

### Reputation of IPs

![Reputation of IP 1](/traffic-analysis/WarmCookie-infection/snapshots/104-21-55-70.png)

![Reputation of IP 2](/traffic-analysis/WarmCookie-infection/snapshots/172-67-170-159_VT.png)

- The VirusTotal records for both IPs come back clean, and both IPs belong to Cloudflare, which is a CDN. This is a good example of how this infrastructure is abused by adversaries for campaigns. In this case, these IP addresses are used to host the malicious domains that deliver a zip file containing the malicious JS downloader.

### Extracting the Name of the Host and User Account from the Capture

- To extract the name of the user account, we need to look for Kerberos traffic. In the AS-REQ packet, the **CNameString** field contains the name of the account. Machine accounts end with `$`, so use the AS-REQ of the user account. We can also use this Wireshark filter: `kerberos.CNameString`.

![User Account](/traffic-analysis/WarmCookie-infection/snapshots/username_as_req.png)

- User: `plucero`
- To find the name of the host, we need to look at NBNS traffic.

![Hostname from NBNS traffic](/traffic-analysis/WarmCookie-infection/snapshots/hostname_nbns.png)

- Hostname: `DESKTOP-H8ALZBV`

---

## Timeline of Events (UTC)

| Time | Source | Destination | Event |
|---|---|---|---|
| 2024-08-15 00:10:55 | 10.8.15.133 | 10.8.15.4 | DNS query for `quote.checkfedexexp[.]com` (A record) |
| 2024-08-15 00:10:58 | 10.8.15.4 | 10.8.15.133 | DNS response: `quote.checkfedexexp[.]com` resolves to 104.21.55[.]70, 172.67.170[.]159 |
| 2024-08-15 00:10:58 | 10.8.15.133 | 104.21.55[.]70 | HTTP GET `/managements?16553a25e45250a41fd5&endeds=MIGpq&JStx=...` (port 80) |
| 2024-08-15 00:11:04 | 104.21.55[.]70 | 10.8.15.133 | Zip file download completed (HTTP/1.1 200 OK, 2,767,804 bytes) |
| 2024-08-15 00:11:23 | 10.8.15.133 | 10.8.15.4 | DNS query for `business.checkfedexexp[.]com` (A record) |
| 2024-08-15 00:11:24 | 10.8.15.4 | 10.8.15.133 | DNS response: `business.checkfedexexp[.]com` resolves to 172.67.170[.]159, 104.21.55[.]70 |
| 2024-08-15 00:11:24 | 10.8.15.133 | 172.67.170[.]159 | TCP connection opened to port 443 (source port 49800), followed by a TLS 1.3 Client Hello with SNI `business.checkfedexexp[.]com` |
| 2024-08-15 00:11:24 to 00:11:25 | 172.67.170[.]159 | 10.8.15.133 | Encrypted TLS 1.3 data sent to the host: about 1.4 MB (1,417,204 bytes of TCP payload) in roughly 1 second. The host sent 650 bytes in total |
| 2024-08-15 00:11:52 | 10.8.15.133 | 172.67.170[.]159 | Host ends the connection with a TCP RST, ACK about 27 seconds after the last data |
| 2024-08-15 00:11:59 | 10.8.15.133 | 72.5.43[.]29 | HTTP HEAD `/data/0f60a3e7baecf2748b1c8183ed37d1e4` (first request to the C2 server) |
| 2024-08-15 00:11:59 | 10.8.15.133 | 72.5.43[.]29 | HTTP GET `/data/0f60a3e7baecf2748b1c8183ed37d1e4` (payload download) |
| 2024-08-15 00:11:59 to 00:12:00 | 72.5.43[.]29 | 10.8.15.133 | HTTP/1.1 200 OK to the HEAD request, and HTTP/1.1 200 OK (`text/html`) to the GET request with the payload |
| 2024-08-15 00:13:00 | 10.8.15.133 | 72.5.43[.]29 | HTTP GET `/` (first check-in) |
| 2024-08-15 00:13:00 | 72.5.43[.]29 | 10.8.15.133 | HTTP/1.1 200 OK (`text/html`) |
| 2024-08-15 00:13:00 | 10.8.15.133 | 72.5.43[.]29 | HTTP POST `/` (124 bytes) |
| 2024-08-15 00:13:02 | 10.8.15.133 | 72.5.43[.]29 | HTTP POST `/` (305,148 bytes, largest upload to the C2) |
| 2024-08-15 00:13:02 | 10.8.15.133 | 72.5.43[.]29 | HTTP POST `/` (732 bytes) |
| 2024-08-15 00:13:01 to 00:13:03 | 72.5.43[.]29 | 10.8.15.133 | HTTP/1.1 400 Bad Request to all 3 POST requests |
| 2024-08-15 00:13:07 to 00:15:23 | 10.8.15.133 | 72.5.43[.]29 | Beaconing: 25 repeated HTTP GET `/` requests, every 3 to 9 seconds, new source port each time |
| 2024-08-15 00:15:23 to 00:16:15 | 10.8.15.133 | 72.5.43[.]29 | Pause in beaconing: no requests for about 52 seconds |
| 2024-08-15 00:16:15 to 00:42:25 | 10.8.15.133 | 72.5.43[.]29 | Beaconing resumes: 277 repeated HTTP GET `/` requests, every 3 to 9 seconds, until the end of the capture |
| 2024-08-15 00:13:08 to 00:42:26 | 72.5.43[.]29 | 10.8.15.133 | HTTP/1.1 400 Bad Request to all 302 beacon GET `/` requests |

---

## Analyzing the Remaining Alerts (1 to 6)

- Alerts 7 to 12 are tied to the infection. Alerts 1 to 6 are checked here against the PCAP to see if they are related.

### Alert 1: ET DNS Standard query response, Name Error

- Wireshark filter `dns.flags.rcode == 3` returns 27 packets, the same as the alert count.
- The DNS server (10.8.15.4) answered "No such name" for `wpad.lafontainebleu.org` and for `_ldap._tcp` SRV names under `lafontainebleu.org`. WPAD is the lookup a Windows client does to find a proxy configuration, and the SRV names are domain controller lookups. No records exist for these names, so the server answers NXDOMAIN.
- The names are under the internal domain, not the domains from the infection.
- Triage: true positive, benign.

![NXDOMAIN responses](/traffic-analysis/WarmCookie-infection/snapshots/alert_1_name_error.png)

### Alerts 2 and 3: ET INFO Terse Request for .txt and ET INFO Microsoft Connection Test

- Wireshark filter `http.request.uri matches ".txt"` returns two requests from 10.8.15.133:
  - `GET /connecttest.txt` to `www.msftconnecttest.com` (23.205.110.48) at 00:09:45, response `200 OK` (`text/plain`). This is the Windows connectivity check and is what alert 3 matches. It is the same connection (source port 49671) as in the alert table.
  - `GET /assets/Owner/arm/ProcessMAU.txt` to `acroipm2.adobe.com` at 00:22:09, response `200 OK` (`text/plain`). This is an Adobe domain, and the path looks like the Adobe Acrobat/Reader updater.
- Both requests have only a few headers, which is what alert 2 looks for. The alert count of 2 matches these two requests.
- Triage: both true positive, benign.

![Requests for .txt files](/traffic-analysis/WarmCookie-infection/snapshots/alert_2_txt_request.png)

### Alert 4: ET POLICY TLSv1.0 Used in Session

- Wireshark filter `ip.addr == 23.33.138.184 and tcp.port == 49672`
- The Client Hello goes to `go.microsoft.com` (SNI). The TLS record layer shows version `TLS 1.0 (0x0301)`, but the handshake version is `TLS 1.2` and the session is decoded as TLS 1.3 (Server Hello, Change Cipher Spec, Application Data).
- The alert most likely matched the `0x0301` value in the record layer. TLS 1.3 clients keep this legacy value in the first record for compatibility, so the session itself is not TLS 1.0.
- Triage: false positive, benign.

![TLS Client Hello](/traffic-analysis/WarmCookie-infection/snapshots/alert_4_tls_v_1.png)

### Alert 5: GPL RPC kerberos principal name overflow TCP

- Wireshark filter `kerberos and tcp.port == 49676`
- Frame 151 is an AS-REQ from 10.8.15.133 to the domain controller 10.8.15.4 (port 88) at 00:09:46. The `CNameString` is `desktop-h8alzbv$`, which is the computer account of the host (the `$` at the end marks a machine account). The realm is `lafontainebleu.org`.
- The name is 16 characters and the whole Kerberos message is 248 bytes, so nothing is oversized.
- The DC answered with `KRB5KDC_ERR_PREAUTH_REQUIRED`. This is the normal first step: the client sends a request without pre-authentication, the DC asks for it, and the client sends it again with an encrypted timestamp.
- Triage: false positive, benign.

![Kerberos AS-REQ of the computer account](/traffic-analysis/WarmCookie-infection/snapshots/alert_5_kerberos.png)

### Alert 6: GPL ICMP_INFO Destination Unreachable Port Unreachable

- Wireshark filter `icmp.code == 3` returns 11 packets, the same as the alert count. All are sent by 10.8.15.133 to the domain controller 10.8.15.4.
- In the first one (frame 2116), the ICMP message contains the original packet: a DNS response from 10.8.15.4 (UDP port 53) to the host's UDP port 59615. The host had no socket listening on that port when the response arrived, so it replied with port unreachable.
- Filter `icmp.code == 3 and dns` also returns 11 packets, so the original packet inside every one of them is DNS, not only in the first one.

![ICMP port unreachable](/traffic-analysis/WarmCookie-infection/snapshots/alert_6_icmp_port_unreacheable.png)

- This is most likely a late or duplicate DNS response arriving after the host closed the port. It is DNS housekeeping between the host and the DC, not C2 traffic.
- Triage: true positive, benign.


### Alert Triage Summary

| # | Alert | Count | Triage | Reason |
|---|---|---|---|---|
| 1 | ET DNS Standard query response, Name Error | 27 | True positive, benign | NXDOMAIN for `wpad` and `_ldap._tcp` SRV names in the internal domain |
| 2 | ET INFO Terse Request for .txt - Likely Hostile | 2 | True positive, benign | Two `.txt` requests with few headers: the Windows connectivity check and an Adobe update check |
| 3 | ET INFO Microsoft Connection Test | 1 | True positive, benign | `GET /connecttest.txt` to `www.msftconnecttest.com` (Windows connectivity check) |
| 4 | ET POLICY TLSv1.0 Used in Session | 148 | False positive, benign | The TLS 1.0 value is the legacy record layer version; the session is TLS 1.3 |
| 5 | GPL RPC kerberos principal name overflow TCP | 5 | False positive, benign | Normal AS-REQ for the computer account `desktop-h8alzbv$`, nothing oversized |
| 6 | GPL ICMP_INFO Destination Unreachable Port Unreachable | 11 | True positive, benign | The host replied port unreachable to a DNS response from the DC on a closed UDP port |
| 7 | ET POLICY Binary Download Smaller than 1 MB Likely Hostile | 4 | True positive, malicious | `MZ` file of about 155.5 KB downloaded from `72.5.43[.]29` |
| 8 | ET TROJAN Possible Windows executable sent when remote host claims to send html content | 4 | True positive, malicious | `Content-Type` is `text/html` but the body is a Windows executable (the WarmCookie DLL) |
| 9 | ET POLICY PE EXE or DLL Windows file download HTTP | 4 | True positive, malicious | A PE file (DLL) was downloaded over HTTP |
| 10 | ET INFO SUSPICIOUS Dotted Quad Host MZ Response | 4 | True positive, malicious | Bare IP in the `Host` header and an `MZ` response |
| 11 | ETPRO INFO Incorrect Spacing of UA Variable M3 | 307 | True positive, malicious | `Mozilla / 5.0 (compatible; MSIE 6.0; ...)` user agent used by the C2 requests |
| 12 | ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1 | 15 | True positive, malicious | POST requests to the bare IP with a fake browser user agent |

- Count is the number of times the rule fired, not the number of requests. For example, the PCAP has only 3 POST requests (`http.request.method == "POST"`), but alert 12 has a count of 15. So it fired more than once per request, likely because the 305,148 byte POST was split across many TCP segments.

---

## Conclusions

1. The host `DESKTOP-H8ALZBV` (10.8.15.133, user `plucero`) downloaded a malicious zip file (`Invoice 876597035_003.zip`) from `quote.checkfedexexp[.]com`. VirusTotal flags both the domain (13/92) and the zip (27/64).
2. The zip contains an obfuscated JS file (junk comments, URL split into string fragments) with a URL on `business.checkfedexexp[.]com`, a different subdomain of the same parent domain. About 20 seconds after the zip download, the host made an encrypted connection to this subdomain and received about 1.4 MB. The content could not be identified due to encryption.
3. The host then downloaded a DLL from `72.5.43[.]29` using the `Microsoft BITS/7.8` user agent. The server labeled it `text/html`, but it is a Windows executable. It is flagged by 60/71 vendors on VirusTotal and matches Elastic's WarmCookie YARA rules and the Quickbind rule (an alias of WarmCookie), which supports that the file is WarmCookie.
4. `72.5.43[.]29` is assessed as a WarmCookie C2 server. ThreatFox lists it (first seen before this infection, moderate confidence), the DLL it served matches WarmCookie rules, and the host sent three HTTP POST requests and 302 beacon GET requests to it using a fake MSIE 6.0 user agent. This is consistent with WarmCookie C2 communication, and the host should be treated as compromised.
5. Of the 12 alerts, 6 are true positive and malicious (alerts 7 to 12, all tied to the DLL download and C2 traffic), 4 are true positive but benign (alerts 1, 2, 3 and 6: NXDOMAIN lookups, `.txt` update and connectivity checks, DNS port unreachable), and 2 are false positives (alerts 4 and 5: TLS 1.0 legacy record version and a normal Kerberos request for the computer account).
6. Not confirmed by this investigation: whether the JS file and the DLL were executed, what the 1.4 MB download contained, and what the POST data contained. The server answered all POST and beacon GET requests with `400 Bad Request`, so it is not known whether the C2 accepted the data. Traffic was encrypted or encoded and no endpoint or host telemetry was available.

---

## Limitations

- This investigation used the PCAP and the alerts only. No host logs, endpoint telemetry or SIEM data were available.
- Execution of the JS file and of the DLL is not observed. It is inferred from the traffic that follows.
- How the user reached `quote.checkfedexexp[.]com` is unknown. The PCAP has no referrer, email or browser data.
- The connection to `business.checkfedexexp[.]com` is encrypted, so what the host received (about 1.4 MB) is unknown.
- The content of the three POST requests is encoded or encrypted and unknown. The server replied `400 Bad Request` to all POST requests and all beacon GET requests, so the PCAP cannot show whether the C2 accepted the data.
- The DLL was not reverse engineered or run in a sandbox. Its identification relies on VirusTotal results.
- Domain and IP reputation (VirusTotal, ThreatFox, WHOIS) reflects the state when it was checked, not 2024. The WHOIS creation date (2025-08-19) is after the capture.
- The Emerging Threats Pro rule text is not public, so some alert interpretations rely on the traffic itself.