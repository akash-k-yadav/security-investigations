# Warm-Cookie Infection

## Source :- MALWARE-TRAFFIC-ANALYSIS.NET
- **Uri** :- https://www.malware-traffic-analysis.net/2024/08/15/index.html
- **Author** :- Brad Duncan

## Background 
- Alert in the Enviroment 
```
ST  CNT  Date/Time         Src IP         SPort  Dst IP         DPort  Pr  Event Message
RT  27   2024-08-15 00:09  10.8.15.4      53     10.8.15.133    53383  17  ET DNS Standard query response, Name Error
RT  2    2024-08-15 00:09  10.8.15.133    49671  23.205.110.48  80     6   ET INFO Terse Request for .txt - Likely Hostile
RT  1    2024-08-15 00:09  10.8.15.133    49671  23.205.110.48  80     6   ET INFO Microsoft Connection Test
RT  148  2024-08-15 00:09  10.8.15.133    49672  23.33.138.184  443    6   ET POLICY TLSv1.0 Used in Session
RT  5    2024-08-15 00:09  10.8.15.133    49676  10.8.15.4      88     6   GPL RPC kerberos principal name overflow TCP
RT  11   2024-08-15 00:10  10.8.15.133    -      10.8.15.4      -      1   GPL ICMP_INFO Destination Unreachable Port Unreachable
RT  4    2024-08-15 00:12  72.5.43.29     80     10.8.15.133    49810  6   ET POLICY Binary Download Smaller than 1 MB Likely Hostile
RT  4    2024-08-15 00:12  72.5.43.29     80     10.8.15.133    49810  6   ET TROJAN Possible Windows executable sent when remote host claims to send html content
RT  4    2024-08-15 00:12  72.5.43.29     80     10.8.15.133    49810  6   ET POLICY PE EXE or DLL Windows file download HTTP
RT  4    2024-08-15 00:12  72.5.43.29     80     10.8.15.133    49810  6   ET INFO SUSPICIOUS Dotted Quad Host MZ Response
RT  307  2024-08-15 00:13  10.8.15.133    49818  72.5.43.29     80     6   ETPRO INFO Incorrect Spacing of UA Variable M3
RT  15   2024-08-15 00:13  10.8.15.133    49818  72.5.43.29     80     6   ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1

```

## LAN segment detail given by blog
- **LAN segment range** :- 10.8.15[.]0/24 
- **Domain** :- lafontainebleu[.]org
- **Active Directory Domain Controller** :- 10.8.15[.]4 (WIN-JEGJIX7Q9RS)
- **AD environment name** :- LAFONTAINBLEU
- **LAN segment gateway** :- 10.8.15[.]1
- **LAN segment broadcast address** :- 10.8.15[.]255
## Task given by author for this analysis 
- Write an incident report from the pcap and the alerts
- Required sections: Executive Summary, Victim Details (hostname, IP, MAC, Windows user account), Indicators of Compromise (IPs, domains, URLs, SHA256 of extracted binaries)
