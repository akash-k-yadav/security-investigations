# Fake Authenticator C2

## Source :- MALWARE-TRAFFIC-ANALYSIS.NET
- **Uri** :- `https://www.malware-traffic-analysis.net/2025/01/22/index.html`
- **Author** :- Brad Duncan

## Background 
- Someone contact Soc team and report a coworker accidentally download a suspicious file after seaching google authenticator.
- Based on caller initial information , it was confirmed there was a infection.
- Traffic associated with suspicious event has been retrieved
- And now job is write incident report 

## LAN segment detail given by blog
- **LAN segment range** :- 10.1.17[.]0/24 
- **Domain** :- bluemoontuesday[.]com
- **Active Directory Domain Controller** :- 10.1.17[.]2 - WIN-GSH54QLW48D
- **AD environment name** :- BLUEMOONTUESDAY
- **LAN segment gateway** :- 10.1.17[.]1
- **LAN segment broadcast address** :- 10.1.17[.]255

## Task given by author for this analysis 
- What is the IP address of the infected Windows client?
- What is the mac address of the infected Windows client?
- What is the host name of the infected Windows client?
- What is the user account name from the infected Windows client?
- What is the likely domain name for the fake Google Authenticator page?
- What are the IP addresses used for C2 servers for this infection?

### Note
- capture pcap and exercise own and publish by **Brad Duncan** on his blog website `malware-traffic-analysis.net` 
- i am using pcap and exercise given to learn and pratice traffic analyis. 
- even though author mention tasks for this exercise , i try to do complete analysis.
