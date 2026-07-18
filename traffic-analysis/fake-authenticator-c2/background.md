# Fake Authenticator C2

## Source :- MALWARE-TRAFFIC-ANALYSIS.NET
- **Uri** :- `https://www.malware-traffic-analysis.net/2025/01/22/index.html`
- **Author** :- Brad Duncan

## Background 
- Someone contacted the SOC team and reported that a coworker had accidentally downloaded a suspicious file after searching for Google Authenticator.
- Based on the caller's initial information, it was confirmed there was an infection.
- Traffic associated with the suspicious event was retrieved.
- The job is to write an incident report based on this traffic.

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
-