# Spearphishing Link Credential Theft knu.edu.com

## Source :- MALWARE-TRAFFIC-ANALYSIS.NET
- **Uri** :- `https://www.malware-traffic-analysis.net/2020/05/05/index.html`
- **Author** :- Brad Duncan

## Background 
- Author uploaded four email samples with network traffic associated with them (.eml and .pcap files).
- This writeup is about the second email sample.
- No specific task or question set was provided by the author for this sample.

## Objective
Since no task list was given, this investigation was scoped independently. The goal is to:
- Determine whether the email is malicious
- Identify the phishing technique used (credential harvesting, fake login page, etc.)
- Extract relevant IOCs (sender domain, spoofed display name, malicious URLs, attachment hash if present)
- Assess what a user would expose if they interacted with the email as intended by the attacker

## Note
- The original .eml and .pcap files are not uploaded to this repository, as they belong to the author of the blog.
- To download the samples yourself, visit the source link above.