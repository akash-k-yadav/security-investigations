# Phishing Email Impersonating SSA, Redirect to icci-sa.com

## Source :- MALWARE-TRAFFIC-ANALYSIS.NET
- **Uri** :- `https://www.malware-traffic-analysis.net/2026/09/14/index.html`
- **Author** :- Brad Duncan
- **Title of Post** :- Backdoor using ScreenConnect from malicious email

## Background
- The author uploaded email and network traffic (.eml and .pcap files) associated with this sample
- The author also uploaded a retrieved binary (.exe) associated with this campaign
- No specific task or question set was provided by the author for this sample

## Objective
Since no task list was given, this investigation was scoped independently. The goal is to:
- Determine whether the email is malicious
- Identify the sender spoofing and impersonation technique used
- Trace the redirect chain from the hyperlink in the email body
- Extract relevant IOCs (sender domain, sender IP, redirect domain, associated IPs)
- Assess what could be confirmed versus what remains unconfirmed from the available network traffic, particularly around the encrypted portions of the capture

## Scope
- This investigation covers phishing email analysis and pcap traffic analysis only
- The retrieved binary (.exe) is out of scope, it is not statically or dynamically analyzed, and is referenced only by hash and reputation where relevant

## Note
- The original .eml, .pcap, and .exe files are not uploaded to this repository, as they belong to the author of the blog
- To download the samples yourself, visit the source link above
- The source author's published title for this case states 'Backdoor using ScreenConnect from malicious email.' This finding is not independently confirmed within the scope of this investigation and is reported here as Unconfirmed, based on the available PCAP and email evidence only.