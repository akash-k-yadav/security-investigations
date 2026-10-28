# Boogeyman 3 - Lurking in the Dark

## Source :- TRYHACKME
- **Uri** :- https://tryhackme.com/room/boogeyman3
- **Room** :- Boogeyman 3
- **Difficulty (as listed)** :- Medium

## Background
- Scenario company is Quick Logistics LLC, which uses a managed security service provider to run its SOC
- The threat actor "Boogeyman" is described as having compromised one employee earlier without tripping any defences, then staying dormant
- Using that initial email access, the actor targeted the CEO, Evan Hutchinson, with a phishing email
- The CEO opened the attachment despite being sceptical, saw nothing happen, and reported the email to the security team
- The security team inspected the CEO's workstation and found:
  - the email attachment in the Downloads folder
  - a file inside the ISO payload (shown to the reader as an image in the room; not reproduced here)
- The security team presumed the incident occurred between **29 and 30 August 2023** (a presumed window given at the start, not a confirmed one)

## Dataset / Environment
- Only logs are provided, in an Elastic Stack lab machine accessed through a web browser
- The phishing email and the attachment (including the ISO payload) are not provided, so neither can be analysed directly

## Task given
- Analyse and assess the impact of the compromise

## Objective
The room is built around a set of guided questions. This investigation does not follow them. It is scoped as a reconstruction of what happened, from the CEO's workstation onward:
- Reconstruct the attack chain from the opened attachment
- Establish what the attacker accessed, ran, and took, and where they went next
- Separate what the logs confirm from what is inferred
- Record what could not be resolved from the available data


## Note
- The room's logs belong to TryHackMe and are not uploaded to this repository
- Screenshots in `snapshots/` are my own captures from the lab while investigating
- To work through the same data, use the source link above and the lab provided with the room
- The presumed incident window comes from the room scenario