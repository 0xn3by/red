# red

Offensive security lab work by Akash Govind (0xn3by). Everything here was done against intentionally vulnerable labs, either self-hosted or provided by authorized training platforms. Nothing in this repository targets third-party or production systems.

## Labs

| Folder | Target | What's inside | Start here |
| --- | --- | --- | --- |
| [`crapi/`](crapi/) | OWASP crAPI, self-hosted in Docker | API pentest against the OWASP API Security Top 10 (2023): 7 confirmed findings (1 Critical, 2 High, 4 Medium) covering BOLA, JWT alg:none bypass, SSRF, NoSQL injection, business-logic abuse, with CVSS 3.1 scores and screenshot evidence | [`crapi/report.md`](crapi/report.md) |
| [`tryhackme/`](tryhackme/) | TryHackMe rooms | Walkthroughs by difficulty (Easy/Medium/Hard): enumeration, exploitation, privilege escalation | [`tryhackme/Challenges/`](tryhackme/Challenges/) |

## History

Each folder was merged in from its original repository with full commit history preserved. To see a lab's history, run `git log -- <folder>`, for example `git log -- crapi`.

## Rules of engagement

Any credentials, keys, or tokens that appear in the write-ups belong to lab targets, not real systems.
