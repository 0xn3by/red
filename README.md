<h1>red</h1>

<p>
  Offensive security lab work by Akash Govind (<code>0xn3by</code>):<br>
  API penetration testing, secure code review, CTF walkthroughs, and privilege escalation, all against authorized labs.
</p>

<p>
  <a href="https://tryhackme.com/p/neby.tech"><img alt="TryHackMe profile neby.tech" src="https://img.shields.io/badge/TryHackMe-neby.tech-212C42?logo=tryhackme&logoColor=white"></a>
  <a href="https://medium.com/@0xaksh"><img alt="Medium @0xaksh" src="https://img.shields.io/badge/Medium-@0xaksh-000000?logo=medium&logoColor=white"></a>
  <a href="https://github.com/0xn3by"><img alt="GitHub 0xn3by" src="https://img.shields.io/badge/GitHub-0xn3by-181717?logo=github&logoColor=white"></a>
</p>

<p>
  <a href="#labs"><img alt="3 labs" src="https://img.shields.io/badge/labs-3-58A6FF"></a>
  <a href="crapi/report.md"><img alt="crAPI: 7 findings, 1 Critical, 2 High, 4 Medium" src="https://img.shields.io/badge/crAPI-7%20findings%20(1C%20%7C%202H%20%7C%204M)-F5A524"></a>
  <a href="owasp-nodegoat/report.md"><img alt="NodeGoat: 7 findings, 4 High, 3 Medium" src="https://img.shields.io/badge/NodeGoat-7%20findings%20(4H%20%7C%203M)-F5A524"></a>
  <a href="#tryhackme"><img alt="7 TryHackMe rooms" src="https://img.shields.io/badge/TryHackMe-7%20rooms-FF3B3B"></a>
  <a href="#rules-of-engagement"><img alt="Authorized labs only" src="https://img.shields.io/badge/scope-authorized%20labs%20only-F5A524"></a>
</p>

Everything in this repository was done against intentionally vulnerable labs, either self-hosted or provided by authorized training platforms. Nothing here targets third-party or production systems.

## Labs

| Folder | Target | What's inside | Start here |
| --- | --- | --- | --- |
| [`crapi/`](crapi/) | OWASP crAPI, self-hosted in Docker | API pentest against the OWASP API Security Top 10 (2023): 7 confirmed findings (1 Critical, 2 High, 4 Medium) covering BOLA, JWT alg:none bypass, SSRF, NoSQL injection, business-logic abuse, with CVSS 3.1 scores and screenshot evidence | [`crapi/report.md`](crapi/report.md) · [Medium write-up](https://medium.com/@0xaksh/how-i-found-7-vulnerabilities-in-owasp-crapi-and-the-reasoning-behind-each-one-6a12fdaa7943) |
| [`owasp-nodegoat/`](owasp-nodegoat/) | OWASP NodeGoat source, commit `c5cb68a` | Manual source-to-sink secure code review against the OWASP Top 10 (2021): 7 findings (4 High, 3 Medium) covering SSJS `eval` injection, NoSQL `$where` injection, stored XSS, IDOR, missing function-level authz, CSRF, session misconfiguration, with line-exact permalinks and CVSS 3.1 scores | [`owasp-nodegoat/report.md`](owasp-nodegoat/report.md) |
| [`tryhackme/`](tryhackme/) | [TryHackMe](https://tryhackme.com/p/neby.tech) rooms | Walkthroughs by difficulty (Easy/Medium/Hard): enumeration, exploitation, privilege escalation | [`tryhackme/Challenges/`](tryhackme/Challenges/) · [Profile](https://tryhackme.com/p/neby.tech) |

## crAPI

A full API penetration test of OWASP crAPI with reproducible request/response evidence for every finding.

- **Read the story:** [How I found 7 vulnerabilities in OWASP crAPI, and the reasoning behind each one](https://medium.com/@0xaksh/how-i-found-7-vulnerabilities-in-owasp-crapi-and-the-reasoning-behind-each-one-6a12fdaa7943) (Medium)
- **Read the report:** [`crapi/report.md`](crapi/report.md) has the executive summary, findings table, and per-finding detail.
- **Check the evidence:** [`crapi/evidence.md`](crapi/evidence.md) plus annotated screenshots in [`crapi/evidence/`](crapi/evidence/).

## OWASP NodeGoat

A manual secure code review of OWASP NodeGoat, tracing each vulnerability from a request-controlled source to the line that renders, queries, or evaluates it. Two findings (IDOR, NoSQL injection) were also confirmed by exploiting a local instance.

- **Read the report:** [`owasp-nodegoat/report.md`](owasp-nodegoat/report.md) has the executive summary, findings table, and per-finding fixes.
- **Follow the code:** [`owasp-nodegoat/code-reference.md`](owasp-nodegoat/code-reference.md) has verbatim source/sink snippets with permalinks to the pinned commit.
- **Check the evidence:** [`owasp-nodegoat/evidence.md`](owasp-nodegoat/evidence.md) has the trace for each finding.

## TryHackMe

Room walkthroughs from my TryHackMe profile, [**neby.tech**](https://tryhackme.com/p/neby.tech).

| Difficulty | Room |
| --- | --- |
| Easy | [Basic Pentesting](tryhackme/Challenges/Easy/basic-pentesting.md) |
| Easy | [Glitch](tryhackme/Challenges/Easy/glitch.md) |
| Medium | [CMSpit](tryhackme/Challenges/Medium/CMsplit.md) |
| Medium | [Frank & Herby Make an App](tryhackme/Challenges/Medium/Frank_%26_Herby_Make_an_App.md) |
| Medium | [Security Footage](tryhackme/Challenges/Medium/security_footage.md) |
| Medium | [Valenfind](tryhackme/Challenges/Medium/valenfind.md) |
| Hard | [BreachBlocker Unlocker](tryhackme/Challenges/Hard/BreachBlocker%20Unlocker.md) |

## History

`crapi/` and `tryhackme/` were merged in from their original repositories with full commit history preserved. `owasp-nodegoat/` was written directly in this repository. To see a lab's history, run `git log -- <folder>`, for example `git log -- crapi`.

## Rules of Engagement

> [!IMPORTANT]
> Any credentials, keys, or tokens that appear in the write-ups belong to lab targets, not real systems. All testing was done against self-hosted lab instances or authorized training platforms.
