# HTB Sherlock: Knock Knock

**Difficulty:** Medium | **Category:** DFIR | **Evidence:** `Capture.pcap` | **Tools:** Wireshark, PowerShell, VirusTotal, GitHub (OSINT)

## Tools
| Tool | What it did here |
|---|---|
| Wireshark | Found the SYN scan, FTP password spray, FTP control/data streams, hidden-port session and the HTTP ransomware download; exported the .docx and the ransomware zip |
| PowerShell | `Get-FileHash` to get the ransomware's SHA256 |
| VirusTotal | Hash lookup to identify the ransomware family |
| GitHub | OSINT on the repo named in `.reminder` to find the leaked SSH password |

## Summary
On 2023-03-21, attacker **3.109.209.43** SYN-scanned Forela's internet-facing dev server (**172.31.39.46**) and then password-sprayed FTP, getting in as `tony.shephard`. From tony's FTP folder they took a **knockd** config that revealed a port-knock sequence for a hidden FTP service on **24456**, along with credentials for `abdullah.yasin`. On the hidden service they escaped the chroot jail and stole AWS credentials, internal documents, `/etc/passwd` and a note pointing to a GitHub repo. That repo's commit history leaked the SSH password for `cyberjunkie`. Over SSH, the attacker downloaded the **GonnaCry** ransomware with `wget`.

## Findings
| # | Question | Answer |
|---|---|---|
| 1 | Open ports found during enumeration | 21, 22, 3306, 6379, 8086 |
| 2 | UTC time the attack started | 2023-03-21 10:42:23 (first SYN) |
| 3 | MITRE technique for initial access | T1110.003 (Password Spraying) |
| 4 | Credentials for initial foothold | tony.shephard:Summer2023! |
| 5 | Malicious IP used for initial access | 3.109.209.43 |
| 6 | File with config data and creds | .backup |
| 7 | Critical service port | 24456 |
| 8 | Technique to reach the critical service | Port knocking |
| 9 | Ports needed to reach the critical service | 29999, 50234, 45087 |
| 10 | UTC time knock-port interaction ended | **TODO** |
| 11 | Valid creds for the critical service | abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad |
| 12 | UTC time of access to the critical server | 2023-03-21 11:00:01 |
| 13 | Abdullah's AWS AccountID:Password | 391629733297:yiobkod0986Y[adij@IKBDS |
| 14 | Deadline for hiring developers | 30/08/2023 |
| 15 | CEO's scheduled arrival in Pakistan | 08/03/2023 |
| 16 | Non-root user with /bin/bash | cyberjunkie |
| 17 | File that led to SSH access | /opt/reminders/.reminder |
| 18 | SSH password | YHUIhnollouhdnoamjndlyvbl398782bapd |
| 19 | Ransomware download URL | http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_server.zip |
| 20 | Download tool and version | Wget/1.21.2 |
| 21 | Ransomware name | GonnaCry |

## Timeline (UTC, 2023-03-21)
| Time | Event |
|---|---|
| 10:42:23 | SYN scan begins from 3.109.209.43 |
| 10:50:20 | FTP (21) login as tony.shephard after password spray |
| 10:52:03 | `RETR .backup` (knockd config and creds) |
| 10:55:13 | `RETR fetch.sh` (hardcoded MySQL creds) |
| **TODO** | Port-knock sequence 29999 → 50234 → 45087 ends |
| 11:00:01 | Login to hidden FTP (24456) as abdullah.yasin |
| 11:00–11:10 | Chroot escape; exfiltrates `.archived.sql`, docx, `reminder.txt`, `/etc/passwd`, `/opt/reminders/.reminder` |
| 11:42:34 | `wget` downloads `Ransomware2_server.zip` |

## Investigation

### 1. Reconnaissance: SYN scan
3.109.209.43 sent SYNs to ports in order (1, 2, 3...), using a new random source port for each probe. Closed ports answered RST/ACK and open ports answered SYN/ACK; the scanner then reset the connection without completing it (a half-open scan). The SYNs to ports 1–7 left within about 0.5 ms of each other, so this was an automated tool. nmap randomizes port order by default, which suggests `nmap -r` or another scanner.

`ip.src == 3.109.209.43 && tcp.flags.syn == 1 && tcp.flags.ack == 0`: first SYN at **10:42:23.708988** (frame 76081).

![Scan start](08-knock-knock-screenshots/scan-start-syn.png)

`ip.addr == 3.109.209.43 && tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.len == 0`: open ports **21, 22, 3306, 6379, 8086**.

![Open ports](08-knock-knock-screenshots/open-ports-synack.png)

### 2. Initial access: FTP password spray (T1110.003)
`ftp.request.command == "USER" || ftp.request.command == "PASS"` shows the attacker trying seasonal passwords (`Spring/Summer/Autumn/Winter` + 2021–2023 + `!`) across several users on port 21.

![Spray attempts](08-knock-knock-screenshots/ftp-login-attempts-attacker.png)

Other IPs tried anonymous logins and common passwords against `www` on 2023-03-20/21. That's unrelated internet noise.

![Other IPs](08-knock-knock-screenshots/ftp-other-ip-attempts.png)

`ftp.response.code == 230` → Follow TCP Stream: **tony.shephard / Summer2023!** succeeded at 10:50:20 (vsFTPd 3.0.5).

![FTP login success](08-knock-knock-screenshots/ftp-login-success-stream.png)

### 3. Loot from tony's FTP
`ftp.request.command == "RETR"`: the attacker downloaded `.backup` and `fetch.sh`.

![RETR](08-knock-knock-screenshots/ftp-retr-files.png)

File contents travel on passive-mode data ports, which the control stream announces in its `229 Entering Extended Passive Mode (|||port|)` replies. `tcp.port == 11365` → `.backup` is a **knockd** config. Knocking **29999 → 50234 → 45087** opens TCP **24456**, and a comment in the file leaks `abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad`.

![.backup](08-knock-knock-screenshots/ftp-data-backup-port.png)

`fetch.sh` (port 63669) contains hardcoded MySQL credentials: `tony.shephard` / `GameOfthronesRocks7865!` @ 3.13.65.234:3306.

The attacker then used the knock sequence (filter `tcp.port in {29999, 50234, 45087}`; the last packet marks when the knock ended at **TODO**), which opened 24456 (T1205.001: Port Knocking).

### 4. Hidden critical service: FTP on 24456
Wireshark doesn't decode 24456 as FTP, so the session was read with `tcp.port == 24456 && tcp.len > 0` and Follow TCP Stream. `abdullah.yasin` logged in at **11:00:01**.

![Hidden service USER/PASS](08-knock-knock-screenshots/critical-service-user-pass.png)

![Hidden service login](08-knock-knock-screenshots/critical-service-login.png)

The attacker then moved outside the FTP root (escaping the chroot jail) and downloaded these files:

| File | Data port | Contents |
|---|---|---|
| `.archived.sql` | 25381 | MySQL dump of `AWS_EC2_DEV`; leaks AWS account ID `391629733297` and password |
| `Tasks to get Done.docx` | 27862 | Deadline chart (e.g. hire 20 developers by 8/30/2023) |
| `reminder.txt` | 5488 | CEO Happy Grunwald arrives in Lahore, Pakistan on 8 March 2023 |
| `/etc/passwd` | 19174 | Users with `/bin/bash`: root, ubuntu, **cyberjunkie** |
| `/etc/shadow` | n/a | Failed (550) |
| `/opt/reminders/.reminder` | 44249 | "Clean up the github repo... sensitive data could have been leaked" |

![AWS creds](08-knock-knock-screenshots/archived-sql-aws.png)

The .docx was exported with Follow TCP Stream → Raw → Save as.

![docx export](08-knock-knock-screenshots/tasks-docx-raw-export.png)

![docx deadline](08-knock-knock-screenshots/tasks-docx-deadline.png)

![reminder.txt](08-knock-knock-screenshots/reminder-txt.png)

![.reminder](08-knock-knock-screenshots/opt-reminders-reminder.png)

### 5. SSH access via GitHub leak (OSINT)
`.reminder` pointed to GitHub. In the repo **forela-finance/forela-dev**, an early commit of `internal-dev.yaml` (an Ansible playbook) hardcoded `ssh_password` for **cyberjunkie**. A later commit replaced it with `{{ ssh_password }}`, but the password stayed in the commit history. SSH is encrypted, so the login itself isn't readable in the pcap.

![GitHub leak](08-knock-knock-screenshots/github-leaked-ssh-password.png)

### 6. Ransomware download
`http.request && ip.src == 172.31.39.46` → at **11:42:34** (frame 213543), `Wget/1.21.2` downloaded
`http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_server.zip`. The other requests in this view are normal EC2 metadata and apt traffic.

![Ransomware download](08-knock-knock-screenshots/ransomware-download-http.png)

The zip was exported with File → Export Objects → HTTP and hashed. Its SHA256 matched VirusTotal (37/66 detections), and its 96 bundled files all sit under `src/GonnaCry/`, so the ransomware is **GonnaCry**, an open-source Linux ransomware.

![SHA256](08-knock-knock-screenshots/ransomware-sha256-powershell.png)

![VirusTotal](08-knock-knock-screenshots/virustotal-details.png)

![GonnaCry files](08-knock-knock-screenshots/virustotal-relations-gonnacry.png)

## IOCs
- Attacker: `3.109.209.43`
- Ransomware host: `13.233.179.35`, URL `http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_server.zip`
- SHA256: `2bf75995bd621a7f89744df3d7b4f0e734f38a43fd0782c1a9bc9b7ddb1b8fae`
- MD5: `ae68f823523b1093c09c6f4e39fedcfc`
- Compromised accounts: tony.shephard, abdullah.yasin, cyberjunkie; AWS account 391629733297

## MITRE ATT&CK
- T1046: Network Service Discovery (SYN scan)
- T1110.003: Password Spraying (FTP)
- T1552.001: Unsecured Credentials in Files (`.backup`, `fetch.sh`, `.archived.sql`)
- T1205.001: Traffic Signaling: Port Knocking
- T1593.003: Search Open Websites/Domains: Code Repositories (GitHub)
- T1021.004: Remote Services: SSH
- T1105: Ingress Tool Transfer (`wget`)
- T1486: Data Encrypted for Impact (GonnaCry)

## Recommendations
- Rotate every leaked credential (FTP, MySQL, AWS, SSH) and purge secrets from the Git history.
- Enforce lockout and MFA on internet-facing services; replace FTP with SFTP.
- Don't rely on port knocking as a security control, and don't keep configs with creds in user home directories.
- Fix the vsFTPd chroot configuration so users can't leave their home directories.
- Isolate the host and block 3.109.209.43 and 13.233.179.35.
