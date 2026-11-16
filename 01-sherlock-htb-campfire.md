# Campfire — Kerberoasting Investigation

Investigated suspected Kerberoasting in an Active Directory environment by correlating Windows Event Logs (Splunk) with workstation Prefetch artifacts.

**Technique:** Kerberoasting — T1558.003

---

## Tools Used

| Tool | What it did here |
|------|------------------|
| **Splunk** | Queried Security logs — Event 4769 (Kerberos service ticket requests) and 4104 (PowerShell script block logging). |
| **PECmd** | Parsed the workstation's Prefetch artifacts into a CSV timeline. |
| **Timeline Explorer** | Reviewed the Prefetch timeline and pinpointed the attacker tool's execution. |

### Tool → Step Map

```
Splunk 4769 -> RC4 service ticket for MSSQLService (alonzo.spire)  -> Kerberoasting
Splunk 4104 -> PowerView recon (Get-NetUser/Computer/GroupMember)  -> enumeration
PECmd (Prefetch) -> Timeline Explorer -> RUBEUS.EXE execution       -> attack tool
```

---

## 1. Kerberos Analysis (Event 4769)

Searched for service ticket requests, excluding `krbtgt` and machine accounts (`$`):

```spl
index="htb-campfire" EventCode=4769
| where Service_Name!="krbtgt" AND NOT like(Service_Name,"%$")
```

One suspicious request stood out — a successful **RC4** service ticket, the classic Kerberoasting signature:

- Account: `alonzo.spire@FORELA.LOCAL`
- Service: `MSSQLService`
- Source IP: `172.17.79.129`
- Encryption: `0x17` (RC4) · Result: `0x0` (Success)

![Splunk 4769](screenshots/01-splunk-4769-kerberoast.png)

RC4 (`0x17`) is the tell — attackers request it because RC4 tickets are the fastest to crack offline.

## 2. PowerShell Analysis (Event 4104)

Pivoted to script block logging for recon activity:

```spl
index="htb-campfire" EventCode=4104
| table _time host Message
| sort _time
```

Found **PowerView** loaded on `Forela-Wkstn001.forela.local` from `alonzo.spire`'s Downloads — AD enumeration functions `Get-NetUser`, `Get-NetComputer`, `Get-NetGroupMember`.

![PowerView 4104](screenshots/02-powerview-4104.png)

## 3. Prefetch Analysis (PECmd → Timeline Explorer)

Parsed the workstation Prefetch to confirm what ran:

```cmd
.\PECmd.exe -d "PATH_TO_PREFETCH" --csv . --csvf campfire-prefetch.csv -q
```

Across 207 Prefetch files, the timeline showed the Kerberoasting tool itself:

- Executable: **RUBEUS.EXE**
- Path: `\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE`
- Execution: `2024-05-21 03:18:08`

![Timeline Explorer Rubeus](screenshots/03-timeline-rubeus.png)

---

## Conclusion

Three correlated artifacts support suspected Kerberoasting on `alonzo.spire`'s workstation: an **RC4 service ticket request** for `MSSQLService` (4769), **PowerView** AD enumeration (4104), and **Rubeus** execution from the user's Downloads (Prefetch).

**Assessment:** Evidence strongly supports suspected Kerberoasting (T1558.003). Successful offline password cracking or further compromise was not confirmed.
