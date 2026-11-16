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

<img width="1914" height="950" alt="01-splunk-4769-kerberoast" src="https://github.com/user-attachments/assets/002112e8-9117-4a54-b271-f30f8d03a484" />


RC4 (`0x17`) is the tell — attackers request it because RC4 tickets are the fastest to crack offline.

## 2. PowerShell Analysis (Event 4104)

Pivoted to script block logging for recon activity:

```spl
index="htb-campfire" EventCode=4104
| table _time host Message
| sort _time
```

Found **PowerView** loaded on `Forela-Wkstn001.forela.local` from `alonzo.spire`'s Downloads — AD enumeration functions `Get-NetUser`, `Get-NetComputer`, `Get-NetGroupMember`.
<img width="1915" height="772" alt="02-powerview-4104" src="https://github.com/user-attachments/assets/852dccf4-93fb-4738-8a0a-4f59c40da8a4" />


## 3. Prefetch Analysis (PECmd → Timeline Explorer)

Parsed the workstation Prefetch to confirm what ran:

```cmd
.\PECmd.exe -d "PATH_TO_PREFETCH" --csv . --csvf campfire-prefetch.csv -q
```

Across 207 Prefetch files, the timeline showed the Kerberoasting tool itself:

- Executable: **RUBEUS.EXE**
- Path: `\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE`
- Execution: `2024-05-21 03:18:08`

<img width="1589" height="930" alt="03-timeline-rubeus" src="https://github.com/user-attachments/assets/5dce6dc4-5a8a-4a60-9253-bb08bab1559e" />


---

## Conclusion

Three correlated artifacts support suspected Kerberoasting on `alonzo.spire`'s workstation: an **RC4 service ticket request** for `MSSQLService` (4769), **PowerView** AD enumeration (4104), and **Rubeus** execution from the user's Downloads (Prefetch).

**Assessment:** Evidence strongly supports suspected Kerberoasting (T1558.003). Successful offline password cracking or further compromise was not confirmed.
