# HTB Sherlock: Logjammer (Easy)

## Scenario

An insider, user **CyberJunkie** on host **DESKTOP-887GK2L**, tampered with the system. The evidence is five Windows event logs: Security, PowerShell-Operational, System, Windows Defender-Operational and Windows Firewall. All times are UTC.

## Tools

| Tool | What it did in this lab |
|---|---|
| Splunk (self-hosted) | Searched and filtered every log, using `stats` and `table` to shrink large result sets. |
| Custom EVTX to JSONL converter (Python) | Splunk cannot read raw `.evtx`, so each event was converted to one JSON line with its fields. Uploaded as sourcetype `logjammer`. |
| Microsoft docs | Looked up the audit subcategory GUID. |

**Tool to step map**

| Step | Splunk search |
|---|---|
| Task 1: first logon | Security `4624` |
| Task 2: firewall rule | Firewall `2004` |
| Task 3: audit policy | Security `4719` |
| Task 4: PowerShell command | PowerShell `4104` |
| Task 5: antivirus detection | Defender `1117` |
| Task 6: log cleared | System `104` |
| Additional findings | Security `4698`, Security `1102` |

Query base for every search below: `source="logjammer_events.jsonl" host="LAFRANCE" sourcetype="logjammer"`

## Walkthrough

### Task 1: When did CyberJunkie first successfully log on?

**Answer:** `2023-03-27 14:37:09` UTC (`27/03/2023 14:37:09` in the answer box's day-first format)

`4624` is a successful logon, and `TargetUserName` is the account that logged on. Each logon appears as two events at the same second (an elevated and a limited token linked by `TargetLinkedLogonId`), so there are two logons, 14:37:09 and 14:38:32. The first is the answer.

```
... log="Security" EventID=4624 TargetUserName="CyberJunkie" LogonType=2
```

(No screenshot for this task. Add one if you have it.)

### Task 2: Name of the firewall rule that was added

**Answer:** `Metasploit C2 Bypass`

EventID `2004` in the Firewall log means a rule was added. It was created through `mmc.exe` by CyberJunkie's SID (`...-1001`), with `Direction: 2` (outbound) and `RemotePorts: 4444` to any address. Filtering by that SID cut 490 events down to 29.

```
... log="Windows Firewall-Firewall" EventID=2004 ModifyingUser="S-1-5-21-3393683511-3463148672-371912004-1001"
```

<img width="1913" height="885" alt="task2-firewall-rule" src="https://github.com/user-attachments/assets/dd037116-dd62-49c8-a0d4-36627992c17f" />


### Task 3: Subcategory of the changed audit policy

**Answer:** `Other Object Access Events`

Security EventID `4719` is "system audit policy was changed" (14:50:03). The event only holds a GUID, `{0CCE9227-69AE-11D9-BED3-505054503030}`. Microsoft's subcategory table maps it to Other Object Access Events, which covers Task Scheduler jobs.

```
... log="Security" EventID=4719
```

<img width="1913" height="927" alt="task3-audit-policy" src="https://github.com/user-attachments/assets/3bb6a3cc-3290-436b-ac20-95814382da66" />


### Task 4: PowerShell command the user executed

**Answer:** `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1`

PowerShell EventID `4104` records script blocks. There are 381 events but only 28 distinct `ScriptBlockText` values. All of them were noise (Defender module code, the console `prompt`, and similar) except one single line, which was the command the user typed. It ran at 14:58:33. The `4103` events show the same command split into parameters.

```
... log="Powershell-Operational" EventID=4104
... log="Powershell-Operational" EventID=4104 | stats count by ScriptBlockText
```

<img width="1911" height="848" alt="task4-powershell-4104-event" src="https://github.com/user-attachments/assets/264b45b0-8124-4b2e-b8d0-a772279f3061" />


<img width="1919" height="933" alt="task4-powershell-noise" src="https://github.com/user-attachments/assets/84469686-a5b7-4ff3-b6ef-9da02cfebf04" />


<img width="1915" height="48" alt="task4-powershell-answer" src="https://github.com/user-attachments/assets/74734376-d880-41fe-acf6-d7d04cbd5e05" />


### Task 5: Tool identified as malware by the antivirus

**Answer:** `SharpHound`

Defender EventID `1117` is "action taken". Grouping by threat name gave two results: `Trojan:Win64/Meterpreter.B` (69) and `HackTool:MSIL/SharpHound!MSR` (2). The question asks for a tool, so the answer is the HackTool detection. Meterpreter is a payload, classified as a Trojan. SharpHound was quarantined at 14:42:48 from `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`, downloaded from GitHub.

```
... log="Windows Defender-Operational" EventID=1117 | stats count by "Threat Name"
... EventID=1117 "Threat Name"="HackTool:MSIL/SharpHound!MSR"
```

<img width="1914" height="741" alt="task5-threat-names" src="https://github.com/user-attachments/assets/f8e41b68-0326-4998-9534-6dc4c57fb41e" />


<img width="1914" height="741" alt="task5-threat-names" src="https://github.com/user-attachments/assets/e52a0da7-c4d6-4e7a-8f2e-8c4707c5a138" />


### Task 6: Event log file that was cleared

**Answer:** `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`, cleared at `2023-03-27 15:01:56` UTC

EventID `104` (System log) means a log was cleared, and `Channel` names which one. There are 15 events. Fourteen are the Sysmon log, all on 24 March, days before the activity above. The single Firewall clear at 15:01:56 on 27 March comes right after the firewall, audit, task and PowerShell activity.

```
... log="System" EventID=104 | stats count by Channel, _time
```

<img width="1910" height="750" alt="task6-log-cleared" src="https://github.com/user-attachments/assets/2ca1de90-12e8-481d-8d6b-8fe5d6840d9c" />


## Summary

On 27 March the Security log was cleared by CyberJunkie at 14:36:45, which wiped earlier logon records. He logged on at 14:37:09, and at 14:42:48 Defender quarantined SharpHound, a tool that maps Active Directory attack paths, from his Downloads folder.

At 14:44:43 he added an outbound firewall rule named "Metasploit C2 Bypass" for port 4444, then at 14:50:03 changed the audit policy for Other Object Access Events. At 14:51:21 he created a daily scheduled task, `HTB-AUTOMATION`, that runs `Automation-HTB.ps1`.

At 14:58:33 he ran `Get-FileHash` on that script, and at 15:01:56 he cleared the Firewall log, which held the rule he had just added.

## Additional Findings

**Scheduled task.** Security `4698` at 14:51:21 shows task `\HTB-AUTOMATION`, created by CyberJunkie. It runs `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1` daily from 09:00 with the argument `-A cyberjunkie@hackthebox.eu`.

```
... log="Security" EventID=4698
```

<img width="1910" height="934" alt="extra1-scheduled-task" src="https://github.com/user-attachments/assets/9161d830-ad0a-403d-b06f-fabbfaaa2b0e" />


**Security log cleared.** Security `1102` at 14:36:45, by CyberJunkie (`SubjectLogonId 0x25235`). It was cleared 24 seconds before the first remaining logon, so the 14:37:09 logon is the first one still in the log, not necessarily the first one that happened.

```
... log="Security" EventID=1102
```

![Security log cleared](shots/extra2-security-cleared.png)
