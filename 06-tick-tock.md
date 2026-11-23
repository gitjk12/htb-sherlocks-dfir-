# HTB Sherlock: Tick Tock (Medium)

## Scenario

Gladys received a fake IT support call and let the caller connect through TeamViewer. The attacker then uploaded a Merlin C2 agent, tried to lock the drive with BitLocker and changed the system clock with a PowerShell script to confuse the timeline. The evidence is 74 Windows event logs (Sysmon, Security, PowerShell, Defender and others) plus the TeamViewer logs. Host: **DESKTOP-R30EAMH**, victim user: **gladys**.

## Tools

| Tool | What it did in this lab |
|---|---|
| Splunk (self-hosted) | Searched and filtered every event log; `stats` and `table` shrank large result sets. |
| Custom EVTX to JSONL converter (Python) | Splunk cannot read raw `.evtx`, so each event was converted to one JSON line (37,773 events). Uploaded as sourcetype `ticktock`. |
| Notepad | Read the plain-text TeamViewer logs (`TeamViewer15_Logfile.log`), which are not event logs. |
| Python (base64) | Decoded the Base64 `powershell.exe -e` commands (UTF-16LE). |

**Tool to step map**

| Step | Tool / log |
|---|---|
| Task 1: C2 executable | Splunk, Sysmon `1`/`3` |
| Task 2: session ID | TeamViewer log (Notepad) |
| Task 3: BitLocker password | Splunk, Sysmon `1`, Python decode |
| Task 4: attacker name | TeamViewer log (Notepad) |
| Task 5: C2 IP | Splunk, Sysmon `3` |
| Task 6: Defender category | Splunk, Defender log |
| Task 7: time script name | Splunk, Sysmon `11` |
| Task 8: connection start time | TeamViewer log (Notepad) |
| Task 10: time changes | Splunk, Security `4616` |
| Task 11: victim SID | Splunk, Security log |

Query base for every search below: `source="ticktock_events.jsonl" host="LAFRANCE" sourcetype="ticktock"`

## Walkthrough

### Task 1: Name of the executable uploaded as the C2 agent

**Answer:** `merlin.exe`

Sysmon EventID `1` (process created) grouped by `Image` shows three candidates: `KAPE.EXE`, `kape.exe` and `merlin.exe`. The two KAPE files are a known forensic collection tool in a `KAPE` folder (the responders' evidence collection) and made only 5 and 3 connections. `merlin.exe` is unknown software on `gladys`'s Desktop with **357** network connections, the earliest to an external Amazon EC2 address (52.56.142.81:80), which matches C2 beaconing.

```
EventID=3 | stats count by Image
```

<img width="1907" height="933" alt="task1-executables" src="https://github.com/user-attachments/assets/39f3a824-979b-4fc2-b458-66988214135a" />


<img width="1905" height="916" alt="task1-task5-merlin-first-connection" src="https://github.com/user-attachments/assets/e592e065-2195-4a95-b6d3-be198255b842" />


### Task 2: Session ID of the initial access

**Answer:** `-2102926010`

The TeamViewer log is plain text. The line `SessionManagerDesktop::IncomingConnection: Connection incoming, sessionID = -2102926010` marks the incoming connection. It is in `TeamViewer15_Logfile.log` (in the collection under `C/Users/gladys/AppData/Local/TeamViewer/Logs/`).

<img width="1121" height="486" alt="task2-task8-teamviewer-session-start" src="https://github.com/user-attachments/assets/924ef5e3-ee00-4bde-a425-e792aedd60cf" />


### Task 3: Password the attacker tried to set as the BitLocker password

**Answer:** `reallylongpassword`

Searching Sysmon EventID `1` for "bitlocker" returned nothing, because the attacker's PowerShell was Base64-encoded (`powershell.exe -e ...`). Filtering on the `-e` switch found two events (2023-05-04 09:56:32 and 11:14:32).

```
EventID=1 "-e" | stats count by CommandLine, _time
```

<img width="1909" height="960" alt="task3-bitlocker-no-results" src="https://github.com/user-attachments/assets/2ec49dd2-60f8-4ad6-b2b0-6edddec218c9" />


<img width="1908" height="561" alt="task3-encoded-commands" src="https://github.com/user-attachments/assets/06a8ecff-440e-4d3e-889e-1242f3d23e8f" />


Decoding the Base64 (UTF-16LE) gives:

```powershell
$SecureString = ConvertTo-SecureString "reallylongpassword" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector
```

What it does: the first line turns the plain-text password into a secure string. The second line turns on BitLocker for the `C:` drive with AES-256, encrypting only used space, and uses that password as the startup PIN. The 09:56 run also adds `-TPMandPinProtector` (TPM and PIN together); the 11:14 run leaves it out. With a PIN only the attacker knows, the owner would be locked out of the drive.

### Task 4: Name used by the attacker

**Answer:** `fritjof olfasson`

TeamViewer logs every participant in a session. In the same log, `CParticipantManagerBase participant fritjof olfasson (ID [1761879737,-207968498]) was added` shows the remote participant for session `-2102926010`, and the name appears again when the session ends.

<img width="1118" height="483" alt="task4-teamviewer-participant" src="https://github.com/user-attachments/assets/5e36dc9d-7e28-4449-8363-5498a8316ae6" />


### Task 5: IP address the C2 connected back to

**Answer:** `52.56.142.81`

Sysmon EventID `3` (network connection) from `merlin.exe`, grouped by `DestinationIp`, returns one address for all 357 connections. It resolves to `ec2-52-56-142-81.eu-west-2.compute.amazonaws.com` on port 80.

```
EventID=3 Image="*merlin.exe" | stats count by DestinationIp
```

<img width="1903" height="582" alt="task5-destination-ip" src="https://github.com/user-attachments/assets/b059c70e-89eb-4f89-9dc8-c3e7c67d9019" />


### Task 6: Category Windows Defender gave the C2 binary

**Answer:** `VirTool:Win32/Myrddin.D`

Searching the Defender log for "merlin" returns one `Threat Name`. The format is Type:Platform/Family.Variant: `VirTool` (a tool for building attacks), Windows 32/64-bit, and the family `Myrddin`, which is Merlin.

```
log="Microsoft-Windows-Windows Defender%4Operational" "merlin" | stats count by "Threat Name"
```

<img width="1910" height="750" alt="task6-threat-name" src="https://github.com/user-attachments/assets/f5412853-a7ac-48fe-89f7-a67968fef70e" />


### Task 7: PowerShell script the attackers used to manipulate time

**Answer:** `Invoke-TimeWizard.ps1`

Sysmon EventID `11` (file created) filtered to `*.ps1` shows 10 scripts. Most are random-named temp files that PowerShell creates itself. Two are not: `Desktop\KAPE\GET_KAPE.PS1` (the responders' tool) and `Desktop\Invoke-TimeWizard.ps1`, which is the time script.

```
EventID=11 TargetFilename="*.ps1" | stats count by TargetFilename
```

<img width="1568" height="750" alt="task7-ps1-files" src="https://github.com/user-attachments/assets/60e5da13-f631-4b96-9758-7f60af1a40ba" />


### Task 8: Time the initial access connection started

**Answer:** `04/05/2023 11:35:27`

The `IncomingConnection` line in the TeamViewer log is stamped `2023/05/04 11:35:27.433`, which is the connection start. Two other values were not accepted: the router time in the log (10:35:58) and the same time converted to UTC (10:35:27). The system clock was tampered with during the attack (Task 10), so TeamViewer's local times do not line up with Sysmon's UTC times.

<img width="1121" height="486" alt="task2-task8-teamviewer-session-start" src="https://github.com/user-attachments/assets/21f080da-349b-4bed-8dfe-5fb7ec4d4aac" />


### Task 10: How many times the PowerShell script changed the machine time

**Answer:** `2371`

Security EventID `4616` is "the system time was changed" and records the process that did it. Grouped by `ProcessName`, there are 2,374 events: 2,371 from `powershell.exe`, 2 from `SystemSettingsAdminFlows.exe` (the Windows Settings app) and 1 with a corrupted name. Only the `powershell.exe` events come from the script.

```
log="Security" EventID=4616 | stats count by ProcessName
```
<img width="1911" height="988" alt="task10-4616-by-process" src="https://github.com/user-attachments/assets/2cc37af9-d183-4f4e-9cfe-f9fbd101618b" />


### Task 11: SID of the victim user

**Answer:** `S-1-5-21-3720869868-2926106253-3446724670-1003`

Filtering the Security log on `SubjectUserName=gladys` and grouping by `SubjectUserSid` returns a single SID for all 2,495 events. The last number, `1003`, is the account itself; the rest identifies the computer.

```
log="Security" SubjectUserName=gladys | stats count by SubjectUserSid
```

<img width="1912" height="878" alt="task11-victim-sid" src="https://github.com/user-attachments/assets/8179abe7-4f01-43a1-ac9c-607b2cdccca0" />

## Summary

1. The attacker connected over TeamViewer (session `-2102926010`) as "fritjof olfasson" and uploaded `merlin.exe` to `gladys`'s Desktop.
2. `merlin.exe`, a Merlin C2 agent that Defender flags as `VirTool:Win32/Myrddin.D`, beaconed 357 times to `52.56.142.81`. The first connection was at 08:38:32 UTC on 4 May 2023 (Sysmon).
3. The attacker ran encoded PowerShell to enable BitLocker on `C:` with the PIN `reallylongpassword`.
4. `Invoke-TimeWizard.ps1` changed the system clock 2,371 times, which breaks the timeline across logs and explains why the TeamViewer, Security and Sysmon times disagree.
