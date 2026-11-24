# HTB Sherlock: Litter

**Difficulty:** Easy | **Category:** SOC | **Evidence:** `suspicious_traffic.pcap` | **Tools:** Wireshark, tshark, CyberChef

## Tools
| Tool | What it did here |
|---|---|
| Wireshark | Spotted the DNS-heavy traffic (Conversations), isolated the tunnel stream |
| tshark | Pulled only the client's DNS query names out of the pcap |
| CyberChef | Stripped the domain + dnscat2 header and decoded the hex into the shell session |

## Summary
Host **192.168.157.144** (DESKTOP-UMNCBE7, user `test`) ran **dnscat2 v0.07**, which tunnelled a reverse shell over DNS to **192.168.157.145** using fake subdomains of `microsofto365.com`. The attacker enumerated the host, renamed the tool to hide it, and exfiltrated a customer PII file of **721 records** by printing it to the shell (`type`). The data left the network inside DNS queries.

## Findings
| # | Question | Answer |
|---|---|---|
| 1 | Suspect protocol | DNS |
| 2 | Suspect host IP | 192.168.157.145 |
| 3 | First command sent | `whoami` |
| 4 | DNS tunnelling tool version | 0.07 (dnscat2) |
| 5 | Tool renamed to | `win_installer.exe` |
| 6 | Files in cloud storage (OneDrive) | 0 |
| 7 | Full path of stolen PII file | `C:\users\test\documents\client data optimisation\user details.csv` |
| 8 | PII records stolen | 721 |

## Investigation
1. **Statistics → Conversations → IPv4.** The .144 ↔ .145 pair stands out: 5,645 packets over ~2068 seconds, almost all DNS.

<img width="1907" height="813" alt="conversations-ipv4" src="https://github.com/user-attachments/assets/0543369d-13a3-4793-a188-5f8526a9927c" />

2. **Follow UDP Stream** (`udp.stream eq 430`). The query names are long hex strings under `microsofto365.com`, which points to a DNS tunnel. The first long query (frame 12184) marks where the session starts.

 <img width="1911" height="694" alt="tunnel-start-packets" src="https://github.com/user-attachments/assets/8f4dd616-ed5f-426d-814b-125370098eb8" />


<img width="1762" height="684" alt="follow-udp-stream-430" src="https://github.com/user-attachments/assets/ec38a690-c5bf-4a9e-94c9-5e217c6e4bc7" />

3. **Decoding.** Follow Stream's ASCII view replaces binary bytes with dots, so it can't be decoded. Instead, the query names were extracted and decoded (the decoding was scripted):
   ```powershell
   tshark -r suspicious_traffic.pcap -Y "ip.src==192.168.157.144 && dns.flags.response==0 && dns.qry.name contains microsofto365" -T fields -e dns.qry.name
   ```
   CyberChef recipe: remove `\.microsofto365\.com` → remove `\.` → remove `^.{18}` (the 9-byte dnscat2 header) → Fork on `\n` → From Hex. Decoding single frames first confirmed the format: frame 12184 opens the dnscat2 command session, and 13776 carries the shell banner.

   <img width="990" height="911" alt="decode-session-start" src="https://github.com/user-attachments/assets/7dacd888-2fce-4644-8e9b-fead3bf2bb05" />

<img width="1007" height="930" alt="decode-shell-banner" src="https://github.com/user-attachments/assets/556328d8-39f0-4314-9530-7f2a3ceeabfc" />

4. **Reading the session.**
   - Shell banner, then `whoami` → `desktop-umncbe7\test`.

     <img width="1340" height="915" alt="task3-whoami-decode" src="https://github.com/user-attachments/assets/fa64841b-69a2-4e61-a517-ea721d032541" />

   - `dir` of Downloads shows `dnscat2-v0.07-client-win32.exe`.

    <img width="1913" height="937" alt="task4-packet-list" src="https://github.com/user-attachments/assets/cb11a7ac-445c-416d-a167-7dc9ee46c123" />


<img width="1346" height="990" alt="task4-dnscat2-version" src="https://github.com/user-attachments/assets/d27f5aee-344b-4a63-a309-5973181d4f04" />

   - Two failed `ren` attempts:

  <img width="1078" height="396" alt="task5-failed-ren" src="https://github.com/user-attachments/assets/29d2944e-d605-4428-8811-aa0da03ba57c" />


     Then a successful `ren dnscat2-v0.07-client-win32.exe win_installer.exe`.

     ![ren command](07-litter-screenshots/task5-ren-command.png)
   - `cd OneDrive` → `dir` returns 0 files.

     <img width="1121" height="409" alt="task6-onedrive-dir" src="https://github.com/user-attachments/assets/1cc27b20-1308-426e-adb2-c49d58ad59f3" />

   - `type "...\client data optimisation\user details.csv"` dumps the CSV (rows 0–720 = 721 records: names, SSNs, addresses, emails, DOBs).

     <img width="1116" height="387" alt="task7-pii-file-type" src="https://github.com/user-attachments/assets/5edb489e-6bf4-4e3d-a1cf-63f3e5b056af" />


    <img width="1116" height="276" alt="task8-pii-records-end" src="https://github.com/user-attachments/assets/523e4240-a2d6-4543-930f-11af665c0e61" />

   - The attacker then tried dnscat2's `download` command inside cmd. It failed (`'download' is not recognized`), but the data had already been exfiltrated through `type`.

## IOCs
- C2 / exfil host: `192.168.157.145`
- Tunnel domain: `microsofto365.com` (Microsoft typosquat)
- Tool: `dnscat2-v0.07-client-win32.exe`, renamed `win_installer.exe`

## MITRE ATT&CK
- T1071.004: Application Layer Protocol: DNS
- T1048: Exfiltration Over Alternative Protocol
- T1036: Masquerading (renaming the tool)
- T1033 / T1083: System Owner/User and File/Directory Discovery

## Recommendations
- Alert on high-volume DNS to a single domain, or on long/high-entropy subdomains.
- Force DNS through internal resolvers and block direct outbound DNS.
- Isolate DESKTOP-UMNCBE7, remove `win_installer.exe`, and start a breach notification for the leaked SSNs/PII.

## Result
All 8 tasks accepted.

<img width="1911" height="694" alt="tunnel-start-packets" src="https://github.com/user-attachments/assets/743e97f8-351f-4007-a391-ea017b364ba9" />

