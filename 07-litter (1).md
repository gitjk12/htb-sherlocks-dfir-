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

   ![Conversations](07-litter-screenshots/conversations-ipv4.png)
2. **Follow UDP Stream** (`udp.stream eq 430`). The query names are long hex strings under `microsofto365.com`, which points to a DNS tunnel.

   ![Follow UDP Stream](07-litter-screenshots/follow-udp-stream-430.png)
3. **Decoding.** Follow Stream's ASCII view replaces binary bytes with dots, so it can't be decoded. Instead, the query names were extracted and decoded (the decoding was scripted):
   ```powershell
   tshark -r suspicious_traffic.pcap -Y "ip.src==192.168.157.144 && dns.flags.response==0 && dns.qry.name contains microsofto365" -T fields -e dns.qry.name
   ```
   CyberChef recipe: remove `\.microsofto365\.com` → remove `\.` → remove `^.{18}` (the 9-byte dnscat2 header) → Fork on `\n` → From Hex.
4. **Reading the session.**
   - Shell banner, then `whoami` → `desktop-umncbe7\test`.
   - `dir` of Downloads shows `dnscat2-v0.07-client-win32.exe`.
   - Two failed `ren` attempts, then a successful `ren dnscat2-v0.07-client-win32.exe win_installer.exe`.

     ![ren command](07-litter-screenshots/task5-ren-command.png)
   - `cd OneDrive` → `dir` returns 0 files.

     ![OneDrive dir](07-litter-screenshots/task6-onedrive-dir.png)
   - `type "...\client data optimisation\user details.csv"` dumps the CSV (rows 0–720 = 721 records: names, SSNs, addresses, emails, DOBs).
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
