# HTB Sherlock: Campfire-2 (Very Easy)

**Scenario:** Domain controller Security log (`DC01.forela.local`). An old admin account requested a ticket from the KDC, which may be an AS-REP roasting attack. Investigated in Splunk.

## Tools
- **Splunk:** searched the Security events by Event ID and field values.
- **evtx to JSON conversion:** Splunk could not decode the raw `.evtx` on upload, so I converted it to JSON lines (152 events) and uploaded it as sourcetype `Campfire-2`.

| Search | Used for |
|---|---|
| `EventID=4768 PreAuthType=0` (Kerberos TGT request, no pre-auth) | Tasks 1 to 4 |
| Search on the source IP, `table SubjectUserName` | Task 5 |

## Walkthrough

**Task 1: When did the AS-REP roasting happen?**
Answer: `2024-05-29 06:36:40`
Event 4768 with `PreAuthType=0` (pre-authentication not required) is the one ticket request that fits. Only one event matched.

```
source="security_events.jsonl" host="LAFRANCE" sourcetype="Campfire-2" EventID=4768 PreAuthType=0
```

![task1-4-asrep-event-4768](shots/task1-4-asrep-event-4768.png)

**Task 2: Targeted account**
Answer: `arthur.kyle`
`TargetUserName` in the same event.

**Task 3: SID of the account**
Answer: `S-1-5-21-3239415629-1862073780-2394361899-1601`
`TargetSid` in the same event.

**Task 4: Internal IP of the compromised asset**
Answer: `172.17.79.129`
`IpAddress` in the same event: the machine that sent the ticket request.

**Task 5: Account used to perform the attack**
Answer: `happy.grunwald`
Searching the log for that IP shows other events from the same machine (a service ticket request and network share access) under the account `happy.grunwald`. The 4768 event can't show who asked, because no authentication is required.

```
source="security_events.jsonl" host="LAFRANCE" sourcetype="Campfire-2" "172.17.79.129"
| table SubjectUserName
```

![task5-search-by-ip](shots/task5-search-by-ip.png)
![tasks-completed](shots/tasks-completed.png)

## Summary
At 06:36:40 on 2024-05-29, a machine at `172.17.79.129` asked the domain controller for a ticket for `arthur.kyle`, an account with pre-authentication disabled, which is the AS-REP roasting technique. Other activity from that same machine ties the attack to the account `happy.grunwald`.
