# Investigation

## Alert

Suspicious PowerShell-based reconnaissance activity detected.

## Investigation Steps

1. Verified Sysmon Event ID 1 logs in Splunk.
2. Identified PowerShell as the parent process.
3. Confirmed execution of reconnaissance commands:
   - whoami.exe
   - hostname.exe
   - systeminfo.exe
   - ipconfig.exe
   - netstat.exe
   - nslookup.exe
   - ping.exe
4. Reviewed parent-child process relationships.
5. Built SPL queries to identify similar activity.

## Findings

PowerShell launched several reconnaissance utilities typically associated with host discovery after initial access.

No malicious payloads were executed during this lab. The activity was intentionally generated for detection and analysis purposes.

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| PowerShell | T1059.001 |
| System Owner/User Discovery | T1033 |
| System Information Discovery | T1082 |
| System Network Configuration Discovery | T1016 |
| System Network Connections Discovery | T1049 |
