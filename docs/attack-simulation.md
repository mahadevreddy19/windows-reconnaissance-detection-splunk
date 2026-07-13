# Attack Simulation

## Objective

Simulate Windows reconnaissance activity commonly performed by an attacker after gaining initial access to a system.

## Lab Environment

- Windows 11 Virtual Machine
- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon

## Commands Executed

```powershell
whoami
hostname
systeminfo
Get-Process
Get-Service
ipconfig /all
netstat -ano
nslookup github.com
ping github.com
```

## Expected Telemetry

The commands generate Sysmon Event ID 1 (Process Creation) logs, allowing analysts to investigate PowerShell-based reconnaissance activity in Splunk.
