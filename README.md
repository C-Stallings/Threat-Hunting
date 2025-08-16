# Threat Hunting Project – Device Exposed to the Internet

## Scenario
**Incident:** `windows-target-1` was found to be internet-facing for several days, attracting multiple failed login attempts from various remote IP addresses. Investigation confirmed no unauthorized access occurred.


<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/9e53c3f6-76b9-4c80-bd61-e84d60a832ef" 
    height="367" 
    width="643" 
    alt="SS_Threat-Hunting_Image"
  />
</p>

---

## Timeline & Findings
- **Last Internet-Facing Time:** `2025-08-14T13:01:18.820459Z`
- Multiple failed login attempts detected from various IPs.
- Top 5 attacker IPs did **not** have any successful logons.
- Only successful remote/network logons in the last 30 days were from legitimate account `labuser` (13 times).
- No failed logons for `labuser` → brute force on that account unlikely.
- All `labuser` successful logon IPs were from expected/normal locations.

---

## KQL Queries

### 1. Identify Internet-Facing Device
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

### 2. Failed Login Attempts
```kql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/e3db466c-14e0-43da-b297-1a502fb3da18" 
    height="367" 
    width="643" 
    alt="SS-Device-LogonSuccess"
  />
</p>

### 3. Check Top Attacker IPs for Success
```kql
let RemoteIPsInQuestion = dynamic(["185.170.144.3","92.53.65.234","115.190.143.222","80.94.93.233","27.123.9.202"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

### 4. `labuser` Account Activity
```kql
// Successful
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()

// Failed
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

### 5. Check `labuser` Successful Logon IPs for Anomalies
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/0d2bd2a3-c225-45f0-93bc-33cf5d284cd0" 
    height="228" 
    width="863" 
    alt="SS-Device-labuser-LogonSuccess"
  />
</p>

*Finding: All successful logon IPs for `labuser` were from expected, known locations — no anomalies detected.*

---

## MITRE ATT&CK TTPs Identified from Incident Notes
- **T1078 – Valid Accounts**  
  (Legitimate "labuser" account used for successful logons.)
- **T1110.001 – Brute Force: Password Guessing**  
  (Multiple failed logon attempts from multiple remote IPs.)
- **T1021 – Remote Services**  
  (Use of remote/interactive logon types such as Network, RemoteInteractive.)
- **T1595 – Active Scanning**  
  (System exposed to the internet, likely targeted by opportunistic attackers.)
- **T1033 – System Owner/User Discovery** *(Possible)*  
  (Failed attempts suggest reconnaissance of valid accounts before authentication.)

---

## Response – Mitigation Options
1. **Block Attacker IPs at Firewall/NSG** – Immediately deny traffic from the identified brute-force source IPs.  
2. **Remove Internet-Facing Exposure** – Disable unnecessary public access or place VM behind VPN/Zero Trust gateway.  
3. **Enforce MFA & Account Lockout Policies** – Ensure repeated failed login attempts trigger temporary lockouts.

---

## Improvement – Prevention & Process Refinement
1. **Continuous Exposure Monitoring** – Implement automated alerts for any VM becoming internet-facing unexpectedly.  
2. **Harden Authentication** – Require MFA for all remote logons and restrict login methods to approved users/networks only.  
3. **Enhance Threat Hunting Playbooks** – Include baseline login location checks and automated anomaly detection to speed future investigations.


