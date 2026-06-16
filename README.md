# Building-a-near-real-time-dashboard
A production-grade, three-interface enterprise security monitoring environment utilizing a centralized SIEM pipeline to detect network reconnaissance, brute-force vectors, and Active Directory privilege escalation in real-time.


##  Architectural Topology & Segmentation
The environment mimics a corporate network topology by strictly enforcing micro-segmentation across three distinct virtual interfaces managed by a core **pfSense** security gateway.

*   **WAN (External Boundary):** Connects to the host network interface, serving as the perimeter edge.
*   **LAN (Internal Trust Zone):** Houses corporate employee assets, including a **Windows 10 Workstation** endpoint.
*   **OPT1 (Isolated Adversary Zone):** Houses the **Kali Linux** offensive testing suite, isolating the attacking infrastructure from the rest of the internal assets.
*   **Server/Management Layer:** Houses the **Windows Server (Domain Controller)** and the central logging pipeline hosted on an **Ubuntu Server Running Snort IDS and Splunk Enterprise**.

```text
                  [ KALI LINUX ] (Simulates External Threat on OPT1)
                         │
                         ▼
                  [ pfSense WAN ]
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
   [ pfSense LAN ]               [ pfSense OPT1 (DMZ) ]
         │                               │
  ┌──────┴──────┐                 ┌──────┴──────┐
  │ Windows 10  │                 │ Win Server  │ (Domain Controller)
  └─────────────┘                 │ Ubuntu/Snort│ (IDS Engine)
                                  │ Ubuntu/Splunk│ (SOC Core)
                                  └─────────────┘
```

---

##  Technology Stack & Core Competencies
*   **SIEM Core:** Splunk Enterprise (Centralized Ingestion, Parsing, & Analytics Engine)
*   **Security Gateway & Routing:** pfSense (Stateful Inspection, Interface Segmentation, Syslog Forwarding)
*   **Network Detection:** Snort IDS (Signature-based Deep Packet Inspection)
*   **Log Forwarding Agents:** Splunk Universal Forwarder (Windows & Linux agents)
*   **Target Environments:** Windows Server (Active Directory Domain Services), Windows 10 Enterprise

---

##  Advanced Detection Engineering & Custom Dashboard Rules

The automated dashboard operates in near real-time, executing continuous polling loops across unrestricted indexes to process and visualize attacker telemetry without UI latency.

### 1. Unified Incident Timeline (Snort & Endpoint Analytics)
Plots historical data points on an interactive line graph, displaying real-time volumetric spikes during aggressive network behavior.
*   **Search Interval:** 15 Seconds
*   **SPL Query:**
```splunk
index=* sourcetype=fast* OR sourcetype=auth* OR sourcetype="WinEventLog:Security" "4625"
| bucket _time span=5m 
| timechart count by sourcetype
```

### 2. Micro-Segmented Perimeter Ingestion (pfSense Interface Diagnostics)
Leverages custom regular expressions to parse native CSV formatted pfSense `filterlog` traffic arrays, mapping traffic load against specific network interfaces (`em0`, `em1`, `em2`).
*   **Search Interval:** 15 Seconds
*   **SPL Query:**
```splunk
index=* "filterlog" 

| rex field=_raw "filterlog\[\d+\]:\s+\d+,,,\d+,(?<outbound_interface>[^\s,]+),.*?,(?<action>block|pass|drop),.*?,(?<attacker_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<destination_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by outbound_interface
```

### 3. Identity Brute-Force Analytics (Multi-Field Regex Extraction)
Bypasses typical Windows multi-line field-extraction conflicts by executing non-greedy multi-line regular expressions (`(?ms)`). This creates an array that filters out machine account noise (`SERVER$`), isolating targeted human accounts (`Administrator`, `Guest`).
*   **Search Interval:** 30 Seconds
*   **SPL Query:**
```splunk
index=* "failed to log on" OR "4625" 
| rex max_match=0 field=_raw "Account Name:\s+(?<extracted_users>[^\s\r\n\-\$]+)" 
| eval Target_User=mvindex(extracted_users, 1)
| search Target_User=* 
| stats count by Target_User
```

### 4. Privilege Escalation Watchdog (Active Directory Audit Trail)
High-fidelity audit tracking monitoring the critical final steps of network compromise, logging unauthorized assignment of permissions into structural groups like **Domain Admins**.
*   **Search Windows Tracking Matrix:** Event Code 4728, 4732, and 4756
*   **SPL Query:**
```splunk
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756) 
| table _time, Security_ID, Group_Name, Member_Name 
| rename Security_ID as "Admin Action By", Group_Name as "Target Group", Member_Name as "User Added" 
| sort -_time
```

---

##  Simulation, Playbooks & Validation

### Phase 1: Perimeter Reconnaissance
*   **Offensive Execution (Kali Linux):** Targeted ports across interface paths using aggressive timing structures:
    ```bash
    nmap -p 1-1000 -T5 [PFSENSE_WAN_IP]
    ```
*   **SOC Observation:** The **Perimeter Firewall Activity** panel registered instant telemetry, scaling a vertical bar matching the network driver slot handling the blocked packets.

### Phase 2: Host Brute-Force Simulation
*   **Offensive Execution (Kali Linux):** Simulated an automated password spraying script against internal targets via SMB:
    ```bash
    crackmapexec smb [TARGET_IP] -u Administrator -p WrongPassword123!
    ```
*   **SOC Observation:** The **Identity Brute-Force Analytics** pie chart automatically generated a high-volume slice highlighting the user `Administrator`, ignoring structural system background identities.

### Phase 3: Active Directory Tampering
*   **Simulation Environment (Windows Server):** Manually instantiated an administrative privilege modification within the Active Directory configuration management panel (`dsa.msc`), appending a rogue user account directly to the **Domain Admins** group.
*   **SOC Observation:** The **Privileged Group Modifications** watchdog table generated a granular forensic line tracing the exact timestamp, target database path, and authorization identity responsible for the group shift.

---

##  Key Takeaways & Security Engineering Milestones
*   **Network Defense Mechanics:** Successfully deployed production-ready stateful inspection and multi-interface rulesets inside pfSense to establish strict zone isolation.
*   **Advanced Detection Engineering:** Solved complex, raw multi-line string extraction errors within raw event fields using advanced Splunk SPL architecture and regular expressions.
*   **Triage Automation Optimization:** Constructed a live, low-latency dashboard engine capable of automatically rendering high-fidelity attacker metrics without relying on standard pre-installed vendor telemetry add-ons.
