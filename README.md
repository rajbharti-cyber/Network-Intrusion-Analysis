# 🚨 Network Intrusion Analysis — Cybersecurity Forensics Case Study

This project demonstrates a full **Network Intrusion Analysis** on captured network traffic, simulating a real-world SOC investigation.  
It includes identification of malicious activities, extraction of indicators, threat classification, timeline building, and MITRE ATT&CK mapping.

This project mirrors real consulting work performed in:
- SOC Operations  
- Incident Response (IR)  
- Threat Hunting  
- Network Forensics  

No sensitive data or raw PCAPs are included—only the professional documentation of analysis.

---

# 📘 1. Project Summary

The objective of this project is to analyze captured network traffic for:

- Signs of intrusion  
- Malware command-and-control (C2)  
- Scanning and enumeration  
- Data exfiltration  
- Suspicious HTTP/DNS/TCP behavior  
- Unauthorized access attempts  

The analysis replicates real-world SOC workflows using tools such as Wireshark, Zeek, tcpdump, and Suricata (conceptually — no code or configurations are shown).

---

# 🎯 2. Objectives

- Perform detailed packet analysis  
- Identify malicious behaviors and patterns  
- Extract Indicators of Compromise (IOCs)  
- Build a timeline of attacker actions  
- Map detections to MITRE ATT&CK  
- Provide remediation recommendations  

---

# 🧩 3. Tools Used (Conceptual)

*No code or commands included—only tools referenced.*

- **Wireshark** — Packet inspection  
- **Zeek Logs** — Behavior and flow analysis  
- **Suricata Alerts** — IDS detection support  
- **OSINT** — Threat intelligence enrichment  
- **MITRE ATT&CK Navigator** — TTP mapping  

---

# 🖼️ 4. SOC Investigation Workflow (ASCII Diagram)

        Network Traffic (PCAP)
                  │
                  ▼
       ┌──────────────────────┐
       │   Packet Inspection   │
       │  (Wireshark/Zeek)     │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │  Intrusion Detection  │
       │ (Indicators & Alerts) │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │ MITRE ATT&CK Mapping │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │ Incident Report & IR │
       └──────────────────────┘

---

# 🔍 5. Key Findings (Example Scenarios)

The following intrusion patterns were observed during analysis:

---

## 1️⃣ **Port Scanning (Host Discovery & Enumeration)**  
### Indicators:
- Multiple SYN packets to sequential ports  
- High-volume TCP connection attempts  

### Interpretation:
Attacker was mapping open ports on the target system.  
**Likely Tool:** Nmap / masscan  
**MITRE:** T1046 – Network Service Discovery

---

## 2️⃣ **Brute Force Login Attempts**  
### Indicators:
- Repeated failed SSH/FTP login attempts  
- Same source IP attempting multiple credentials  

### Interpretation:
Password-guessing attack.  
**MITRE:** T1110 – Brute Force

---

## 3️⃣ **SQL Injection Attempt (Web Exploit)**  
### Indicators:
- HTTP requests containing:
  - `UNION SELECT`
  - `' OR '1'='1'`
  - `../` traversal sequences  
- Inspection of unusual query strings  

### Interpretation:
Attacker attempted to exploit web application vulnerabilities.  
**MITRE:** T1190 – Exploit Public-Facing Application

---

## 4️⃣ **Malware Command-and-Control (C2) Beaconing**  
### Indicators:
- Periodic outbound HTTP requests  
- Long base64-like payloads  
- Suspicious User-Agent strings  
- Regular beacon intervals (e.g., every 30 seconds)  

### Interpretation:
Infected host communicating with attacker C2 infrastructure.  
**MITRE:** T1071 – Web-Based C2

---

## 5️⃣ **Potential Data Exfiltration Over DNS**  
### Indicators:
- DNS queries with extremely long encoded strings  
- High volume of TXT requests  
- Unusual domains  

### Interpretation:
DNS tunneling behavior observed.  
**MITRE:** T1048 – Exfiltration Over Alternative Protocol

---

# 🧠 6. Indicators of Compromise (IOCs)

### ✔ Network Indicators
- Suspicious IPs (attacker-controlled)  
- Unusual DNS domains  
- Malicious User-Agent strings  

### ✔ Behavioral Indicators
- Repeated failed login attempts  
- Unexpected process-to-network behavior  
- C2-like periodic outbound connections  

### ✔ Protocol Indicators
- Encoded payloads in HTTP requests  
- Abnormal DNS query lengths  
- Unauthorized SQL query patterns  

---

# 🧱 7. MITRE ATT&CK Mapping

| Activity | Technique ID | Technique Name | Tactic |
|----------|--------------|----------------|--------|
| Port Scan | T1046 | Network Service Discovery | Reconnaissance |
| Brute Force | T1110 | Credential Access | Credential Access |
| SQL Injection | T1190 | Exploit Public-Facing App | Initial Access |
| C2 Beaconing | T1071 | Application Layer Protocol | Command & Control |
| DNS Tunneling | T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

---

# 🔧 8. Timeline of Intrusion (Example)

00:01 — Reconnaissance begins (port scan detected)
00:04 — SSH brute force attempts detected
00:09 — Web exploitation attempts (SQLi, path traversal)
00:12 — Successful exploitation → C2 communication starts
00:17 — DNS tunneling begins → potential data exfiltration
00:21 — Defender detection & logging triggered

---

# 🛡️ 9. Remediation Recommendations

### ✔ Strengthen Authentication  
- Enforce MFA  
- Apply lockout policy  
- Monitor authentication logs  

### ✔ Harden Web Applications  
- Enable WAF  
- Use parameterized queries  
- Validate user inputs  

### ✔ Improve Network Monitoring  
- Deploy IDS/IPS (Suricata/Snort)  
- Enable NetFlow logging  
- Monitor for periodic C2 communications  

### ✔ Patch & Update Systems  
- Apply missing patches  
- Upgrade vulnerable services  

### ✔ DNS Security  
- Block unauthorized DNS queries  
- Use DNS filtering & inspection  
- Monitor TXT record anomalies  

---

# 📦 10. Deliverables Included

- Network intrusion analysis documentation  
- Attack classification & findings  
- MITRE ATT&CK mapping  
- IOC summary  
- Incident timeline  
- Remediation recommendations  
- Forensic investigation workflow  

(No raw logs or PCAPs are included.)

---

# 📈 11. Key Outcomes

- Identified multiple stages of cyber intrusion  
- Mapped behaviors to MITRE ATT&CK  
- Demonstrated practical SOC/IR investigation skills  
- Produced analyst-quality documentation  
- Improved detection & response understanding  
- Strengthened network security maturity  

---

# 🧾 12. Conclusion

This Network Intrusion Analysis project demonstrates professional-level capabilities in:

- Network forensics  
- SOC investigation  
- Threat detection and classification  
- MITRE ATT&CK mapping  
- Incident reporting  
- Cyber defense strategy  

It reflects the real workflows used by Tier-1, Tier-2, and Tier-3 SOC analysts and cybersecurity consultants.

---

# 📬 Contact

**GitHub:** https://github.com/rajbharti-cyber  
**LinkedIn:** https://www.linkedin.com/in/rajbharti-cybersecurity/
