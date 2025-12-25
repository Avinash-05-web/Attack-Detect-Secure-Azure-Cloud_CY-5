# 🔐 Attack, Detect & Secure the Cloud Environment (Azure)

> **Cybersecurity Major Project | Red Team vs Blue Team | Cloud Security**  
> **Author:** Avinash Das Manikpuri  

---

## 📌 Project Overview

This project is a **hands-on cybersecurity major project** implemented on **Microsoft Azure**, designed to simulate a **real-world enterprise cloud security lifecycle**.

Using a **Red Team vs Blue Team methodology**, the project demonstrates how cyber-attacks are executed, detected using SIEM, investigated, mitigated, and validated through post-hardening re-attacks. All activities were performed in a **controlled lab environment** using **free and open-source tools only**.

---

## 🎯 Project Objectives

- Simulate real-world cyber-attacks on cloud infrastructure  
- Generate realistic system, authentication, and web logs  
- Detect and investigate malicious activity using SIEM  
- Identify misconfigurations and security gaps  
- Apply security hardening techniques  
- Validate improvements through post-hardening re-attacks  

---

## ☁️ Cloud Architecture

**Cloud Platform:** Microsoft Azure  
**Operating System:** Ubuntu Server 22.04 LTS  

### Virtual Machines Used

| VM Name | Role |
|------|------|
| **VM-Internal** | Internal Linux server (SSH attack target) |
| **VM-Web** | Web server hosting Apache/Nginx |
| **VM-SIEM** | Centralized SIEM server (Wazuh) |

All virtual machines are deployed within a **single Azure Virtual Network** to allow controlled internal communication and centralized monitoring.

---

## 🧨 Phase 1 – Red Team (Attack Simulation)

### 🔍 Reconnaissance & Enumeration

Port and service enumeration was performed to identify exposed services and establish the attack surface.

```bash
nmap -sS -sV -O <target-ip>

🔐 SSH Brute-Force Attacks
Password-based SSH brute-force attacks were executed to simulate credential-stuffing and weak authentication exploitation.

bash
hydra -l testuser -P rockyou.txt ssh://<target-ip>
Generated logs:

/var/log/auth.log

SIEM brute-force alerts

⬆️ Privilege Escalation Enumeration
Post-authentication enumeration was performed to identify misconfigured sudo permissions and SUID binaries.

bash
sudo -l
find / -perm -4000 2>/dev/null
🌐 Web Application Attacks (VM-Web)
Directory and file enumeration:

bash
gobuster dir -u http://<vm-web-ip> -w /usr/share/wordlists/dirb/common.txt
SQL Injection testing:

text
' OR '1'='1 --
Web vulnerability scanning:

bash
nikto -h http://<vm-web-ip>
Logs generated:

/var/log/apache2/access.log

/var/log/apache2/error.log

✅ Red Team Outcome
Multiple attack vectors identified

Extensive authentication, system, and web logs generated

Realistic attack patterns created for SOC analysis

🔵 Phase 2 – Blue Team (Detection & Investigation)
📥 Log Collection
Logs were collected from all virtual machines and forwarded to the SIEM platform.

bash
cat /var/log/auth.log
cat /var/log/syslog
tail -f /var/log/apache2/access.log
📊 SIEM Analysis (Wazuh)
The SIEM detected:

SSH brute-force attempts

Malicious web payloads

Enumeration activity

Privilege escalation attempts

🚨 Indicators of Compromise (IOC)
Type	Description
Attacker IP	External public IP
Auth Pattern	Repeated failed SSH logins
Web Payload	SQL injection strings
Privilege Attempt	Unauthorized sudo access

🔎 Root Cause Analysis
The investigation revealed:

Weak SSH authentication controls

Excessively permissive network access

Lack of rate limiting

Insufficient logging visibility

🛡️ Phase 3 – Security Hardening
📜 Logging Enhancements
Auditd rules were configured to enhance visibility.

bash
auditctl -w /etc/passwd -p wa
auditctl -w /etc/shadow -p wa
🔐 SSH Hardening
bash
sudo nano /etc/ssh/sshd_config
Applied configurations:

text
PermitRootLogin no
PasswordAuthentication no
Restart SSH:

bash
sudo systemctl restart ssh
🚧 Firewall & Rate Limiting
Enable and configure UFW:

bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw status
Install and enable Fail2Ban:

bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
🌐 Web Server Hardening
bash
sudo systemctl restart apache2
sudo systemctl status apache2
Actions performed:

Restricted directory access

Reduced information leakage

Hardened service configuration

🔁 Phase 4 – Post-Hardening Validation
All original attack scenarios were repeated after hardening.

Results Comparison
Control	Before Hardening	After Hardening
SSH Access	Public	Restricted
Open Ports	Multiple	Minimal
SIEM Alerts	Noisy	Clean & actionable

📊 Key Outcomes
✔ Successful detection of simulated attacks

✔ Reduced attack surface

✔ Improved SIEM alert quality

✔ SOC-level investigation experience

✔ Validated security improvements

🛠 Tools & Technologies
Cloud & OS

Microsoft Azure

Ubuntu Server 22.04 LTS

Red Team

Nmap

Hydra

Gobuster

Nikto

Blue Team / SIEM

Wazuh SIEM

Auditd

Apache Logs

Hardening

UFW

Fail2Ban

SSH hardening

📁 Repository Structure
Attack-Detect-Secure-Azure-Cloud/
├── README.md
├── Reports/
├── Screenshots/
│   ├── Phase_0_Setup/
│   ├── Phase_1_Red_Team/
│   ├── Phase_2_Blue_Team/
│   └── Phase_3_Hardening/
└── Architecture/

⚠️ Disclaimer
This project was conducted strictly for educational purposes in a self-owned Azure lab environment.
No unauthorized systems were targeted
