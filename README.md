# 🔐 CodeAlpha Cyber Security Internship Projects

### Network Sniffer + Snort-Based Intrusion Detection System

This repository contains my completed tasks for the **CodeAlpha Cyber Security Internship**, focusing on **network monitoring, packet analysis, and intrusion detection systems (IDS)**.

---

## 🚀 Overview

This project consists of two major components:

### 🔹 Task 1: Network Packet Analyzer (NetScope)

A Python-based GUI tool built using **Scapy + Tkinter** to capture and analyze live network traffic.

### 🔹 Task 4: Snort-Based IDS Dashboard (SentinelWatch)

A real-time intrusion detection monitoring system that integrates **Snort 3 (Snort++)** with a custom Python dashboard for visualization and response.

---

## 🧠 Key Features

### 📡 Network Sniffer (Task 1)

- Live packet capturing using Scapy
- Protocol detection (TCP, UDP, ICMP, DNS, ARP)
- Source/Destination IP analysis
- Payload inspection
- Real-time GUI with filtering & search
- Export captured packets

---

### 🚨 Intrusion Detection System (Task 4)

- Snort 3 (Snort++) integration
- Custom rule-based attack detection
- Real-time log monitoring
- Severity classification (HIGH / MEDIUM / LOW)
- Dashboard visualization:
  - Alert table
  - Severity pie chart
  - Attack rate graph
  - Top attacker IPs

- Response mechanisms:
  - Block malicious IP (iptables)
  - Generate incident report

---

## ⚙️ Technologies Used

- Python (Tkinter, threading)
- Scapy
- Snort 3 (Snort++)
- Linux (Kali)
- Regular Expressions
- Networking Protocols

---

## 🔧 Setup Instructions

### 🔹 1. Install Snort (Kali Linux)

```bash
sudo apt update
sudo apt install snort -y
```

---

### 🔹 2. Configure Snort (Snort++)

Edit:

```bash
sudo nano /etc/snort/snort.lua
```

Add:

```lua
ips =
{
    variables = default_variables,
    rules = [[
        include /etc/snort/rules/local.rules
        include /etc/snort/rules/scan.rules
        include /etc/snort/rules/dos.rules
    ]]
}
```

---

### 🔹 3. Add Custom Rules

```bash
sudo nano /etc/snort/rules/local.rules
```

Example:

```snort
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001;)
alert tcp any any -> any 22 (msg:"SSH Attempt"; sid:1000002;)
alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000003;)
```

---

### 🔹 4. Run Snort

```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
```

---

### 🔹 5. Run IDS Dashboard

```bash
python3 sentinelwatch.py
```

Set log path:

```text
/var/log/snort/alert_fast.txt
```

---

## 🧪 Testing

Generate traffic:

```bash
ping 8.8.8.8
nmap -sS 127.0.0.1
curl http://example.com
```

---

## 📊 Screenshots

### 🔹 Network Sniffer

<img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/0f6f7aa3-e17d-43d2-b048-32dd379c0a6e" />


### 🔹 IDS Dashboard

<img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/072b0208-e031-4d9f-b4be-ac51a735250f" />


---

## 🎯 Learning Outcomes

- Understanding packet structures and protocols
- Implementing real-time packet capture
- Configuring Snort IDS with custom rules
- Log parsing and threat classification
- Building security dashboards
- Applying incident response techniques

---

## 📌 Conclusion

This project demonstrates practical implementation of:

- Network monitoring
- Threat detection
- Security visualization
- Automated response

---

## 👨‍💻 Author

**Saad Ali**
Cyber Security Student

---

## 🔗 Internship

Completed as part of **CodeAlpha Cyber Security Internship Program**
