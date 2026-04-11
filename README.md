# CyberLab IDS

> WiFi Network Attack Simulation & Visual Monitoring Platform  
> Master 1 Cybersecurity — Université Paris Cité — 2025/2026

---

## Description

CyberLab IDS is a web-based platform for simulating and visualizing
network attacks (MITM and DDoS) in an isolated WiFi lab environment
built with VirtualBox virtual machines.

---

## Lab Architecture

```
        ~~~  WiFi AP (cyberlab)  ~~~
           /         |          \
      [WiFi]      [WiFi]      [WiFi]
         |            |           |
     VM-Server   VM-Attacker  VM-Victim
```

## Project Structure

```
cyberlab/                    ← VM-Server
├── app.py                   # Flask server + REST API
├── templates/index.html     # Visual dashboard
└── static/js/               # Socket.IO, Chart.js (local)

cyberlab-agent/              ← VM-Attacker
├── agent.py                 # Main agent
├── mitm.py                  # ARP Spoofing module
└── ddos.py                  # Packet flood module
```

---

## Quick Start

**VM-Server**
```bash
cd /opt/cyberlab
source venv/bin/activate
python3 app.py
```

**VM-Server**
```bash
ping 192.168.100.1
```

**VM-Attacker**
```bash
cd /opt/cyberlab-agent
sudo venv/bin/python3 agent.py
```

**Browser → http://192.168.100.1:5000**
