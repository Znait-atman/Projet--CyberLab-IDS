#!/bin/bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║   Installation VM-Attacker CyberLab  ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Mise à jour ──────────────────────────────────────────────
apt-get update -y

# ── 2. Dépendances ───────────────────────────────────────────────
apt-get install -y python3 python3-pip python3-venv \
    libpcap-dev tcpdump net-tools curl

# ── 3. IP statique ──────────────────────────────────────────────
echo "[*] Configuration IP statique 192.168.100.3/24"
cat >> /etc/network/interfaces << 'EOF'

auto eth0
iface eth0 inet static
    address 192.168.100.3
    netmask 255.255.255.0
EOF

# ── 4. Dossier agent ─────────────────────────────────────────────
mkdir -p /opt/cyberlab-agent
cd /opt/cyberlab-agent

# ── 5. Environnement Python ──────────────────────────────────────
python3 -m venv venv
source venv/bin/activate
pip install requests==2.31.0 scapy==2.5.0

echo ""
echo "✅ Installation attaquant terminée."
echo "👉 Copie agent.py + mitm.py + ddos.py dans /opt/cyberlab-agent/"
echo "👉 Lance avec : cd /opt/cyberlab-agent && source venv/bin/activate && sudo python3 agent.py"