#!/bin/bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║   Installation VM-Server CyberLab    ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Mise à jour ──────────────────────────────────────────────
apt-get update -y && apt-get upgrade -y

# ── 2. Python & pip ─────────────────────────────────────────────
apt-get install -y python3 python3-pip python3-venv net-tools curl

# ── 3. IP statique ──────────────────────────────────────────────
echo "[*] Configuration IP statique 192.168.100.1/24"
cat >> /etc/network/interfaces << 'EOF'

auto eth0
iface eth0 inet static
    address 192.168.100.1
    netmask 255.255.255.0
EOF

# ── 4. Dossier du projet ─────────────────────────────────────────
mkdir -p /opt/cyberlab/templates
cd /opt/cyberlab

# ── 5. Environnement Python ──────────────────────────────────────
python3 -m venv venv
source venv/bin/activate
pip install flask==3.0.3 flask-socketio==5.3.6 eventlet==0.36.1

echo ""
echo "✅ Installation serveur terminée."
echo "👉 Copie app.py + templates/index.html dans /opt/cyberlab/"
echo "👉 Lance avec : cd /opt/cyberlab && source venv/bin/activate && python3 app.py"