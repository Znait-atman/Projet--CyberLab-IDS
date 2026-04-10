from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from collections import deque
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberlab-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── État global ────────────────────────────────────────────────
state = {
    'mitm':  {'active': False, 'arp_poisoned': False, 'packets_intercepted': 0},
    'ddos':  {'active': False, 'pps': 0, 'total_packets': 0, 'mbps': 0.0},
    'network': {
        'attacker': {'ip': '192.168.100.3', 'mac': '??:??:??:??:??:??', 'status': 'disconnected'},
        'victim':   {'ip': '192.168.100.2', 'mac': '??:??:??:??:??:??', 'status': 'normal'},
        'server':   {'ip': '192.168.100.1', 'mac': '??:??:??:??:??:??', 'status': 'online'},
    }
}

pending_commands = []
mitm_packets     = deque(maxlen=50)
logs             = deque(maxlen=200)
ddos_history     = deque(maxlen=30)   # historique PPS pour le graphe


def log(msg, level='info'):
    entry = {'time': datetime.now().strftime('%H:%M:%S'), 'message': msg, 'level': level}
    logs.appendleft(entry)
    socketio.emit('log', entry)


# ── Routes Frontend ────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/state')
def get_state():
    return jsonify({
        'mitm':    state['mitm'],
        'ddos':    state['ddos'],
        'network': state['network'],
        'packets': list(mitm_packets),
        'logs':    list(logs),
        'ddos_history': list(ddos_history),
    })


@app.route('/api/command', methods=['POST'])
def send_command():
    """Reçoit les commandes du frontend et les met en file pour l'agent."""
    data = request.json
    cmd  = data.get('command')
    pending_commands.append(data)

    messages = {
        'start_mitm': ('🎯 Commande MITM envoyée à l\'attaquant…', 'warning'),
        'stop_mitm':  ('⏹  Arrêt MITM demandé',                  'info'),
        'start_ddos': ('💥 Commande DDoS envoyée à l\'attaquant…', 'warning'),
        'stop_ddos':  ('⏹  Arrêt DDoS demandé',                  'info'),
    }
    if cmd in messages:
        log(*messages[cmd])

    return jsonify({'status': 'ok'})


# ── Routes Agent (Attaquant) ───────────────────────────────────
@app.route('/api/poll')
def poll():
    """L'agent Kali interroge cette route pour recevoir ses ordres."""
    if pending_commands:
        return jsonify(pending_commands.pop(0))
    return jsonify({'command': 'none'})


@app.route('/api/report', methods=['POST'])
def report():
    """L'agent envoie ses données ici (statut, paquets…)."""
    data        = request.json
    report_type = data.get('type')

    # ── Connexion de l'agent ──
    if report_type == 'agent_hello':
        state['network']['attacker']['mac']    = data.get('mac', '')
        state['network']['attacker']['status'] = 'connected'
        log(f"✅ Agent connecté → {data.get('ip')}  MAC: {data.get('mac')}", 'success')
        socketio.emit('network_update', state['network'])

    # ── Statut MITM ──
    elif report_type == 'mitm_status':
        active = data.get('active', False)
        previously_active = state['mitm']['active']
        state['mitm'].update({
            'active': active,
            'arp_poisoned': data.get('arp_poisoned', False),
            'packets_intercepted': data.get('packets_intercepted', 0),
        })
        if active and not previously_active:
            log(f"⚠️  ARP Poisoning ACTIF ! Victime: {data.get('victim_ip')} ↔ Passerelle: {data.get('gateway_ip')}", 'danger')
        elif not active and previously_active:
            log('✅ MITM stoppé — tables ARP restaurées', 'success')
            state['network']['attacker']['status'] = 'connected'
            state['network']['victim']['status']   = 'normal'
        if active:
            state['network']['attacker']['status'] = 'attacking'
            state['network']['victim']['status']   = 'compromised'
        socketio.emit('mitm_update', state['mitm'])
        socketio.emit('network_update', state['network'])

    # ── Paquet intercepté (MITM) ──
    elif report_type == 'mitm_packet':
        pkt = {
            'time':     datetime.now().strftime('%H:%M:%S'),
            'src':      data.get('src'),
            'dst':      data.get('dst'),
            'protocol': data.get('protocol'),
            'info':     data.get('info'),
            'size':     data.get('size'),
        }
        mitm_packets.appendleft(pkt)
        socketio.emit('mitm_packet', pkt)

    # ── Statut DDoS ──
    elif report_type == 'ddos_status':
        active = data.get('active', False)
        previously_active = state['ddos']['active']
        state['ddos'].update({
            'active':        active,
            'pps':           data.get('pps', 0),
            'total_packets': data.get('total_packets', 0),
            'mbps':          round(data.get('mbps', 0.0), 2),
        })
        ddos_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'pps': state['ddos']['pps']})
        if active and not previously_active:
            log(f"💥 DDoS lancé vers {data.get('target_ip')} — {data.get('pps')} pkt/s", 'danger')
        elif not active and previously_active:
            log(f"✅ DDoS stoppé — total: {state['ddos']['total_packets']} paquets envoyés", 'success')
            state['network']['attacker']['status'] = 'connected'
            state['network']['victim']['status']   = 'normal'
        if active:
            state['network']['attacker']['status'] = 'attacking'
            state['network']['victim']['status']   = 'under_attack'
        socketio.emit('ddos_update', state['ddos'])
        socketio.emit('ddos_history', list(ddos_history))
        socketio.emit('network_update', state['network'])

    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    print("╔══════════════════════════════════════╗")
    print("║   CyberLab Dashboard  →  port 5000   ║")
    print("╚══════════════════════════════════════╝")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
