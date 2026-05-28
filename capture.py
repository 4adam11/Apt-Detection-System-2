"""
ml/capture.py
Live network packet capture using Scapy.
Captures packets, extracts features per flow, sends to ML model via callback.
"""

import time
import threading
import random
from collections import defaultdict
from datetime import datetime

# Try to import Scapy (may need root on Linux)
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Capture] Scapy not available — simulation mode active")


# ── Flow Tracker ─────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Tracks per-(src_ip, dst_ip, protocol) flow statistics.
    Flushes completed flows every FLUSH_INTERVAL seconds.
    """
    FLUSH_INTERVAL = 5   # seconds between feature extractions

    def __init__(self, on_flow_ready):
        self.flows     = defaultdict(lambda: {
            'start_time': time.time(),
            'packets': [], 'bytes': 0,
            'src_ports': set(), 'dst_ports': set(),
            'failed_logins': 0, 'dns_requests': 0,
        })
        self.on_flow_ready = on_flow_ready
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if not pkt.haslayer('IP'):
            return
        ip = pkt['IP']
        key = (ip.src, ip.dst, ip.proto)

        with self._lock:
            flow = self.flows[key]
            flow['packets'].append(pkt)
            flow['bytes'] += len(pkt)

            if pkt.haslayer('TCP'):
                flow['src_ports'].add(pkt['TCP'].sport)
                flow['dst_ports'].add(pkt['TCP'].dport)
                # Detect failed SSH login (RST on port 22)
                if pkt['TCP'].flags & 0x04 and pkt['TCP'].dport == 22:
                    flow['failed_logins'] += 1

            if pkt.haslayer('UDP'):
                flow['src_ports'].add(pkt['UDP'].sport)
                flow['dst_ports'].add(pkt['UDP'].dport)

            if pkt.haslayer('DNS') and pkt.haslayer('DNSQR'):
                flow['dns_requests'] += 1

    def flush_flows(self):
        """Extract features from aged flows and call callback."""
        now = time.time()
        with self._lock:
            to_flush = [
                k for k, v in self.flows.items()
                if now - v['start_time'] >= self.FLUSH_INTERVAL
            ]
            for key in to_flush:
                flow = self.flows.pop(key)
                features = self._extract_features(key, flow, now)
                self.on_flow_ready(features)

    def _extract_features(self, key, flow, now):
        src_ip, dst_ip, proto = key
        duration = max(now - flow['start_time'], 0.001)
        pkt_count = len(flow['packets'])

        # Detect C2-like beacon (uniform inter-packet timing)
        beacon_interval = 0
        times = sorted(p.time for p in flow['packets']) if flow['packets'] else []
        if len(times) > 3:
            gaps = [times[i+1] - times[i] for i in range(len(times)-1)]
            std_dev = (sum((g - sum(gaps)/len(gaps))**2 for g in gaps) / len(gaps)) ** 0.5
            if std_dev < 2.0:   # very regular = likely C2 beacon
                beacon_interval = round(sum(gaps)/len(gaps), 2)

        # Encrypted ratio heuristic (large packets → likely TLS)
        enc_count = sum(1 for p in flow['packets'] if len(p) > 900)
        enc_ratio = round(enc_count / max(pkt_count, 1), 4)

        return {
            'src_ip':   src_ip,
            'dst_ip':   dst_ip,
            'src_port': 0,
            'dst_port': 0,
            'protocol': {6: 'TCP', 17: 'UDP'}.get(proto, 'OTHER'),
            'duration':                round(duration, 3),
            'packet_count':            pkt_count,
            'byte_count':              flow['bytes'],
            'failed_logins':           flow['failed_logins'],
            'unique_ports':            len(flow['src_ports'] | flow['dst_ports']),
            'dns_requests':            flow['dns_requests'],
            'outbound_connections':    len(flow['dst_ports']),
            'data_exfil_bytes':        flow['bytes'] if flow['bytes'] > 50000 else 0,
            'privilege_escalation':    0,
            'lateral_movement':        0,
            'c2_beacon_interval':      beacon_interval,
            'encrypted_traffic_ratio': enc_ratio,
        }


# ── Live Capture ──────────────────────────────────────────────────────────────

class LiveCapture:
    def __init__(self, on_flow_ready, iface=None):
        self.on_flow_ready = on_flow_ready
        self.iface         = iface
        self.running       = False
        self.tracker       = FlowTracker(on_flow_ready)
        self._threads      = []

    def start(self):
        if self.running:
            return
        self.running = True
        if SCAPY_AVAILABLE:
            t = threading.Thread(target=self._sniff_loop, daemon=True)
            t.start()
            self._threads.append(t)
        else:
            t = threading.Thread(target=self._simulate_loop, daemon=True)
            t.start()
            self._threads.append(t)

        # Flush thread
        ft = threading.Thread(target=self._flush_loop, daemon=True)
        ft.start()
        self._threads.append(ft)
        print(f"[Capture] Started — Scapy={'YES' if SCAPY_AVAILABLE else 'SIMULATED'}")

    def stop(self):
        self.running = False
        print("[Capture] Stopped")

    def _sniff_loop(self):
        """Real Scapy packet capture (requires root/sudo)."""
        try:
            sniff(
                iface=self.iface,
                prn=self.tracker.process_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"[Capture] Scapy error: {e} — switching to simulation")
            self._simulate_loop()

    def _flush_loop(self):
        while self.running:
            time.sleep(FlowTracker.FLUSH_INTERVAL)
            self.tracker.flush_flows()

    # ── Simulation Mode ───────────────────────────────────────────────────────

    ATTACK_PROFILES = {
        'normal': dict(
            duration=(0.5, 4.0), packet_count=(5, 80), byte_count=(200, 8000),
            failed_logins=(0, 1), unique_ports=(1, 4), dns_requests=(1, 15),
            outbound_connections=(1, 8), data_exfil_bytes=(0, 300),
            privilege_escalation=0, lateral_movement=0,
            c2_beacon_interval=0, encrypted_traffic_ratio=(0.1, 0.45)
        ),
        'recon': dict(
            duration=(0.1, 1.5), packet_count=(80, 600), byte_count=(100, 800),
            failed_logins=(0, 1), unique_ports=(60, 250), dns_requests=(60, 250),
            outbound_connections=(30, 120), data_exfil_bytes=(0, 50),
            privilege_escalation=0, lateral_movement=0,
            c2_beacon_interval=0, encrypted_traffic_ratio=(0.0, 0.15)
        ),
        'compromise': dict(
            duration=(2.0, 12.0), packet_count=(150, 1200), byte_count=(8000, 60000),
            failed_logins=(6, 25), unique_ports=(2, 8), dns_requests=(5, 25),
            outbound_connections=(4, 20), data_exfil_bytes=(0, 2000),
            privilege_escalation=(1, 3), lateral_movement=0,
            c2_beacon_interval=0, encrypted_traffic_ratio=(0.3, 0.65)
        ),
        'lateral': dict(
            duration=(8.0, 60.0), packet_count=(400, 4000), byte_count=(15000, 120000),
            failed_logins=(2, 12), unique_ports=(4, 22), dns_requests=(10, 55),
            outbound_connections=(8, 55), data_exfil_bytes=(200, 8000),
            privilege_escalation=(1, 4), lateral_movement=(1, 6),
            c2_beacon_interval=(30, 350), encrypted_traffic_ratio=(0.5, 0.88)
        ),
        'exfil': dict(
            duration=(12.0, 120.0), packet_count=(800, 12000),
            byte_count=(120000, 1200000), data_exfil_bytes=(60000, 600000),
            failed_logins=(0, 4), unique_ports=(1, 4), dns_requests=(25, 120),
            outbound_connections=(1, 8), privilege_escalation=(1, 5),
            lateral_movement=(1, 5), c2_beacon_interval=(60, 700),
            encrypted_traffic_ratio=(0.72, 1.0)
        )
    }

    def _rand_ip(self):
        return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _rand_val(self, v):
        if isinstance(v, tuple):
            if isinstance(v[0], float) or isinstance(v[1], float):
                return round(random.uniform(v[0], v[1]), 4)
            return random.randint(int(v[0]), int(v[1]))
        return v

    def _simulate_loop(self):
        """Generate synthetic flows at realistic rates."""
        weights = [0.60, 0.10, 0.12, 0.10, 0.08]   # class distribution
        profiles = list(self.ATTACK_PROFILES.keys())
        protos = ['TCP', 'UDP', 'TCP', 'TCP']

        while self.running:
            profile_name = random.choices(profiles, weights=weights)[0]
            profile = self.ATTACK_PROFILES[profile_name]
            features = {
                'src_ip':   self._rand_ip(),
                'dst_ip':   self._rand_ip(),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 8080, 3389, 53, 445]),
                'protocol': random.choice(protos),
            }
            for k, v in profile.items():
                features[k] = self._rand_val(v)

            self.on_flow_ready(features)
            time.sleep(random.uniform(0.8, 2.5))   # realistic inter-flow gap
