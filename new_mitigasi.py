import requests
import threading
import time
from collections import defaultdict

# --- Konstanta dan Auth ---
ONOS_URL = "http://localhost:8181/onos/v1/flows"
AUTH = ('onos', 'rocks')
BLOCK_THRESHOLD = 0.5

# Mode mitigasi: 'block', 'rate_limit', atau 'temp_block'
MITIGATION_MODE = 'temp_block'  # RECOMMENDED: temporary block dengan auto-unblock

# Jika rate_limit, set bandwidth maksimal (Kbps)
RATE_LIMIT_KBPS = 100  # 100 Kbps (cukup untuk ping/ssh, tapi tidak untuk flood)

# Temporary block duration (detik) - flow rule auto expire
TEMP_BLOCK_DURATION = 20  # Block 20 detik, lalu auto-unblock

# Threshold detection
REPEAT_LIMIT_SOURCE = 10
RESET_API = "http://localhost:8000/reset"
FLOW_SESSION_RESET = "http://localhost:5050/reset"
UNBLOCK_DELAY = 60  # Untuk permanent block mode

# --- State dan Tracking ---
# Per source tracking
BLOCKED_MACS = set()
mac_anomaly_count = defaultdict(int)

# Per destination tracking (NEW)
PROTECTED_TARGETS = set()  # Target yang sedang diproteksi
dst_anomaly_count = defaultdict(int)  # Counter per destination
attacking_sources = defaultdict(set)  # Track attacker per target

mitigated_state = defaultdict(lambda: {"active": False, "timestamp": None, "last_anomaly": None})

# Counter untuk debugging
total_anomalies_received = 0
total_mitigations_done = 0

# --- Mitigasi ke ONOS ---
def submit_mitigation_block_port(device_id, port_number):
    """
    Block semua traffic dari port fisik tertentu.
    Ini block host secara fisik, tidak peduli MAC/IP apa yang dipakai.
    """
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": device_id,
        "treatment": {},  # DROP
        "selector": {
            "criteria": [
                {"type": "IN_PORT", "port": port_number}
            ]
        }
    }

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH, timeout=5)
        print(f"[MITIGASI PORT] Block port {port_number} on {device_id}")
        print(f"                Status: {response.status_code}")
        print(f"                Note: Semua traffic dari port ini di-block")
        
        if response.status_code != 200:
            print(f"[ERROR] ONOS Response: {response.text[:200]}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] Submit mitigasi port gagal: {e}")
        return False

def get_port_from_mac(mac_address):
    """
    Cari port number dari MAC address via ONOS API.
    """
    try:
        # Get hosts info from ONOS
        hosts_url = "http://localhost:8181/onos/v1/hosts"
        resp = requests.get(hosts_url, auth=AUTH, timeout=5)
        
        if resp.status_code == 200:
            hosts = resp.json().get("hosts", [])
            for host in hosts:
                if host.get("mac") == mac_address:
                    locations = host.get("locations", [])
                    if locations:
                        device_id = locations[0].get("elementId")
                        port = locations[0].get("port")
                        return device_id, port
        
        print(f"[WARN] Could not find port for MAC {mac_address}")
        return None, None
    except Exception as e:
        print(f"[ERROR] Failed to get port info: {e}")
        return None, None
    """
    Block traffic dari attacker (source) ke victim (destination).
    Victim masih bisa menerima dari host lain, dan attacker hanya di-block ke victim ini.
    """
    criteria = [
        {"type": "ETH_SRC", "mac": src_mac},  # Dari MAC attacker
        {"type": "ETH_DST", "mac": dst_mac}   # Ke MAC victim
    ]
    
    # Tambahkan IP filter untuk lebih spesifik (opsional tapi recommended)
    if src_ip and src_ip != "unknown":
        criteria.append({"type": "IPV4_SRC", "ip": f"{src_ip}/32"})
    if dst_ip and dst_ip != "unknown":
        criteria.append({"type": "IPV4_DST", "ip": f"{dst_ip}/32"})
    
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001",
        "treatment": {},  # Empty treatment = DROP
        "selector": {
            "criteria": criteria
        }
    }

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH, timeout=5)
        print(f"[MITIGASI] Block attacker: {src_mac} ({src_ip}) -> victim: {dst_mac} ({dst_ip})")
        print(f"           Status: {response.status_code}")
        print(f"           Note: Victim masih bisa terima traffic dari host lain")
        
        if response.status_code != 200:
            print(f"[ERROR] ONOS Response: {response.text[:200]}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] Submit mitigasi gagal: {e}")
        return False

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH, timeout=5)
        print(f"[MITIGASI SOURCE] Block {src_mac} -> {dst_mac} | Status: {response.status_code}")
        if response.status_code != 200:
            print(f"[ERROR] ONOS Response: {response.text[:200]}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] Submit mitigasi gagal: {e}")
        return False

def submit_mitigation_protect_destination(dst_mac, dst_ip):
    """
    Proteksi destination dengan rate limiting atau drop semua traffic
    ke destination (kecuali dari whitelist)
    """
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001",
        "treatment": {},  # Drop semua
        "selector": {
            "criteria": [
                {"type": "ETH_DST", "mac": dst_mac}
            ]
        }
    }

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH, timeout=5)
        print(f"[MITIGASI DESTINATION] Protect {dst_mac} ({dst_ip}) | Status: {response.status_code}")
        if response.status_code != 200:
            print(f"[ERROR] ONOS Response: {response.text[:200]}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] Submit mitigasi gagal: {e}")
        return False

def unblock_source(src_mac):
    """
    Unblock attacker: Hapus flow rule yang mem-block attacker ini.
    Setelah unblock, attacker bisa kirim traffic lagi (monitoring tetap berjalan).
    """
    BLOCKED_MACS.discard(src_mac)
    mitigated_state[src_mac]["active"] = False
    mitigated_state[src_mac]["timestamp"] = None
    mac_anomaly_count[src_mac] = 0
    
    print(f"\n{'='*60}")
    print(f"[UNBLOCK] Attacker {src_mac} di-unblock")
    print(f"          Attacker sekarang bisa kirim traffic lagi")
    print(f"          Sistem akan monitoring ulang jika ada serangan baru")
    print(f"{'='*60}\n")

    # Hapus flow rule dari ONOS
    try:
        delete_url = f"http://localhost:8181/onos/v1/flows/of:0000000000000001"
        flows = requests.get(delete_url, auth=AUTH, timeout=5).json()
        
        deleted_count = 0
        for flow in flows.get("flows", []):
            # Cari flow yang block src_mac ini
            for crit in flow.get("selector", {}).get("criteria", []):
                if crit.get("type") == "ETH_SRC" and crit.get("mac") == src_mac:
                    flow_id = flow.get("id")
                    device_id = flow.get("deviceId")
                    del_url = f"{ONOS_URL}/{device_id}/{flow_id}"
                    resp = requests.delete(del_url, auth=AUTH, timeout=5)
                    print(f"[UNBLOCK] Deleted flow rule {flow_id} | Status: {resp.status_code}")
                    deleted_count += 1
                    break
        
        if deleted_count == 0:
            print(f"[WARN] No flow rules found for {src_mac}")
        else:
            print(f"[SUCCESS] {deleted_count} flow rules deleted for {src_mac}")
            
    except Exception as e:
        print(f"[ERROR] Gagal hapus flow: {e}")

def unprotect_destination(dst_mac):
    """Remove protection dari destination"""
    PROTECTED_TARGETS.discard(dst_mac)
    
    print(f"[UNPROTECT] Destination {dst_mac} protection removed")

    try:
        delete_url = f"http://localhost:8181/onos/v1/flows/of:0000000000000001"
        flows = requests.get(delete_url, auth=AUTH, timeout=5).json()

        for flow in flows.get("flows", []):
            for crit in flow.get("selector", {}).get("criteria", []):
                if crit.get("type") == "ETH_DST" and crit.get("mac") == dst_mac:
                    flow_id = flow.get("id")
                    device_id = flow.get("deviceId")
                    del_url = f"{ONOS_URL}/{device_id}/{flow_id}"
                    resp = requests.delete(del_url, auth=AUTH, timeout=5)
                    print(f"[UNPROTECT] Hapus flow {flow_id} | Status: {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Gagal hapus flow: {e}")

def delayed_unblock_source(src_mac):
    """
    Auto-unblock attacker setelah UNBLOCK_DELAY detik.
    Ini memberi kesempatan kedua, tapi tetap di-monitor.
    """
    print(f"[AUTO-UNBLOCK] Scheduled untuk {src_mac} dalam {UNBLOCK_DELAY} detik")
    print(f"               Attacker akan di-unblock otomatis dan di-monitor ulang")
    time.sleep(UNBLOCK_DELAY)
    unblock_source(src_mac)
    print(f"[AUTO-UNBLOCK] {src_mac} sekarang bisa kirim traffic lagi")

def delayed_unprotect_destination(dst_mac, dst_ip):
    print(f"[TIMER] Scheduled unprotect untuk destination {dst_ip} dalam {UNBLOCK_DELAY} detik")
    time.sleep(UNBLOCK_DELAY)
    unprotect_destination(dst_mac)
    # Reset counter
    dst_anomaly_count[dst_ip] = 0
    attacking_sources[dst_ip].clear()

# --- Fungsi utama pemantauan dan mitigasi ---
def monitor_anomalies_and_mitigate(anomalies):
    global total_anomalies_received, total_mitigations_done
    
    print(f"\n[MONITOR] Received {len(anomalies)} flows | Mode: {MITIGATION_MODE}")
    
    ddos_flows = [a for a in anomalies if a.get("result") == 1 and a.get("status") == "predicted"]
    
    if not ddos_flows:
        print(f"[MONITOR] No DDoS detected in this batch")
        return
    
    print(f"[MONITOR] Found {len(ddos_flows)} DDoS flows")
    
    if MITIGATION_MODE == 'per_source':
        mitigate_per_source(ddos_flows)
    else:  # per_destination
        mitigate_per_destination(ddos_flows)

def mitigate_per_source(ddos_flows):
    """
    Mitigasi berdasarkan source MAC/Port.
    Jika USE_PORT_BLOCKING=True dan --rand-source terdeteksi, block port fisik.
    """
    global total_anomalies_received, total_mitigations_done
    
    # Detect if --rand-source is being used (banyak source berbeda ke 1 target)
    src_macs = set(a.get("src_mac") for a in ddos_flows if a.get("src_mac"))
    dst_ips = set(a.get("dst_ip") for a in ddos_flows if a.get("dst_ip"))
    
    is_distributed = len(src_macs) > 5 and len(dst_ips) == 1
    
    if is_distributed and USE_PORT_BLOCKING:
        print(f"\n[DETECTION] Distributed attack detected!")
        print(f"            Unique sources: {len(src_macs)}")
        print(f"            Target: {list(dst_ips)[0]}")
        print(f"            Switching to PORT-BASED blocking...")
        
        # Group by victim to find attacker patterns
        victim_attacks = {}
        for anomaly in ddos_flows:
            dst_ip = anomaly.get("dst_ip")
            if dst_ip not in victim_attacks:
                victim_attacks[dst_ip] = []
            victim_attacks[dst_ip].append(anomaly)
        
        for dst_ip, attacks in victim_attacks.items():
            # Take first source MAC as representative (they're all from same physical host)
            first_attack = attacks[0]
            src_mac = first_attack.get("src_mac")
            
            # Get physical port
            device_id, port = get_port_from_mac(src_mac)
            
            if device_id and port:
                print(f"[INFO] Attacker connected to {device_id} port {port}")
                print(f"[MITIGASI] Blocking PORT {port} (physical host block)")
                
                success = submit_mitigation_block_port(device_id, port)
                
                if success:
                    total_mitigations_done += 1
                    BLOCKED_MACS.add(f"PORT:{device_id}:{port}")
                    
                    print(f"[SUCCESS] Port {port} blocked - All MACs from this port blocked")
                    print(f"[INFO] Attacker cannot spoof anymore from this port")
                    
                    # Reset buffers
                    try:
                        requests.post(RESET_API, timeout=5)
                        requests.post(FLOW_SESSION_RESET, timeout=5)
                    except:
                        pass
                    
                    return  # Done, port blocked
            else:
                print(f"[WARN] Could not determine port, falling back to destination protection")
                # Fallback to destination protection
                mitigate_per_destination(ddos_flows)
                return
    
    # Normal per-source blocking (untuk single source attack)
    for anomaly in ddos_flows:
        total_anomalies_received += 1
        
        probability = anomaly.get("probability", 0)
        src_mac = anomaly.get("src_mac")
        dst_mac = anomaly.get("dst_mac")
        src_ip = anomaly.get("src_ip", "unknown")
        dst_ip = anomaly.get("dst_ip", "unknown")

        if not src_mac or not dst_mac:
            continue

        if probability >= BLOCK_THRESHOLD:
            mac_anomaly_count[src_mac] += 1
            
            print(f"[ANOMALI #{total_anomalies_received}] Attacker: {src_mac} ({src_ip}) -> Victim: {dst_mac} ({dst_ip})")
            print(f"           Probability: {probability:.4f} | Count: {mac_anomaly_count[src_mac]}/{REPEAT_LIMIT_SOURCE}")

            protocol = anomaly.get("protocol", "").lower()
            repeat_limit = 5 if protocol in ["1", "icmp"] else REPEAT_LIMIT_SOURCE

            if mac_anomaly_count[src_mac] >= repeat_limit and src_mac not in BLOCKED_MACS:
                print(f"\n{'='*60}")
                print(f"[MITIGASI TRIGGERED] Attacker threshold reached!")
                print(f"                      Attacker: {src_mac} ({src_ip})")
                print(f"                      Victim: {dst_mac} ({dst_ip})")
                print(f"                      Total attacks: {mac_anomaly_count[src_mac]}")
                print(f"{'='*60}")
                
                # Pilih metode mitigasi berdasarkan mode
                if MITIGATION_MODE == 'rate_limit':
                    print(f"[MODE] Rate limiting to {RATE_LIMIT_KBPS} Kbps")
                    success = submit_mitigation_rate_limit(src_mac, dst_mac, src_ip, dst_ip, RATE_LIMIT_KBPS)
                elif MITIGATION_MODE == 'temp_block':
                    print(f"[MODE] Temporary block for {TEMP_BLOCK_DURATION} seconds")
                    success = submit_mitigation_priority_drop(src_mac, dst_mac, src_ip, dst_ip)
                else:  # 'block' - permanent until manual/auto unblock
                    print(f"[MODE] Permanent block (auto-unblock in {UNBLOCK_DELAY}s)")
                    success = submit_mitigation_block_source(src_mac, dst_mac, src_ip, dst_ip)
                
                if success:
                    BLOCKED_MACS.add(src_mac)
                    total_mitigations_done += 1
                    
                    mitigated_state[src_mac].update({
                        "active": True,
                        "last_anomaly": anomaly,
                        "timestamp": time.time(),
                        "victim_ip": dst_ip,
                        "victim_mac": dst_mac,
                        "mode": MITIGATION_MODE
                    })
                    
                    if MITIGATION_MODE == 'temp_block':
                        print(f"[SUCCESS] Attacker {src_mac} temporarily blocked")
                        print(f"[INFO] Flow rule will auto-expire in {TEMP_BLOCK_DURATION} seconds")
                        print(f"[INFO] Attacker can then send normal traffic (ping, ssh)")
                        print(f"[INFO] But flood will be detected and blocked again")
                        
                        # Auto-remove from BLOCKED_MACS after duration
                        def delayed_cleanup(mac):
                            time.sleep(TEMP_BLOCK_DURATION + 5)  # +5 detik buffer
                            BLOCKED_MACS.discard(mac)
                            mac_anomaly_count[mac] = 0
                            print(f"[CLEANUP] {mac} removed from blocked list (temp block expired)")
                        
                        threading.Thread(target=delayed_cleanup, args=(src_mac,), daemon=True).start()
                    elif MITIGATION_MODE == 'rate_limit':
                        print(f"[SUCCESS] Attacker {src_mac} rate-limited to {RATE_LIMIT_KBPS} Kbps")
                        print(f"[INFO] Attacker can still ping/ssh but cannot flood")
                    else:
                        print(f"[SUCCESS] Attacker {src_mac} blocked permanently")
                        print(f"[INFO] Will auto-unblock in {UNBLOCK_DELAY} seconds")
                        threading.Thread(target=delayed_unblock_source, args=(src_mac,), daemon=True).start()
                    
                    # Reset buffer
                    try:
                        requests.post(RESET_API, timeout=5)
                        requests.post(FLOW_SESSION_RESET, timeout=5)
                        print(f"[RESET] Detection buffers cleared")
                    except:
                        pass

def mitigate_per_destination(ddos_flows):
    """Mitigasi berdasarkan destination (untuk distributed attack dengan --rand-source)"""
    global total_anomalies_received, total_mitigations_done
    
    # Aggregate per destination
    dst_attacks = defaultdict(list)
    for anomaly in ddos_flows:
        dst_ip = anomaly.get("dst_ip")
        if dst_ip:
            dst_attacks[dst_ip].append(anomaly)
    
    for dst_ip, attacks in dst_attacks.items():
        total_anomalies_received += len(attacks)
        dst_anomaly_count[dst_ip] += len(attacks)
        
        # Track unique attackers
        for attack in attacks:
            src_mac = attack.get("src_mac")
            if src_mac:
                attacking_sources[dst_ip].add(src_mac)
        
        unique_attackers = len(attacking_sources[dst_ip])
        avg_probability = sum(a.get("probability", 0) for a in attacks) / len(attacks)
        
        print(f"[ANOMALI] Target: {dst_ip}")
        print(f"          Attacks: {len(attacks)} flows | Total: {dst_anomaly_count[dst_ip]}")
        print(f"          Unique sources: {unique_attackers}")
        print(f"          Avg probability: {avg_probability:.4f}")
        
        # Ambil dst_mac dari salah satu attack
        dst_mac = attacks[0].get("dst_mac")
        protocol = attacks[0].get("protocol", "").lower()
        
        # Threshold lebih rendah untuk destination mode karena aggregate
        repeat_limit = 3 if protocol in ["1", "icmp"] else REPEAT_LIMIT_DESTINATION
        
        if dst_anomaly_count[dst_ip] >= repeat_limit and dst_mac not in PROTECTED_TARGETS:
            print(f"\n{'='*60}")
            print(f"[MITIGASI TRIGGERED] Destination under attack!")
            print(f"                      Target: {dst_ip} ({dst_mac})")
            print(f"                      Total attacks: {dst_anomaly_count[dst_ip]}")
            print(f"                      Unique attackers: {unique_attackers}")
            print(f"{'='*60}")
            
            success = submit_mitigation_protect_destination(dst_mac, dst_ip)
            
            if success:
                PROTECTED_TARGETS.add(dst_mac)
                total_mitigations_done += 1
                
                mitigated_state[dst_mac].update({
                    "active": True,
                    "last_anomaly": attacks[0],
                    "timestamp": time.time(),
                    "target_ip": dst_ip,
                    "attacker_count": unique_attackers
                })
                
                print(f"[SUCCESS] Destination protected: {dst_ip}")
                print(f"[INFO] All traffic to {dst_ip} is now blocked")
                print(f"[INFO] Detected attackers: {list(attacking_sources[dst_ip])[:5]}...")
                
                try:
                    requests.post(RESET_API, timeout=5)
                    requests.post(FLOW_SESSION_RESET, timeout=5)
                    print(f"[RESET] Buffers cleared")
                except:
                    pass
                
                threading.Thread(
                    target=delayed_unprotect_destination, 
                    args=(dst_mac, dst_ip), 
                    daemon=True
                ).start()
    
    print(f"\n[STATS] Mode: {MITIGATION_MODE}")
    print(f"[STATS] Total anomalies: {total_anomalies_received} | Mitigations: {total_mitigations_done}")
    
    if MITIGATION_MODE == 'per_source':
        print(f"[STATS] Blocked sources: {list(BLOCKED_MACS)}")
    else:
        print(f"[STATS] Protected targets: {list(PROTECTED_TARGETS)}")
        print(f"[STATS] Attack counts per target: {dict(dst_anomaly_count)}")

def get_last_mitigated_for(mac):
    return mitigated_state.get(mac, {}).get("last_anomaly")

def get_mitigation_stats():
    """Function untuk mendapatkan statistik mitigasi"""
    return {
        "mitigation_mode": MITIGATION_MODE,
        "total_anomalies_received": total_anomalies_received,
        "total_mitigations_done": total_mitigations_done,
        "per_source": {
            "blocked_macs": list(BLOCKED_MACS),
            "mac_anomaly_counts": dict(mac_anomaly_count)
        },
        "per_destination": {
            "protected_targets": list(PROTECTED_TARGETS),
            "dst_anomaly_counts": dict(dst_anomaly_count),
            "attacking_sources": {k: list(v) for k, v in attacking_sources.items()}
        },
        "active_mitigations": {k: v for k, v in mitigated_state.items() if v["active"]}
    }

# --- API Endpoints untuk Manual Control (Tambahkan ke Flask app atau buat baru) ---
from flask import Flask, request
app_mitigation = Flask(__name__)

@app_mitigation.route("/unblock", methods=["POST"])
def api_unblock():
    """
    Manual unblock attacker sebelum waktu auto-unblock.
    Usage: curl -X POST http://localhost:5051/unblock -H "Content-Type: application/json" -d '{"mac":"00:00:00:00:00:01"}'
    """
    data = request.get_json()
    mac = data.get("mac")
    
    if not mac:
        return {"error": "MAC address required"}, 400
    
    if mac not in BLOCKED_MACS:
        return {"error": f"MAC {mac} is not blocked"}, 404
    
    unblock_source(mac)
    return {
        "status": "success",
        "message": f"MAC {mac} has been unblocked manually",
        "timestamp": time.time()
    }, 200

@app_mitigation.route("/blocked", methods=["GET"])
def api_get_blocked():
    """
    List semua attacker yang sedang di-block.
    Usage: curl http://localhost:5051/blocked
    """
    blocked_list = []
    for mac in BLOCKED_MACS:
        state = mitigated_state.get(mac, {})
        blocked_list.append({
            "mac": mac,
            "victim_ip": state.get("victim_ip"),
            "victim_mac": state.get("victim_mac"),
            "blocked_since": state.get("timestamp"),
            "time_remaining": UNBLOCK_DELAY - (time.time() - state.get("timestamp", 0)) if state.get("timestamp") else 0
        })
    
    return {
        "blocked_count": len(BLOCKED_MACS),
        "blocked_attackers": blocked_list
    }, 200

@app_mitigation.route("/stats", methods=["GET"])
def api_get_stats():
    """
    Get mitigation statistics.
    Usage: curl http://localhost:5051/stats
    """
    return get_mitigation_stats(), 200

def run_mitigation_api():
    """Run Flask API untuk manual control"""
    app_mitigation.run(host="0.0.0.0", port=5051, debug=False, use_reloader=False)

# Start mitigation control API in background
threading.Thread(target=run_mitigation_api, daemon=True).start()
print("[INFO] Mitigation Control API running on port 5051")
