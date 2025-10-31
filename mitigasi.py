import requests
import threading
import time
from collections import defaultdict

# --- Konstanta dan Auth ---
ONOS_URL = "http://localhost:8181/onos/v1/flows"
AUTH = ('onos', 'rocks')
BLOCK_THRESHOLD = 0.5
REPEAT_LIMIT = 50
RESET_API = "http://localhost:8000/reset"
FLOW_SESSION_RESET = "http://localhost:5050/reset"
UNBLOCK_DELAY = 30  # detik

# --- State dan Tracking ---
BLOCKED_MACS = set()
mac_anomaly_count = defaultdict(int)
mitigated_state = defaultdict(lambda: {"active": False, "timestamp": None, "last_anomaly": None})

# --- Mitigasi ke ONOS ---
def submit_mitigation(src_mac, dst_mac):
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001",  # Ganti sesuai ID perangkatmu
        "treatment": {},
        "selector": {
            "criteria": [
                {"type": "ETH_SRC", "mac": src_mac},
                {"type": "ETH_DST", "mac": dst_mac}
            ]
        }
    }

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH)
        print(f"[MITIGASI] Rule blokir {src_mac} → {dst_mac} | Status: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Submit mitigasi gagal: {e}")

def unblock_mac(src_mac):
    BLOCKED_MACS.discard(src_mac)
    mitigated_state[src_mac]["active"] = False
    mitigated_state[src_mac]["timestamp"] = None
    print(f"[UNBLOCK] MAC {src_mac} diizinkan kembali")

    # Hapus flow rule blokir dari ONOS
    try:
        delete_url = f"http://localhost:8181/onos/ui/of:0000000000000001"
        flows = requests.get(delete_url, auth=AUTH).json()

        for flow in flows.get("flows", []):
            for crit in flow.get("selector", {}).get("criteria", []):
                if crit.get("type") == "ETH_SRC" and crit.get("mac") == src_mac:
                    flow_id = flow.get("id")
                    device_id = flow.get("deviceId")
                    del_url = f"{ONOS_URL}/{device_id}/{flow_id}"
                    resp = requests.delete(del_url, auth=AUTH)
                    print(f"[UNBLOCK] Hapus flow {flow_id} | Status: {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Gagal hapus flow blokir {src_mac}: {e}")

def delayed_unblock(src_mac):
    time.sleep(UNBLOCK_DELAY)
    unblock_mac(src_mac)
    print(f"[MITIGASI] Sistem siap mendeteksi ulang untuk {src_mac}")

# --- Fungsi utama pemantauan dan mitigasi ---
def monitor_anomalies_and_mitigate(anomalies):
    for anomaly in anomalies:
        
        probability = anomaly.get("probability", 0)
        src_mac = anomaly.get("src_mac")
        dst_mac = anomaly.get("dst_mac")
        result = anomaly.get("result", 0)  # Tambahkan ini

        if not src_mac or not dst_mac:
            continue

        # hanya proses jika result == 1 (DDoS)
        if result == 1 and probability >= BLOCK_THRESHOLD:
            mac_anomaly_count[src_mac] += 1
            print(f"[ANOMALI] {src_mac} → {dst_mac} | Probability: {probability:.4f} | Count: {mac_anomaly_count[src_mac]}")

            # Tentukan repeat limit berdasarkan protokol
            default_repeat_limit = REPEAT_LIMIT
            protocol = anomaly.get("protocol", "").lower()

            if protocol in ["1", "icmp"]:
                repeat_limit = 30
            else:
                repeat_limit = default_repeat_limit

            # Mitigasi jika jumlah anomali melebihi repeat limit
            if mac_anomaly_count[src_mac] >= repeat_limit and src_mac not in BLOCKED_MACS:
                submit_mitigation(src_mac, dst_mac)
                BLOCKED_MACS.add(src_mac)

                mitigated_state[src_mac].update({
                    "active": True,
                    "last_anomaly": anomaly,
                    "timestamp": time.time()
                })

                try:
                    requests.post(RESET_API)
                    requests.post(FLOW_SESSION_RESET)
                    print(f"[RESET] Buffer anomaly dan flow aktif dibersihkan untuk {src_mac}")
                except Exception as e:
                    print(f"[ERROR] Gagal reset buffer: {e}")

                threading.Thread(target=delayed_unblock, args=(src_mac,), daemon=True).start()

def get_last_mitigated_for(mac):
    return mitigated_state.get(mac, {}).get("last_anomaly")
