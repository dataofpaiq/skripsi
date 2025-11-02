import requests
import threading
import time
from collections import defaultdict

# --- Konstanta dan Auth ---
ONOS_URL = "http://localhost:8181/onos/v1/flows"
AUTH = ('onos', 'rocks')
BLOCK_THRESHOLD = -0.017323
REPEAT_LIMIT = 50
RESET_API = "http://localhost:8000/reset"
FLOW_SESSION_RESET = "http://localhost:5050/reset"
UNBLOCK_DELAY = 30

# --- State dan Tracking ---
BLOCKED_MACS = set()
mac_anomaly_count = defaultdict(int)
mitigated_state = defaultdict(lambda: {"active": False, "timestamp": None, "last_anomaly": None})

# Track flow IDs untuk memudahkan penghapusan
mitigation_flow_ids = defaultdict(list)

# --- Submit Mitigasi ke ONOS ---
def submit_mitigation(src_mac, dst_mac):
    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001",
        "treatment": {},
        "selector": {
            "criteria": [
                {"type": "ETH_SRC", "mac": src_mac},
                {"type": "ETH_DST", "mac": dst_mac}
            ]
        }
    }

    try:
        response = requests.post(ONOS_URL, json={"flows": [flow]}, auth=AUTH, timeout=5)
        if response.status_code in [200, 201]:
            result = response.json()
            if "flows" in result and len(result["flows"]) > 0:
                flow_id = result["flows"][0].get("id")
                mitigation_flow_ids[src_mac].append({
                    "flow_id": flow_id,
                    "device_id": "of:0000000000000001",
                    "src_mac": src_mac,
                    "dst_mac": dst_mac
                })
                print(f"[MITIGASI] Rule blokir {src_mac} → {dst_mac} | Status: {response.status_code}")
        else:
            print(f"[MITIGASI] Rule blokir {src_mac} → {dst_mac} | Status: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Submit mitigasi gagal: {e}")

# --- Unblock MAC ---
def unblock_mac(src_mac):
    if src_mac not in mitigation_flow_ids:
        return
    
    flow_list = mitigation_flow_ids[src_mac]
    
    for flow_info in flow_list:
        flow_id = flow_info.get("flow_id")
        device_id = flow_info.get("device_id")
        
        if not flow_id or not device_id:
            continue
        
        try:
            del_url = f"http://localhost:8181/onos/v1/flows/of:0000000000000001"
            resp = requests.delete(del_url, auth=AUTH, timeout=5)
            if resp.status_code in [200, 204]:
                print(f"[UNBLOCK] Hapus flow {flow_id} | Status: {resp.status_code}")
        except Exception as e:
            print(f"[ERROR] Gagal hapus flow {src_mac}: {e}")
    
    # Reset state
    mitigation_flow_ids[src_mac].clear()
    BLOCKED_MACS.discard(src_mac)
    mitigated_state[src_mac]["active"] = False
    mitigated_state[src_mac]["timestamp"] = None
    mac_anomaly_count[src_mac] = 0

def delayed_unblock(src_mac):
    time.sleep(UNBLOCK_DELAY)
    unblock_mac(src_mac)

# --- Monitor dan Mitigasi ---
def monitor_anomalies_and_mitigate(anomalies):
    for anomaly in anomalies:
        score = anomaly.get("score", 0)
        src_mac = anomaly.get("src_mac")
        dst_mac = anomaly.get("dst_mac")

        if not src_mac or not dst_mac:
            continue

        if score < BLOCK_THRESHOLD:
            mac_anomaly_count[src_mac] += 1
            print(f"[ANOMALI] {src_mac} → {dst_mac} | Score: {score:.4f} | Count: {mac_anomaly_count[src_mac]}")

            # Tentukan repeat limit berdasarkan protokol
            protocol = anomaly.get("protocol", "").lower()
            repeat_limit = 30 if protocol in ["1", "icmp"] else REPEAT_LIMIT

            # Mitigasi jika threshold tercapai
            if mac_anomaly_count[src_mac] >= repeat_limit and src_mac not in BLOCKED_MACS:
                submit_mitigation(src_mac, dst_mac)
                BLOCKED_MACS.add(src_mac)

                mitigated_state[src_mac].update({
                    "active": True,
                    "last_anomaly": anomaly,
                    "timestamp": time.time()
                })

                # Reset buffer
                try:
                    requests.post(RESET_API, timeout=5)
                    requests.post(FLOW_SESSION_RESET, timeout=5)
                    print(f"[RESET] Buffer anomaly dan flow aktif dibersihkan untuk {src_mac}")
                except Exception as e:
                    print(f"[ERROR] Gagal reset buffer: {e}")

                # Schedule unblock
                threading.Thread(target=delayed_unblock, args=(src_mac,), daemon=True).start()

def get_last_mitigated_for(mac):
    return mitigated_state.get(mac, {}).get("last_anomaly")
