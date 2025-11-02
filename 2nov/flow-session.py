import csv
from collections import defaultdict
import requests
from scapy.sessions import DefaultSession
from datetime import datetime
import threading
from flask import Flask, jsonify

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow
import threading

# --- Konstanta ---
EXPIRED_UPDATE = 40                 # Naikkan dari 10 ke 40 detik untuk flow yang lebih panjang
ICMP_DURATION_THRESHOLD = 5         # Turunkan kembali ke 5 untuk deteksi lebih cepat
ICMP_PACKET_COUNT_THRESHOLD = 10    # Turunkan ke 10 untuk deteksi lebih cepat
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 500       # Naikkan dari 100 ke 500 untuk delay lebih lama
MIN_PACKETS_BEFORE_SEND = 5         # Minimal packet sebelum flow dikirim ke model

# --- Ambil reset_id dari model ---
def fetch_current_reset_id():
    try:
        resp = requests.get("http://localhost:8000/reset")
        if resp.status_code == 200:
            return resp.json().get("reset_id", str(datetime.now().timestamp()))
    except:
        pass
    return str(datetime.now().timestamp())

# --- FlowSession Class ---
class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        self.RESET_ID = fetch_current_reset_id()

        if self.output_mode == "flow":
            output = open(self.output_file, "w", newline="")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)

        global flow_session_instance
        flow_session_instance = self

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def upload_and_mitigate_icmp_flow(self, flow, direction, packet_flow_key, count):
        """Mengirim flow ICMP ke model ML/CSV, lalu reset flow-nya (tanpa blocking thread utama)"""
        data = flow.get_data()

        # --- MODE ONLINE ---
        if self.url_model:
            payload = {
                "columns": list(data.keys()),
                "data": [list(data.values())],
                "reset_id": self.RESET_ID
            }
            try:
                post = requests.post(
                    self.url_model,
                    json=payload,
                    headers={"Content-Type": "application/json; format=pandas-split"}
                )
                if post.status_code == 200:
                    resp = post.json()
                    print("[OK] ICMP Flow dikirim ke model.")
                    if isinstance(resp, list) and len(resp) > 0:
                        flow_result = resp[-1]
                        result = flow_result.get("result", 0)
                        probability = flow_result.get("probability", 0.0)  # PERBAIKAN: gunakan probability bukan score
                        
                        # PERBAIKAN: result=1 adalah DDoS, result=0 adalah Benign
                        result_print = "DDoS" if result == 1 else "Benign"

                        flow_data = {
                            "src_ip": data.get("src_ip", "-"),
                            "dst_ip": data.get("dst_ip", "-"),
                            "src_mac": data.get("src_mac", "-"),
                            "dst_mac": data.get("dst_mac", "-"),
                            "src_port": data.get("src_port", "-"),
                            "dst_port": data.get("dst_port", "-"),
                            "protocol": data.get("protocol", "-"),
                            "prediction": result_print,
                            "probability": round(probability, 4)  # PERBAIKAN: gunakan probability
                        }

                        # Kirim ke dashboard
                        try:
                            requests.post("http://localhost:8050/flow-prediction", json=flow_data)
                        except Exception as e:
                            print("Gagal kirim ke dashboard:", e)
            except Exception as e:
                print("[ERROR] Gagal mengirim flow ICMP:", e)

        # --- MODE OFFLINE ---
        else:
            if self.csv_line == 0:
                self.csv_writer.writerow(data.keys())
            self.csv_writer.writerow(data.values())
            self.csv_line += 1
            print("[OK] ICMP Flow ditulis ke CSV.")

        # Reset flow: buat flow baru tanpa packet lama
        count += 1
        self.flows[(packet_flow_key, count)] = Flow(flow.packets[-1][0], direction)
        print(f"[INFO] Flow ICMP di-reset (paralel)")    

    def on_packet_received(self, packet):
        print(">> Packet received:", packet.summary())
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if not any(proto in packet for proto in ("TCP", "UDP", "ICMP")):
                return
        try:
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        if flow is None:
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow
            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))
                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))
                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)
        print("[+] Packet added to flow")

        if flow.protocol == 1:
            if flow.duration >= ICMP_DURATION_THRESHOLD and len(flow.packets) >= ICMP_PACKET_COUNT_THRESHOLD:
                print("[!] Deteksi ICMP: Mengunggah dan membuat flow baru secara paralel...")

                # Jalankan upload & reset flow ICMP dalam thread terpisah
                threading.Thread(
                    target=self.upload_and_mitigate_icmp_flow,
                    args=(flow, direction, packet_flow_key, count),
                    daemon=True
                ).start()

                return  # Hindari lanjut proses di bawahnya


        if not self.url_model:
            self.garbage_collect_packets = 1000
        else:
            self.garbage_collect_packets = GARBAGE_COLLECT_PACKETS

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

        print(f"[DEBUG] Packet #{self.packets_count} - Flow count: {len(self.flows)}")

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        print("[*] Running garbage collection...")
        if not self.url_model:
            print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            if flow is None:
                continue  # flow sudah dihapus, skip

            # baris ini untuk skip flow yang belum punya packet
            if len(flow.packets) == 0:
                continue

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 120
            ):
                data = flow.get_data()
                if self.url_model:
                    payload = {
                        "columns": list(data.keys()),
                        "data": [list(data.values())],
                        "reset_id": self.RESET_ID
                    }
                    post = requests.post(
                        self.url_model,
                        json=payload,
                        headers={"Content-Type": "application/json; format=pandas-split"}
                    )
                    if post.status_code != 200:
                        print("[ERROR] Gagal request ke model.", post.status_code)
                        continue
                    resp = post.json()
                    if isinstance(resp, list) and len(resp) > 0:
                        flow_result = resp[-1]
                        result = flow_result.get("result", 0)
                        probability = flow_result.get("probability", 0.0)  # PERBAIKAN: gunakan probability bukan score
                        
                        # PERBAIKAN: result=1 adalah DDoS, result=0 adalah Benign
                        result_print = "DDoS" if result == 1 else "Benign"
                    else:
                        print("[WARNING] Response model kosong atau tidak sesuai format.")
                        result_print = "Benign"
                        probability = 0.0
                    flow_data = {
                        "src_ip": data.get("src_ip", "-"),
                        "dst_ip": data.get("dst_ip", "-"),
                        "src_mac": data.get("src_mac", "-"),
                        "dst_mac": data.get("dst_mac", "-"),
                        "src_port": data.get("src_port", "-"),
                        "dst_port": data.get("dst_port", "-"),
                        "protocol": data.get("protocol", "-"),
                        "prediction": result_print,
                        "probability": round(probability, 4)  # PERBAIKAN: gunakan probability
                    }
                    try:
                        requests.post("http://localhost:8050/flow-prediction", json=flow_data)
                    except Exception as e:
                        print("Gagal kirim ke dashboard:", e)
                if self.csv_line == 0:
                    self.csv_writer.writerow(data.keys())
                print(f"[>] Writing flow with duration {flow.duration:.2f}s")
                self.csv_writer.writerow(data.values())
                self.csv_line += 1
                self.flows.pop(k, None)
        if not self.url_model:
            print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))

# --- Flask App untuk Reset External ---
app_reset = Flask(__name__)
flow_session_instance = None

@app_reset.route("/reset", methods=["POST"])
def reset_flows():
    global flow_session_instance
    if flow_session_instance:
        flow_session_instance.flows.clear()
        flow_session_instance.packets_count = 0
        print("[RESET] Semua flow aktif dibersihkan dari memori.")
        return jsonify({"status": "cleared"}), 200
    return jsonify({"error": "FlowSession belum terinisialisasi"}), 500

def run_reset_server():
    app_reset.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)

threading.Thread(target=run_reset_server, daemon=True).start()

# --- Generator Session ---
def generate_session_class(output_mode, output_file, url_model):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
        },
    )
