from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import joblib
import pandas as pd
import json
import numpy as np
import logging
from datetime import datetime
from mitigasi_improved import monitor_anomalies_and_mitigate
from mitigasi_improved import get_last_mitigated_for
from threading import Thread
import tensorflow as tf
from collections import deque, defaultdict
import signal
import sys
import atexit

# Membersihkan sseluruh flow bray
def cleanup_on_exit():
    
    try:
        # Ambil semua flow rules
        response = requests.get(
            "http://localhost:8181/onos/v1/flows/of:0000000000000001",
            auth=('onos', 'rocks'),
            timeout=5
        )
        
        if response.status_code == 200:
            flows = response.json().get("flows", [])
            
            # Hapus flow rules dengan priority 40000 (mitigasi rules)
            for flow in flows:
                if flow.get("priority") == 40000:
                    flow_id = flow.get("id")
                    device_id = flow.get("deviceId")
                    
                    del_url = f"http://localhost:8181/onos/v1/flows/{device_id}/{flow_id}"
                    del_resp = requests.delete(del_url, auth=('onos', 'rocks'), timeout=5)
                    
                    print(f"[CLEANUP] Removed flow {flow_id}: {del_resp.status_code}")
            
            print("[CLEANUP] All mitigation flows removed")
        
        # Reset buffers juga
        requests.post("http://localhost:8000/reset", timeout=5)
        requests.post("http://localhost:5050/reset", timeout=5)
        print("[CLEANUP] Buffers cleared")
        
    except Exception as e:
        print(f"[CLEANUP ERROR] {e}")

# Signal handler untuk Ctrl+C
def signal_handler(sig, frame):
    print("\n[SIGNAL] Received interrupt signal")
    cleanup_on_exit()
    sys.exit(0)

# Register handlers
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Kill signal
atexit.register(cleanup_on_exit)               # Normal exit

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI()
current_reset_id = str(datetime.now().timestamp())

recent_anomalies = []

# PERUBAHAN: Buffer per source IP DAN buffer global per destination IP
sequence_buffers_per_src = {}  # Per source IP (original)
sequence_buffers_per_dst = defaultdict(lambda: deque(maxlen=5))  # Per destination IP (NEW)

prediction_count = 0
buffering_count = 0

# Load model
print("Loading LSTM model...")
model = tf.keras.models.load_model("lstm_model.keras")
print("Model loaded successfully!")

print("Loading scaler...")
scaler = joblib.load("robust_scaler.pkl")
print("Scaler loaded successfully!")

print("Loading selected features...")
with open("selected_features_lstm.json") as f:
    FEATURES = json.load(f)
print(f"Loaded {len(FEATURES)} features")

TIMESTEPS = 5
THRESHOLD = 0.5

# Mode deteksi: 'per_source' atau 'per_destination'
DETECTION_MODE = 'per_source'  # Ubah ini untuk ganti mode

class FlowData(BaseModel):
    columns: list
    data: list

def create_sequence_per_source(flow_features, src_ip):
    """Buffer per source IP (original method)"""
    if src_ip not in sequence_buffers_per_src:
        sequence_buffers_per_src[src_ip] = deque(maxlen=TIMESTEPS)
        logger.info(f"Created new buffer for source IP: {src_ip}")
    
    sequence_buffers_per_src[src_ip].append(flow_features)
    current_buffer_size = len(sequence_buffers_per_src[src_ip])
    
    if current_buffer_size < TIMESTEPS:
        return None
    
    sequence = np.array(list(sequence_buffers_per_src[src_ip]))
    sequence = sequence.reshape(1, TIMESTEPS, len(FEATURES))
    
    return sequence

def create_sequence_per_destination(flow_features, dst_ip):
    """Buffer per destination IP (untuk distributed attack)"""
    sequence_buffers_per_dst[dst_ip].append(flow_features)
    current_buffer_size = len(sequence_buffers_per_dst[dst_ip])
    
    logger.debug(f"Destination {dst_ip}: Buffer {current_buffer_size}/{TIMESTEPS}")
    
    if current_buffer_size < TIMESTEPS:
        return None
    
    sequence = np.array(list(sequence_buffers_per_dst[dst_ip]))
    sequence = sequence.reshape(1, TIMESTEPS, len(FEATURES))
    
    return sequence

@app.post("/predict")
async def predict(flow: FlowData):
    global prediction_count, buffering_count
    
    logger.info(f"=== Received {len(flow.data)} flows (Mode: {DETECTION_MODE}) ===")
    
    df = pd.DataFrame(flow.data, columns=flow.columns)
    
    if len(df) > 0:
        sample = df.head(1).to_dict('records')[0]
        logger.info(f"Sample: src={sample.get('src_ip')} -> dst={sample.get('dst_ip')}, proto={sample.get('protocol')}")
    
    if "reset_id" in df.columns and not (df["reset_id"] == current_reset_id).all():
        logger.warning("Reset ID mismatch, ignoring flows")
        return JSONResponse(content=[])
    
    try:
        missing_features = [f for f in FEATURES if f not in df.columns]
        if missing_features:
            logger.error(f"Missing features: {missing_features}")
            return {"error": f"Missing required features: {missing_features}"}
        
        X = df[FEATURES]
        X_scaled = scaler.transform(X)
        X_scaled = np.clip(X_scaled, -5, 5)
        
    except Exception as e:
        logger.error(f"Error in feature extraction/scaling: {str(e)}", exc_info=True)
        return {"error": str(e)}
    
    response_list = []
    
    for i in range(len(df)):
        src_ip = str(df.iloc[i].get("src_ip", "N/A"))
        dst_ip = str(df.iloc[i].get("dst_ip", "N/A"))
        
        # Pilih metode buffering berdasarkan mode
        if DETECTION_MODE == 'per_source':
            sequence = create_sequence_per_source(X_scaled[i], src_ip)
            buffer_key = src_ip
            buffer_size = len(sequence_buffers_per_src.get(src_ip, []))
        else:  # per_destination
            sequence = create_sequence_per_destination(X_scaled[i], dst_ip)
            buffer_key = dst_ip
            buffer_size = len(sequence_buffers_per_dst.get(dst_ip, []))
        
        if sequence is None:
            buffering_count += 1
            flow_result = {
                "result": 0,
                "probability": 0.0,
                "status": "buffering",
                "buffer_key": buffer_key,
                "buffer_size": buffer_size,
                "required_size": TIMESTEPS,
                "detection_mode": DETECTION_MODE,
                "src_ip": src_ip,
                "src_mac": str(df.iloc[i].get("src_mac", "N/A")),
                "src_port": int(df.iloc[i].get("src_port", 0)) if str(df.iloc[i].get("src_port", 0)).isdigit() else str(df.iloc[i].get("src_port", "N/A")),
                "dst_ip": dst_ip,
                "dst_mac": str(df.iloc[i].get("dst_mac", "N/A")),
                "dst_port": int(df.iloc[i].get("dst_port", 0)) if str(df.iloc[i].get("dst_port", 0)).isdigit() else str(df.iloc[i].get("dst_port", "N/A")),
                "protocol": str(df.iloc[i].get("protocol", "N/A"))
            }
            response_list.append(flow_result)
            continue
        
        try:
            probability = model.predict(sequence, verbose=0)[0][0]
            result = 1 if probability >= THRESHOLD else 0
            prediction_count += 1
            
            logger.info(f"PREDICTION #{prediction_count} - {buffer_key} | Prob: {probability:.4f} | {'DDoS' if result == 1 else 'Benign'}")
            
            flow_result = {
                "result": int(result),
                "probability": float(probability),
                "status": "predicted",
                "prediction_label": "DDoS" if result == 1 else "Benign",
                "detection_mode": DETECTION_MODE,
                "buffer_key": buffer_key,
                "src_ip": src_ip,
                "src_mac": str(df.iloc[i].get("src_mac", "N/A")),
                "src_port": int(df.iloc[i].get("src_port", 0)) if str(df.iloc[i].get("src_port", 0)).isdigit() else str(df.iloc[i].get("src_port", "N/A")),
                "dst_ip": dst_ip,
                "dst_mac": str(df.iloc[i].get("dst_mac", "N/A")),
                "dst_port": int(df.iloc[i].get("dst_port", 0)) if str(df.iloc[i].get("dst_port", 0)).isdigit() else str(df.iloc[i].get("dst_port", "N/A")),
                "protocol": str(df.iloc[i].get("protocol", "N/A"))
            }
            
            if flow_result["result"] == 1:
                logger.warning(f"DDoS DETECTED targeting {dst_ip} (prob: {probability:.4f})")
                recent_anomalies.append(flow_result)
                if len(recent_anomalies) > 50:
                    recent_anomalies.pop(0)
            
            response_list.append(flow_result)
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}", exc_info=True)
            flow_result = {
                "result": 0,
                "probability": 0.0,
                "status": "error",
                "error": str(e),
                "src_ip": src_ip,
                "src_mac": str(df.iloc[i].get("src_mac", "N/A")),
                "src_port": int(df.iloc[i].get("src_port", 0)) if str(df.iloc[i].get("src_port", 0)).isdigit() else str(df.iloc[i].get("src_port", "N/A")),
                "dst_ip": dst_ip,
                "dst_mac": str(df.iloc[i].get("dst_mac", "N/A")),
                "dst_port": int(df.iloc[i].get("dst_port", 0)) if str(df.iloc[i].get("dst_port", 0)).isdigit() else str(df.iloc[i].get("dst_port", "N/A")),
                "protocol": str(df.iloc[i].get("protocol", "N/A"))
            }
            response_list.append(flow_result)
    
    detected_ddos = [r for r in response_list if r.get("result") == 1 and r.get("status") == "predicted"]
    if detected_ddos:
        logger.warning(f"Sending {len(detected_ddos)} DDoS flows to mitigation")
        Thread(target=monitor_anomalies_and_mitigate, args=(response_list,), daemon=True).start()
    
    return JSONResponse(content=response_list)

@app.get("/anomalies")
def get_anomalies(mac: str = None):
    return {
        "recent": recent_anomalies[-20:], 
        "last_mitigated": get_last_mitigated_for(mac) if mac else None,
        "total_anomalies": len(recent_anomalies)
    }

@app.post("/reset")
def reset_anomaly_buffer():
    global current_reset_id, prediction_count, buffering_count
    recent_anomalies.clear()
    sequence_buffers_per_src.clear()
    sequence_buffers_per_dst.clear()
    prediction_count = 0
    buffering_count = 0
    current_reset_id = str(datetime.now().timestamp())
    logger.info("=== SYSTEM RESET ===")
    return {
        "status": "all buffers cleared", 
        "reset_id": current_reset_id
    }

@app.get("/buffer_status")
def get_buffer_status():
    if DETECTION_MODE == 'per_source':
        buffers = sequence_buffers_per_src
    else:
        buffers = dict(sequence_buffers_per_dst)
    
    buffer_info = {}
    for key, buffer in buffers.items():
        buffer_info[key] = {
            "current_size": len(buffer),
            "required_size": TIMESTEPS,
            "ready_for_prediction": len(buffer) >= TIMESTEPS
        }
    
    return JSONResponse(content={
        "detection_mode": DETECTION_MODE,
        "buffers": buffer_info,
        "total_keys": len(buffer_info),
        "total_predictions": prediction_count,
        "total_buffering": buffering_count
    })

@app.post("/set_mode")
def set_detection_mode(mode: str):
    global DETECTION_MODE
    if mode not in ['per_source', 'per_destination']:
        return {"error": "Mode must be 'per_source' or 'per_destination'"}
    
    DETECTION_MODE = mode
    logger.info(f"Detection mode changed to: {DETECTION_MODE}")
    return {"status": "ok", "detection_mode": DETECTION_MODE}

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "model_loaded": True,
        "detection_mode": DETECTION_MODE,
        "timestamp": datetime.now().isoformat(),
        "predictions_made": prediction_count,
        "flows_buffering": buffering_count,
        "active_buffers": len(sequence_buffers_per_src) if DETECTION_MODE == 'per_source' else len(sequence_buffers_per_dst)
    }

@app.get("/model_info")
def get_model_info():
    return {
        "model_type": "Bidirectional LSTM",
        "timesteps": TIMESTEPS,
        "features_count": len(FEATURES),
        "features": FEATURES,
        "threshold": THRESHOLD,
        "detection_mode": DETECTION_MODE,
        "input_shape": f"(batch_size, {TIMESTEPS}, {len(FEATURES)})"
    }
