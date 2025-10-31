from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import joblib
import pandas as pd
import json
import numpy as np
import logging
from datetime import datetime
from mitigasi import monitor_anomalies_and_mitigate
from mitigasi import get_last_mitigated_for
from threading import Thread
import tensorflow as tf
from collections import deque

logging.basicConfig(level=logging.DEBUG)
app = FastAPI()
current_reset_id = str(datetime.now().timestamp())

# List untuk menyimpan data anomali terakhir
recent_anomalies = []

# Dictionary untuk menyimpan buffer sequence per IP source
# Format: {src_ip: deque([flow1, flow2, ..., flow5])}
sequence_buffers = {}

# Load model LSTM, scaler, dan fitur
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

# Konstanta dari training
TIMESTEPS = 5
THRESHOLD = 0.5  # Threshold untuk klasifikasi (probability >= 0.5 = DDoS)

class FlowData(BaseModel):
    columns: list
    data: list

def create_sequence_for_prediction(flow_features, src_ip):
    """
    Membuat sequence untuk prediksi LSTM
    Args:
        flow_features: numpy array dengan shape (n_features,)
        src_ip: IP source untuk tracking sequence
    Returns:
        sequence: numpy array dengan shape (1, TIMESTEPS, n_features) atau None jika belum cukup
    """
    # Inisialisasi buffer untuk IP baru
    if src_ip not in sequence_buffers:
        sequence_buffers[src_ip] = deque(maxlen=TIMESTEPS)
    
    # Tambahkan flow saat ini ke buffer
    sequence_buffers[src_ip].append(flow_features)
    
    # Jika buffer belum penuh, return None
    if len(sequence_buffers[src_ip]) < TIMESTEPS:
        return None
    
    # Buat sequence dari buffer
    sequence = np.array(list(sequence_buffers[src_ip]))
    sequence = sequence.reshape(1, TIMESTEPS, len(FEATURES))
    
    return sequence

@app.post("/predict")
async def predict(flow: FlowData):
    df = pd.DataFrame(flow.data, columns=flow.columns)
    
    # Jika reset_id tidak cocok, abaikan
    if "reset_id" in df.columns and not (df["reset_id"] == current_reset_id).all():
        return JSONResponse(content=[])
    
    try:
        # Ekstrak fitur yang diperlukan
        X = df[FEATURES]
        
        # Scale features menggunakan RobustScaler
        X_scaled = scaler.transform(X)
        
        # Clip extreme outliers (sesuai dengan training)
        X_scaled = np.clip(X_scaled, -5, 5)
        
    except Exception as e:
        logging.error(f"Error in feature extraction/scaling: {str(e)}")
        return {"error": str(e)}
    
    response_list = []
    
    for i in range(len(df)):
        src_ip = str(df.get("src_ip", ["N/A"])[i])
        
        # Buat sequence untuk flow ini
        sequence = create_sequence_for_prediction(X_scaled[i], src_ip)
        
        # Jika sequence belum cukup, tandai sebagai "buffering"
        if sequence is None:
            flow_result = {
                "result": 0,  # Anggap benign sementara
                "probability": 0.0,
                "status": "buffering",
                "buffer_size": len(sequence_buffers.get(src_ip, [])),
                "required_size": TIMESTEPS,
                "src_ip": src_ip,
                "src_mac": str(df.get("src_mac", ["N/A"])[i]),
                "src_port": int(df.get("src_port", ["N/A"])[i]) if str(df.get("src_port", ["N/A"])[i]).isdigit() else str(df.get("src_port", ["N/A"])[i]),
                "dst_ip": str(df.get("dst_ip", ["N/A"])[i]),
                "dst_mac": str(df.get("dst_mac", ["N/A"])[i]),
                "dst_port": int(df.get("dst_port", ["N/A"])[i]) if str(df.get("dst_port", ["N/A"])[i]).isdigit() else str(df.get("dst_port", ["N/A"])[i]),
                "protocol": str(df.get("protocol", ["N/A"])[i])
            }
            response_list.append(flow_result)
            continue
        
        try:
            # Prediksi menggunakan LSTM
            probability = model.predict(sequence, verbose=0)[0][0]
            result = 1 if probability >= THRESHOLD else 0  # 1 = DDoS, 0 = Benign
            
            flow_result = {
                "result": int(result),
                "probability": float(probability),
                "status": "predicted",
                "prediction_label": "DDoS" if result == 1 else "Benign",
                "src_ip": src_ip,
                "src_mac": str(df.get("src_mac", ["N/A"])[i]),
                "src_port": int(df.get("src_port", ["N/A"])[i]) if str(df.get("src_port", ["N/A"])[i]).isdigit() else str(df.get("src_port", ["N/A"])[i]),
                "dst_ip": str(df.get("dst_ip", ["N/A"])[i]),
                "dst_mac": str(df.get("dst_mac", ["N/A"])[i]),
                "dst_port": int(df.get("dst_port", ["N/A"])[i]) if str(df.get("dst_port", ["N/A"])[i]).isdigit() else str(df.get("dst_port", ["N/A"])[i]),
                "protocol": str(df.get("protocol", ["N/A"])[i])
            }
            
            # Jika terdeteksi sebagai DDoS (result == 1), simpan sebagai anomali
            if flow_result["result"] == 1:
                recent_anomalies.append(flow_result)
                if len(recent_anomalies) > 50:  # batasi 50 anomali terakhir
                    recent_anomalies.pop(0)
            
            response_list.append(flow_result)
            
        except Exception as e:
            logging.error(f"Error in prediction: {str(e)}")
            flow_result = {
                "result": 0,
                "probability": 0.0,
                "status": "error",
                "error": str(e),
                "src_ip": src_ip,
                "src_mac": str(df.get("src_mac", ["N/A"])[i]),
                "src_port": int(df.get("src_port", ["N/A"])[i]) if str(df.get("src_port", ["N/A"])[i]).isdigit() else str(df.get("src_port", ["N/A"])[i]),
                "dst_ip": str(df.get("dst_ip", ["N/A"])[i]),
                "dst_mac": str(df.get("dst_mac", ["N/A"])[i]),
                "dst_port": int(df.get("dst_port", ["N/A"])[i]) if str(df.get("dst_port", ["N/A"])[i]).isdigit() else str(df.get("dst_port", ["N/A"])[i]),
                "protocol": str(df.get("protocol", ["N/A"])[i])
            }
            response_list.append(flow_result)
    
    # Monitor anomali dan lakukan mitigasi
    Thread(target=monitor_anomalies_and_mitigate, args=(response_list,), daemon=True).start()
    
    return JSONResponse(content=response_list)

@app.get("/anomalies")
def get_anomalies(mac: str = None):
    return {
        "recent": recent_anomalies[-20:], 
        "last_mitigated": get_last_mitigated_for(mac) if mac else None
    }

@app.post("/reset")
def reset_anomaly_buffer():
    global current_reset_id
    recent_anomalies.clear()
    sequence_buffers.clear()  # Clear sequence buffers juga
    current_reset_id = str(datetime.now().timestamp())
    return {
        "status": "anomaly buffer and sequence buffers cleared", 
        "reset_id": current_reset_id
    }

@app.get("/buffer_status")
def get_buffer_status():
    """Endpoint untuk melihat status buffer sequence per IP"""
    buffer_info = {}
    for src_ip, buffer in sequence_buffers.items():
        buffer_info[src_ip] = {
            "current_size": len(buffer),
            "required_size": TIMESTEPS,
            "ready_for_prediction": len(buffer) >= TIMESTEPS
        }
    return JSONResponse(content=buffer_info)

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "model_loaded": True,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/model_info")
def get_model_info():
    """Endpoint untuk melihat informasi model"""
    return {
        "model_type": "Bidirectional LSTM",
        "timesteps": TIMESTEPS,
        "features_count": len(FEATURES),
        "threshold": THRESHOLD,
        "input_shape": f"(batch_size, {TIMESTEPS}, {len(FEATURES)})"
    }