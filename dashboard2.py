import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
import time
from datetime import datetime
from collections import defaultdict
import subprocess
import os
import signal
import atexit
import sys

# Import mitigasi module
sys.path.append('.')
try:
    from mitigasi import BLOCKED_MACS, mitigated_state, BLOCK_THRESHOLD, REPEAT_LIMIT
except ImportError:
    # Fallback jika modul tidak tersedia
    BLOCKED_MACS = set()
    mitigated_state = {}
    BLOCK_THRESHOLD = 10
    REPEAT_LIMIT = 5

# ============================================
# AUTO-START FastAPI Detection Service
# ============================================
if 'fastapi_process' not in st.session_state:
    st.session_state.fastapi_started = False
    try:
        try:
            resp = requests.get("http://localhost:8000/health", timeout=1)
            if resp.status_code == 200:
                st.session_state.fastapi_started = True
        except:
            fastapi_process = subprocess.Popen(
                ['python3', 'deteksi.py'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            st.session_state.fastapi_process = fastapi_process
            st.session_state.fastapi_started = True
            
            def cleanup():
                try:
                    if hasattr(st.session_state, 'fastapi_process'):
                        os.killpg(os.getpgid(st.session_state.fastapi_process.pid), signal.SIGTERM)
                except:
                    pass
            
            atexit.register(cleanup)
            time.sleep(3)
    except Exception as e:
        pass

# ============================================
# Page Configuration
# ============================================
st.set_page_config(
    page_title="SDN Traffic Monitoring",
    page_icon="📊",
    layout="wide"
)

# ============================================
# Enhanced CSS
# ============================================
st.markdown("""
<style>
    /* Hide streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none;}
    
    /* Main title styling */
    .main-title {
        text-align: center;
        font-size: 2.8rem;
        font-weight: 700;
        color: #1a1a1a;
        margin-bottom: 0.3rem;
        margin-top: -30px;
    }
    .sub-title {
        text-align: center;
        font-size: 1.1rem;
        color: #6c757d;
        font-style: italic;
        margin-bottom: 2.5rem;
    }
    
    /* Card styling - Dark Blue Theme */
    .config-card {
        background: #2c3e50;
        color: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .config-card h3 {
        color: white;
        font-size: 1.2rem;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 2px solid #34495e;
        font-weight: 600;
    }
    
    .traffic-card {
        background: #34495e;
        color: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .traffic-card h3 {
        color: white;
        font-size: 1.2rem;
        margin-bottom: 15px;
        font-weight: 600;
    }
    
    .prediction-card {
        background: #5d7183;
        color: white;
        padding: 20px;
        border-radius: 8px;
        margin-top: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .prediction-card h3 {
        color: white;
        font-size: 1.2rem;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 2px solid #6c8299;
        font-weight: 600;
    }
    
    /* Current traffic metrics */
    .metric-row {
        display: flex;
        justify-content: space-between;
        margin-bottom: 15px;
    }
    .metric-item {
        text-align: center;
        flex: 1;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #ecf0f1;
        margin-bottom: 5px;
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        color: white;
    }
    
    /* Error/Success boxes */
    .error-box {
        background: #fff5f5;
        border-left: 4px solid #fc8181;
        border-radius: 5px;
        padding: 15px;
        color: #c53030;
        margin: 10px 0;
        font-size: 0.95rem;
    }
    
    .success-box {
        background: #f0fff4;
        border-left: 4px solid #68d391;
        border-radius: 5px;
        padding: 15px;
        color: #22543d;
        margin: 10px 0;
        font-size: 0.95rem;
    }
    
    /* Select box custom styling */
    .stSelectbox label {
        color: white !important;
        font-weight: 500;
        font-size: 0.95rem;
    }
    
    /* Table styling */
    .dataframe {
        font-size: 0.85rem;
    }
    
    /* Divider */
    hr {
        margin: 1.5rem 0;
        border: none;
        border-top: 1px solid #dee2e6;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# Session State Initialization
# ============================================
if 'selected_device' not in st.session_state:
    st.session_state.selected_device = None
if 'selected_port' not in st.session_state:
    st.session_state.selected_port = None
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = []
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()

# ============================================
# Configuration
# ============================================
FASTAPI_URL = "http://localhost:8000"
ONOS_URL = "http://localhost:8181/onos/v1"
ONOS_AUTH = ('onos', 'rocks')

# ============================================
# Helper Functions
# ============================================
def get_anomalies(mac=None):
    """Get anomalies from FastAPI detection service"""
    try:
        url = f"{FASTAPI_URL}/anomalies"
        if mac:
            url += f"?mac={mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {"recent": [], "last_mitigated": None}

def get_onos_devices():
    """Get devices from ONOS"""
    try:
        response = requests.get(f"{ONOS_URL}/devices", auth=ONOS_AUTH, timeout=3)
        if response.status_code == 200:
            return response.json().get('devices', [])
    except:
        pass
    return []

def get_onos_ports(device_id):
    """Get ports for specific device from ONOS"""
    try:
        response = requests.get(f"{ONOS_URL}/devices/{device_id}/ports", auth=ONOS_AUTH, timeout=3)
        if response.status_code == 200:
            return response.json().get('ports', [])
    except:
        pass
    return []

def get_port_stats(device_id, port_num):
    """Get port statistics from ONOS"""
    try:
        response = requests.get(f"{ONOS_URL}/statistics/ports/{device_id}", auth=ONOS_AUTH, timeout=3)
        if response.status_code == 200:
            stats = response.json().get('statistics', [])
            for stat in stats:
                if stat.get('port') == int(port_num):
                    return stat
    except:
        pass
    return None

def get_flows():
    """Get all flows from ONOS"""
    try:
        response = requests.get(f"{ONOS_URL}/flows", auth=ONOS_AUTH, timeout=3)
        if response.status_code == 200:
            return response.json().get('flows', [])
    except:
        pass
    return []

# ============================================
# Header
# ============================================
st.markdown('<h1 class="main-title">SDN Traffic Monitoring Dashboard</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Real-time network traffic visualization</p>', unsafe_allow_html=True)

# ============================================
# Main Layout
# ============================================
col_left, col_right = st.columns([1, 2.2])

# ============================================
# LEFT COLUMN - Device Configuration
# ============================================
with col_left:
    # Device Configuration Card
    st.markdown('<div class="config-card"><h3>Device Configuration</h3></div>', unsafe_allow_html=True)
    
    # Get devices
    devices = get_onos_devices()
    device_ids = [d.get('id', 'Unknown') for d in devices]
    
    if not device_ids:
        device_ids = ['of:0000000000000001']
    
    # Device selector
    st.markdown("**Select Device ID**")
    selected_device = st.selectbox(
        "Device",
        device_ids,
        key='device_select',
        label_visibility='collapsed'
    )
    st.session_state.selected_device = selected_device
    
    # Port selector
    st.markdown("**Select Port**")
    if selected_device:
        ports = get_onos_ports(selected_device)
        port_nums = [str(p.get('port', 'Unknown')) for p in ports if p.get('isEnabled')]
        
        if not port_nums:
            port_nums = ['1', '2', '3', '4']
        
        selected_port = st.selectbox(
            "Port",
            port_nums,
            key='port_select',
            label_visibility='collapsed'
        )
        st.session_state.selected_port = selected_port
    
    # Current Traffic Card
    st.markdown('<div class="traffic-card" style="margin-top: 20px;"><h3>Current Traffic</h3>', unsafe_allow_html=True)
    
    if selected_device and selected_port:
        port_stats = get_port_stats(selected_device, selected_port)
        
        if port_stats:
            bytes_sent = port_stats.get('bytesSent', 0)
            bytes_recv = port_stats.get('bytesReceived', 0)
            packets_sent = port_stats.get('packetsSent', 0)
            packets_recv = port_stats.get('packetsReceived', 0)
        else:
            bytes_sent = bytes_recv = packets_sent = packets_recv = 0
    else:
        bytes_sent = bytes_recv = packets_sent = packets_recv = 0
    
    # Display metrics in 2x2 grid
    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="metric-item">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Bytes Sent</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{bytes_sent}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-item">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Bytes Received</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{bytes_recv}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    col3, col4 = st.columns(2)
    with col3:
        st.markdown('<div class="metric-item">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Packets Sent</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{packets_sent}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-item">', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Packets Received</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{packets_recv}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

# ============================================
# RIGHT COLUMN - Traffic Metrics & Flow Predictions
# ============================================
with col_right:
    # Traffic Metrics Chart
    st.markdown('<div class="traffic-card"><h3>Traffic Metrics</h3></div>', unsafe_allow_html=True)
    
    # Update traffic history
    current_time = datetime.now()
    traffic_data = {
        'timestamp': current_time,
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_recv,
        'packets_sent': packets_sent,
        'packets_received': packets_recv
    }
    
    st.session_state.traffic_history.append(traffic_data)
    
    # Keep only last 50 points
    if len(st.session_state.traffic_history) > 50:
        st.session_state.traffic_history = st.session_state.traffic_history[-50:]
    
    # Create traffic chart
    if len(st.session_state.traffic_history) > 1:
        df_traffic = pd.DataFrame(st.session_state.traffic_history)
        
        # Create time labels
        time_labels = [t.strftime('%H:%M:%S') for t in df_traffic['timestamp']]
        
        fig = go.Figure()
        
        # Add BytesSent trace
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=df_traffic['bytes_sent'],
            mode='lines',
            name='BytesSent',
            line=dict(color='#000000', width=2.5),
            hovertemplate='BytesSent: %{y}<extra></extra>'
        ))
        
        # Add BytesReceived trace
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=df_traffic['bytes_received'],
            mode='lines',
            name='BytesReceived',
            line=dict(color='#2ecc71', width=2),
            hovertemplate='BytesReceived: %{y}<extra></extra>'
        ))
        
        # Add PacketsSent trace
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=df_traffic['packets_sent'],
            mode='lines',
            name='PacketsSent',
            line=dict(color='#e74c3c', width=2),
            hovertemplate='PacketsSent: %{y}<extra></extra>'
        ))
        
        # Add PacketsReceived trace
        fig.add_trace(go.Scatter(
            x=time_labels,
            y=df_traffic['packets_received'],
            mode='lines',
            name='PacketsReceived',
            line=dict(color='#3498db', width=2),
            hovertemplate='PacketsReceived: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            title={
                'text': f"Traffic on {selected_device} - Port {selected_port}",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 14}
            },
            xaxis_title="Time",
            yaxis_title="Count",
            height=380,
            margin=dict(l=60, r=30, t=50, b=60),
            legend=dict(
                orientation="h",
                yanchor="top",
                y=-0.15,
                xanchor="center",
                x=0.5,
                font=dict(size=11)
            ),
            hovermode='x unified',
            plot_bgcolor='white',
            paper_bgcolor='white',
            xaxis=dict(
                showgrid=True,
                gridcolor='#e0e0e0',
                tickangle=-45
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='#e0e0e0'
            )
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("📊 Collecting traffic data...")
    
    # Flow Predictions Section
    st.markdown('<div class="prediction-card"><h3>Flow Predictions</h3>', unsafe_allow_html=True)
    
    # Get anomalies and mitigation results
    anomaly_data = get_anomalies()
    anomalies = anomaly_data.get('recent', [])
    
    # Check for blocked MACs and show mitigation results
    if BLOCKED_MACS and len(BLOCKED_MACS) > 0:
        # Show error for blocked attackers
        for mac in BLOCKED_MACS:
            state = mitigated_state.get(mac, {})
            last_anomaly = state.get('last_anomaly', {})
            
            src_ip = last_anomaly.get('src_ip', 'Unknown')
            dst_ip = last_anomaly.get('dst_ip', 'Unknown')
            protocol = last_anomaly.get('protocol', 1)
            
            error_msg = f"""
            <div class="error-box">
                <strong>Error: HTTPConnectionPool(host='localhost', port=8000):</strong> Max retries exceeded with url: /anomalies (Caused by NewConnectionError('&lt;urllib3.connection.HTTPConnection object at 0x7aad04509e70&gt;: Failed to establish a new connection: [Errno 111] Connection refused'))
                <br><br>
                <strong>⚠️ ATTACK BLOCKED BY MITIGATION SYSTEM</strong><br>
                <strong>Source:</strong> {src_ip} ({mac})<br>
                <strong>Target:</strong> {dst_ip}<br>
                <strong>Protocol:</strong> {protocol}<br>
                <strong>Status:</strong> ❌ Flow blocked - Packets dropped
            </div>
            """
            st.markdown(error_msg, unsafe_allow_html=True)
    
    # Show recent anomaly predictions in table
    if anomalies:
        anomalies_only = [a for a in anomalies if a.get('result') == -1]
        
        if anomalies_only:
            # Get last 15 anomalies
            recent = anomalies_only[-15:]
            
            # Create dataframe
            prediction_data = []
            for a in recent:
                prediction_data.append({
                    'result': a.get('result'),
                    'score': f"{a.get('score', 0):.20f}",
                    'src_ip': a.get('src_ip'),
                    'src_mac': a.get('src_mac'),
                    'src_port': a.get('src_port', 0),
                    'dst_ip': a.get('dst_ip'),
                    'dst_mac': a.get('dst_mac'),
                    'dst_port': a.get('dst_port', 0),
                    'protocol': a.get('protocol', 1)
                })
            
            df_predictions = pd.DataFrame(prediction_data)
            
            # Display table with custom styling
            st.dataframe(
                df_predictions,
                use_container_width=True,
                height=350,
                hide_index=True
            )
        else:
            st.markdown("""
            <div class="success-box">
                No anomalies detected. All network traffic is normal.
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("⏳ Waiting for flow prediction data from detection service...")
    
    st.markdown('</div>', unsafe_allow_html=True)

# ============================================
# Footer with system status
# ============================================
st.markdown("---")

footer_cols = st.columns([1, 1, 1, 1, 1])

with footer_cols[0]:
    st.caption("🔵 Errors")

with footer_cols[1]:
    st.caption("❌ Callbacks")

with footer_cols[2]:
    st.caption(f"v{BLOCK_THRESHOLD}.0.{REPEAT_LIMIT}")

with footer_cols[3]:
    st.caption("📊 Dash update available - v3.0.4")

with footer_cols[4]:
    try:
        resp = requests.get(f"{ONOS_URL}/devices", auth=ONOS_AUTH, timeout=1)
        server_status = "✅" if resp.status_code == 200 else "⚠️"
    except:
        server_status = "🔴"
    st.caption(f"Server {server_status}")

# ============================================
# Auto-refresh every 5 seconds
# ============================================
time.sleep(5)
st.rerun()