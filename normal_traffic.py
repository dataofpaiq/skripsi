import random
import time
import subprocess
from threading import Thread

# ======= CONFIG =======
TARGET_IP = "10.0.0.2"
TRAFFIC_DURATION = 7200  # dalam detik
HTTP_REQUESTS_PER_SEC = 2  # rate per detik

# ======= Daftar Endpoint Nginx =======
HTTP_ENDPOINTS = [
    "/",                                 # index.html
    "/static/style.css",                # CSS
    "/static/script.js",                # JS
    "/api/data.json",                   # API JSON
    "/smallfile.bin",                   # 1MB file
    "/mediumfile.bin",                  # 10MB file
    "/bigfile.bin",                     # 100MB file
    "/login.html",                      # halaman login
    "/nonexistent"                      # 404 error
]

# ======= Fungsi Traffic Normal =======
def generate_http_traffic():
    """Kirim request GET dan POST acak ke berbagai endpoint Nginx."""
    while True:
        endpoint = random.choice(HTTP_ENDPOINTS)
        full_url = f"http://{TARGET_IP}{endpoint}"

        if endpoint == "/nonexistent":
            print(f"HTTP 404 Test → {full_url}")
        elif endpoint == "/login.html" and random.random() < 0.3:
            # 30% kemungkinan simulasi POST form login
            post_cmd = f"curl -s -X POST -d 'username=user&password=pass' {full_url}"
            subprocess.run(post_cmd, shell=True, stdout=subprocess.DEVNULL)
            print(f"HTTP POST Login → {full_url}")
        else:
            get_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {full_url}"
            response = subprocess.run(get_cmd, shell=True, capture_output=True, text=True).stdout.strip()
            print(f"HTTP GET {endpoint} → Status: {response}")
        
        time.sleep(1 / HTTP_REQUESTS_PER_SEC)

def generate_udp_traffic():
    """Simulasi UDP ringan seperti DNS/VoIP (untuk pembeda dari UDP Flood)."""
    while True:
        duration = random.uniform(1, 2)
        cmd = f"iperf -c {TARGET_IP} -u -t {duration} -b 100K"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)
        print(f"UDP iPerf → {duration:.1f}s (100Kbps)")
        time.sleep(random.uniform(10, 20))

def generate_icmp_traffic():
    """Simulasi ICMP ping ringan sebagai baseline untuk beda dari ICMP Flood."""
    while True:
        count = random.choice([1, 2])
        cmd = f"ping -c {count} {TARGET_IP}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
        latency = output.split("time=")[-1].split()[0] if "time=" in output else "N/A"
        print(f"ICMP Ping → {count} packet(s) | Latency: {latency}")
        time.sleep(random.uniform(2, 5))

# ======= MAIN EXECUTION =======
if __name__ == "__main__":
    print(f"🚀 Memulai simulasi trafik normal ke {TARGET_IP} (Nginx)")

    Thread(target=generate_http_traffic, daemon=True).start()
    Thread(target=generate_udp_traffic, daemon=True).start()
    Thread(target=generate_icmp_traffic, daemon=True).start()

    time.sleep(TRAFFIC_DURATION)
    print("Simulasi trafik normal selesai.")
