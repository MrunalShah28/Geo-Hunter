import re
import pandas as pd
import geoip2.database
import folium
from folium.plugins import MarkerCluster

# 1. SETUP: Define the Regex to read standard Apache/Nginx logs
LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+|-)'

# 2. SETUP: Path to your MaxMind Database
DB_PATH = 'GeoLite2-City.mmdb'

def parse_log_line(line):
    """
    Takes a single line of text and extracts: IP, Timestamp, Request, Status Code.
    """
    match = re.search(LOG_PATTERN, line)
    if not match:
        return None
    
    ip = match.group(1)
    timestamp = match.group(2)
    request = match.group(3)
    status = match.group(4)
    
    # Extract the URL from the request
    try:
        url = request.split()[1]
        method = request.split()[0]
    except IndexError:
        url = request
        method = "UNKNOWN"
        
    return {
        "ip": ip,
        "timestamp": timestamp,
        "request": request,
        "url": url,
        "method": method,
        "status": status
    }

def detect_attacks(df):
    """
    Scans the dataframe for known attack signatures.
    """
    def categorize(row):
        url = str(row['url']).lower()
        
        # 1. SQL Injection Signatures
        if "union select" in url or "' or '1'='1" in url or "information_schema" in url:
            return "SQL Injection"
        
        # 2. XSS Signatures
        elif "<script>" in url or "javascript:" in url or "onerror=" in url:
            return "XSS Attack"
        
        # 3. Path Traversal Signatures
        elif "../" in url or "etc/passwd" in url or "boot.ini" in url:
            return "Path Traversal"
        
        # 4. Scanner/Bot Signatures
        elif "admin.php" in url or "wp-login" in url:
            return "Admin Scan"
            
        return "Normal"

    df['threat_label'] = df.apply(categorize, axis=1)
    return df

def generate_map(df):
    """
    Creates an interactive World Map with pins for every IP.
    """
    attack_map = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    marker_cluster = MarkerCluster().add_to(attack_map)

    try:
        reader = geoip2.database.Reader(DB_PATH)
    except FileNotFoundError:
        print("Error: Database Not Found")
        return None

    unique_ips = df['ip'].unique()
    
    for ip in unique_ips:
        try:
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            country = response.country.name
            
            ip_data = df[df['ip'] == ip]
            attacks = ip_data[ip_data['threat_label'] != "Normal"]
            
            if not attacks.empty:
                color = "red"
                popup_text = f"ATTACKER: {ip} ({country}) - {len(attacks)} Malicious Requests"
            else:
                color = "blue"
                popup_text = f"User: {ip} ({country})"
            
            folium.Marker(
                location=[lat, lon],
                popup=popup_text,
                icon=folium.Icon(color=color, icon="info-sign")
            ).add_to(marker_cluster)
            
        except geoip2.errors.AddressNotFoundError:
            continue

    return attack_map._repr_html_()

def process_log_file(filepath):
    """
    The Main Driver Function.
    """
    parsed_data = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            data = parse_log_line(line)
            if data:
                parsed_data.append(data)
                
    df = pd.DataFrame(parsed_data)
    
    if df.empty:
        return None, None, None

    df = detect_attacks(df)
    map_html = generate_map(df)
    
    total_requests = len(df)
    malicious_requests = len(df[df['threat_label'] != "Normal"])
    top_attackers = df[df['threat_label'] != "Normal"]['ip'].value_counts().head(5).to_dict()
    
    stats = {
        "total": total_requests,
        "malicious": malicious_requests,
        "top_attackers": top_attackers
    }
    
    return df, map_html, stats
