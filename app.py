import streamlit as st
import pandas as pd
import asyncio
from collections import Counter
import os
import json
from datetime import datetime
import plotly.express as px
from src.cai.tools.breaking_circuits_suite import BreakingCircuitsSuite

# --- Configuration & Constants ---
APP_TITLE = "Breaking Circuits AI Security Suite"
TSHARK_CMD = "tshark"

# --- Initialize Suite ---
suite = BreakingCircuitsSuite(config_path='config.yaml')

# --- Helper Functions ---
def init_session_state():
    """Initializes all necessary keys in Streamlit's session state."""
    defaults = {
        'raw_packet_data': [],
        'alerts': [],
        'selected_packet_index': None,
        'ip_threat_intel_results': {},
        'abuseipdb_cache': {},
        'web_scan_results': {}
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def process_pcap_file_with_tshark(pcap_file_path, bpf_filter=None):
    """Processes a PCAP file using tshark and populates the session state."""
    st.session_state.raw_packet_data = []
    st.session_state.alerts = []
    st.session_state.ip_threat_intel_results = {}
    
    cmd = [TSHARK_CMD, "-r", pcap_file_path, "-T", "ek"]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets_json = proc.stdout.strip().split('\n')
        
        for i, packet_json_str in enumerate(packets_json):
            try:
                packet_data = json.loads(packet_json_str)
                layers = packet_data.get("layers", {})
                
                # Basic summary generation
                timestamp = layers.get('frame', {}).get('frame.time', 'N/A')
                protocols = layers.get('frame', {}).get('frame.protocols', 'N/A')
                summary = f"Pkt {i+1}: {timestamp} - Protocols: {protocols}"
                
                st.session_state.raw_packet_data.append({"summary": summary, "details": packet_data})
            except json.JSONDecodeError:
                continue # Skip malformed lines
        return f"Successfully processed {len(st.session_state.raw_packet_data)} packets from {os.path.basename(pcap_file_path)}."
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return f"Error running tshark: {e}. Please ensure tshark is installed and in your PATH."

async def run_threat_intelligence_checks():
    """Extracts unique public IPs and checks them against AbuseIPDB."""
    unique_public_ips = set()
    for packet in st.session_state.raw_packet_data:
        layers = packet.get("details", {}).get("layers", {})
        for ip_layer in ["ip", "ipv6"]:
            if ip_layer in layers:
                src_ip = layers[ip_layer].get(f"{ip_layer}.src")
                dst_ip = layers[ip_layer].get(f"{ip_layer}.dst")
                if src_ip and suite.is_public_ip(src_ip): unique_public_ips.add(src_ip)
                if dst_ip and suite.is_public_ip(dst_ip): unique_public_ips.add(dst_ip)
    
    if not unique_public_ips:
        return
        
    tasks = [suite.check_ip_abuseipdb(ip, st.session_state.abuseipdb_cache) for ip in unique_public_ips]
    results = await asyncio.gather(*tasks)
    
    for ip_intel in results:
        if ip_intel:
            st.session_state.ip_threat_intel_results[ip_intel["ipAddress"]] = ip_intel
            if ip_intel.get("abuseConfidenceScore", 0) > 50:
                st.session_state.alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "AbuseIPDB",
                    "message": f"High abuse score ({ip_intel['abuseConfidenceScore']}%) for IP: {ip_intel['ipAddress']}",
                    "severity": "High"
                })

# --- Streamlit App UI ---
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(f"🚨 {APP_TITLE}")

init_session_state()

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ Controls & Configuration")
    
    st.subheader("📦 Packet Analysis")
    uploaded_file = st.file_uploader("Upload PCAP/PCAPNG", type=["pcap", "pcapng", "cap"])
    pcap_filter = st.text_input("BPF Filter for PCAP (optional)")
    
    if st.button("Analyze PCAP"):
        if uploaded_file:
            with st.spinner(f"Processing {uploaded_file.name}..."):
                with open(uploaded_file.name, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                status = process_pcap_file_with_tshark(uploaded_file.name, pcap_filter)
                st.success(status)
                os.remove(uploaded_file.name)
            with st.spinner("Running Threat Intelligence checks..."):
                asyncio.run(run_threat_intelligence_checks())
            st.rerun()
        else:
            st.warning("Please upload a PCAP file.")

    st.markdown("---")
    st.subheader("🛡️ Web Application Security")
    target_url = st.text_input("Target URL for Scanning", placeholder="e.g., http://example.com")
    
    if st.button("Run Web Scans"):
        if target_url:
            st.session_state.web_scan_results = {}
            with st.spinner(f"Scanning {target_url}..."):
                st.session_state.web_scan_results["Port Scan"] = suite.scan_ports(target_url)
                st.session_state.web_scan_results["XSS Detection"] = suite.detect_xss(target_url)
                st.session_state.web_scan_results["Nikto Scan"] = suite.run_nikto_scan(target_url)
            st.success(f"Web application scans completed for {target_url}.")
            st.rerun()
        else:
            st.warning("Please enter a target URL.")

# --- Main Area Display ---
tab1, tab2, tab3 = st.tabs(["📊 Traffic Analysis Dashboard", "🛡️ Web Security Results", "🚨 Alerts"])

with tab1:
    st.header("Packet Analysis")
    if not st.session_state.raw_packet_data:
        st.info("Upload a PCAP file to begin packet analysis.")
    else:
        # Packet Data Log
        col1, col2 = st.columns([1, 2])
        with col1:
            st.subheader("📦 Packet Log")
            summaries = [pkt["summary"] for pkt in st.session_state.raw_packet_data]
            selected_summary = st.radio("Select a packet to view details:", summaries, key="packet_selector", index=None)
            if selected_summary:
                st.session_state.selected_packet_index = summaries.index(selected_summary)
            else:
                st.session_state.selected_packet_index = None

        # Packet Details and Threat Intel
        with col2:
            st.subheader("🔍 Packet Details & Threat Intel")
            if st.session_state.selected_packet_index is not None:
                pkt_details = st.session_state.raw_packet_data[st.session_state.selected_packet_index]['details']
                st.json(pkt_details, expanded=False)

                # Display Threat Intel
                packet_ips = set()
                layers = pkt_details.get("layers", {})
                for ip_layer in ["ip", "ipv6"]:
                    if ip_layer in layers:
                        packet_ips.add(layers[ip_layer].get(f"{ip_layer}.src"))
                        packet_ips.add(layers[ip_layer].get(f"{ip_layer}.dst"))
                
                for ip in packet_ips:
                    if ip and ip in st.session_state.ip_threat_intel_results:
                        intel = st.session_state.ip_threat_intel_results[ip]
                        score = intel.get('abuseConfidenceScore', 0)
                        color = "red" if score > 50 else "orange" if score > 0 else "green"
                        st.expander(f"Intel for {ip} (Score: {score}%)", expanded=False).write(intel)
            else:
                st.info("Select a packet from the log to see details.")

with tab2:
    st.header("Web Application Security Scan Results")
    if not st.session_state.web_scan_results:
        st.info("Run a web scan to see results here.")
    else:
        for scan_name, result in st.session_state.web_scan_results.items():
            with st.expander(f"**{scan_name}**", expanded=True):
                st.text(result)

with tab3:
    st.header("Triggered Alerts")
    if not st.session_state.alerts:
        st.info("No alerts triggered yet.")
    else:
        alerts_df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(alerts_df)