import platform
import subprocess
from scapy.all import IP, ICMP, traceroute, sr1, TCP, sniff, ARP, Ether, srp
import os
import dns.resolver
import psutil
import requests
import time
import socket
import nmap
from playwright.sync_api import sync_playwright
import yaml
from io import StringIO
import logging
import ipaddress
import httpx
from datetime import datetime, timedelta

# --- Setup Logging ---
logger = logging.getLogger(__name__)

class BreakingCircuitsSuite:
    """
    A consolidated suite of network diagnostic and security tools.
    """
    def __init__(self, config_path='config.yaml'):
        self.os = platform.system()
        self.config_path = config_path

    # --- Network Diagnostic Skills (from network_diagnostic_suite.py) ---

    def ping(self, target_ip: str, packet_size: int = 56, count: int = 1, timeout: int = 1) -> str:
        ping_cmd = ""
        if self.os == "Windows":
            ping_cmd = f"ping -n {count} -l {packet_size} -w {timeout*1000} {target_ip}"
        else:
            ping_cmd = f"ping -c {count} -s {packet_size} -W {timeout} {target_ip}"
        try:
            result = subprocess.run(ping_cmd, shell=True, check=True, text=True, capture_output=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"

    def traceroute(self, target_ip: str, max_hops: int = 30) -> str:
        try:
            result, _ = traceroute(target_ip, maxttl=max_hops, verbose=0)
            output = "Traceroute Results:\n"
            output += result.show(dump=True)
            return output
        except Exception as e:
            return f"Traceroute failed: {e}"


    def dns_lookup(self, domain, record_type='A', dns_server='8.8.8.8'):
        try:
            res = dns.resolver.Resolver()
            res.nameservers = [dns_server]
            answer = res.query(domain, record_type)
            return f"DNS {record_type} records for {domain}:\n" + '\n'.join([str(r) for r in answer])
        except Exception as e:
            return f"DNS Lookup failed: {e}"

    def get_network_info(self):
        info = {}
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                info[interface] = []
                for addr in addrs:
                    info[interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
            return info
        except Exception as e:
            return f"Could not get network info: {e}"

    # --- Web Security & Scanning Tools (from securitysuite2.py) ---

    def get_api_key(self, service_name: str) -> str | None:
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config.get('api_keys', {}).get(service_name)
        except (FileNotFoundError, yaml.YAMLError) as e:
            logger.error(f"Error reading API key for {service_name}: {e}")
            return None

    def scan_ports(self, target: str, advanced_scan: bool = False, custom_ports: str | None = None, os_detection: bool = False, service_detection: bool = False) -> dict | str:
        scanner = nmap.PortScanner()
        arguments = '-T4'
        if advanced_scan:
            arguments += ' -A'
        else:
            if custom_ports:
                arguments += f' -p {custom_ports}'
            else:
                arguments += ' -p 1-1024'
            if os_detection:
                arguments += ' -O'
            if service_detection:
                arguments += ' -sV'
        try:
            from urllib.parse import urlparse
            target_host = urlparse(target).hostname or target
            scanner.scan(hosts=target_host, arguments=arguments)
            return scanner.csv()
        except Exception as e:
            return f"An unexpected error occurred during port scan: {e}"

    def detect_xss(self, url: str) -> str:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(ignore_https_errors=True)
                
                alert_triggered = False
                def handle_dialog(dialog):
                    nonlocal alert_triggered
                    if "XSS" in dialog.message:
                        alert_triggered = True
                    dialog.dismiss()
                
                page.on('dialog', handle_dialog)
                page.goto(url, timeout=15000)
                
                payload = "<script>alert('XSS_Test')</script>"
                forms = page.query_selector_all('form')
                if not forms:
                    page.goto(f"{url}?q={payload}", timeout=10000)
                    if alert_triggered:
                        return "XSS Vulnerability Potentially Detected via URL parameter."

                for form in forms:
                    inputs = form.query_selector_all('input[type="text"], input[type="search"], textarea')
                    for input_field in inputs:
                        input_field.fill(payload)
                        form.evaluate('form => form.submit()')
                        page.wait_for_timeout(1000) # wait for potential script execution
                        if alert_triggered:
                            return f"XSS Vulnerability Detected in a form input."
                
                browser.close()
                return "No obvious XSS vulnerability detected."
        except Exception as e:
            return f"Error during XSS detection: {e}"

    def run_nikto_scan(self, url: str) -> str:
        try:
            command = ["nikto", "-h", url, "-Format", "txt", "-Tuning", "x6"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else f"Nikto Error: {result.stderr}"
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return f"Nikto scan failed: {e}"

    # --- Threat Intelligence (from circuitshark.py) ---
    def is_public_ip(self, ip_address_str):
        try:
            ip = ipaddress.ip_address(ip_address_str)
            return not ip.is_private
        except ValueError:
            return False

    async def check_ip_abuseipdb(self, ip_address, cache):
        abuse_key = self.get_api_key("ABUSEIPDB_API_KEY")
        if not abuse_key or not self.is_public_ip(ip_address):
            return None
            
        if ip_address in cache and (datetime.now() - cache[ip_address]["timestamp"] < timedelta(minutes=60)):
            return cache[ip_address]["data"]

        headers = {'Accept': 'application/json', 'Key': abuse_key}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                response.raise_for_status()
                result = response.json().get("data")
                cache[ip_address] = {"timestamp": datetime.now(), "data": result}
                return result
        except httpx.RequestError as e:
            logger.error(f"AbuseIPDB request error for {ip_address}: {e}")
            return None