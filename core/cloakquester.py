import os
import socket
import ssl
import threading

import requests
import toml
from bs4 import BeautifulSoup as bs
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .color import color_print as cp


def _to_hostname(url: str = None) -> str:
    hostname = url.replace("https://", "")
    hostname = hostname.replace("http://", "")
    return hostname

def _to_url(hostname: str = None) -> str:
    return f"https://{hostname}"

def get_addr(hostname: str = None) -> str|None:
    '''
    Retrieve IP address based on the given hostname.

    Args:
        hostname (str, optional): The hostname from which to retrieve the IP address. Default is None.

    Returns:
        str|None: The IP address corresponding to the hostname, or None if the IP address could not be retrieved.
    '''
    try:
        return socket.gethostbyname(hostname)
    except:
        return
    
def detect_web_server(hostname: str = None) -> str:
    '''
    Detect the web server used by a given hostname.

    Args:
        hostname (str, optional): The hostname for which to detect the web server. Default is None.

    Returns:
        str: The name of the web server detected from the response headers, or "Unknown" if the detection fails.
    '''
    try:
        response = requests.head(_to_url(hostname))

        if "CF-RAY" in response.headers:
            return "cloudflare"
        
        return response.headers["Server"]
    except:
        return "unknown"

def get_certificate_info(hostname: str = None) -> dict|None:
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as secure_sock:
                certificate = x509.load_der_x509_certificate(secure_sock.getpeercert(True), default_backend())

        return {
            "Common Name": certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Issuer": certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Validity Start": certificate.not_valid_before_utc,
            "Validity End": certificate.not_valid_after_utc,
        }
    except Exception as e:
        cp(f"Error extracting SSL certificate information: {e}", "red")
        return None

def ssl_analysis(hostname: str = None, filename: str = None):
    subdomains_found = []

    def check_subdomain(subdomain: str = None) -> None:
        subdomain_url = _to_url(f"{subdomain}.{hostname}")
        try:
            response = requests.get(subdomain_url, timeout=20)
            if response.status_code == 200:
                subdomains_found.append(subdomain_url)
                cp(f"[+] Subdomain Found: {subdomain_url}", "green")
        except:
            pass

    with open(filename, "r") as file:
        subdomains = [line.strip() for line in file]

    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_subdomain, args=(subdomain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    cp(f"\n[*] Total subdomains scanned: {len(subdomains)}", "green")
    cp(f"[*] Total subdomains found: {len(subdomains_found)}\n", "green")

    for subdomain in subdomains_found:
        ip_addr = get_addr(_to_hostname(subdomain))
        if ip_addr:
            cp(f"\n[+] IP address found on {subdomain}: {ip_addr}", "green")

            ssl_info = get_certificate_info(_to_hostname(subdomain))
            if ssl_info:
                cp("[+] SSL certificate information:", "green")
                for k,v in ssl_info.items():
                    print(f"{k}: {v}")

def read_config() -> str:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "config.toml")) as file:
        conf = toml.load(file)

    return conf['api_key']['security_trails']

def securitytrails_ip_history(hostname: str = None) -> None:
    api_key = read_config()

    url = f"https://api.securitytrails.com/v1/history/{hostname}/dns/a"
    headers = {
        "accept": "application/json",
        "APIKEY": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        cp(f"\n[+] Historical IP Address Info from SecurityTrails for {hostname}", "green")
        for record in data.get('records', []):
            ip_addr = record.get("values", [{}])[0].get("ip", "N/A")
            first_seen = record.get("first_seen", "N/A")
            last_seen = record.get("last_seen", "N/A")
            organizations = record.get("organizations", ["N/A"])[0]
            cp(f"\n[+] IP Address: {ip_addr}", "green")
            cp(f" \u2514\u27A4 First Seen: {first_seen}","green")
            cp(f" \u2514\u27A4 Last Seen: {last_seen}", "green")
            cp(f" \u2514\u27A4 Organizations: {organizations}", "green")
    except Exception as e:
        cp(f"[!] Error extracting Historical IP Address information from SecurityTrails: {e}", "red")

    return None

def viewdns_ip_history(hostname: str = None) -> None:
    try:
        url = f"https://viewdns.info/iphistory/?domain={hostname}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }
        response = requests.get(url, headers=headers)
        soup = bs(response.text, 'html.parser')
        table = soup.find('table', {'border': '1'})

        if table:
            cp(f"\n[+] Historical IP Address Info from Viewdns for {hostname}", "green")
            for row in table.find_all('tr')[2:]:
                columns = row.find_all('td')
                ip_addr = columns[0].text.strip()
                location = columns[1].text.strip()
                owner = columns[2].text.strip()
                last_seen = columns[3].text.strip()
                cp(f"\n[+] IP Address: {ip_addr}", "green")
                cp(f" \u2514\u27A4 Location: {location}", "green")
                cp(f" \u2514\u27A4 Owner: {owner}", "green")
                cp(f" \u2514\u27A4 Last Seen: {last_seen}", "green")
        else:
            print(f"\n[-] No IP found on ViewDNS")
    except Exception as e:
        print(f"[!] Error extracting IP history: {e}")

    return None

