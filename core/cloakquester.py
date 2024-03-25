import socket
import ssl
import threading

import requests
from bs4 import BeautifulSoup as bs
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from . import config
from .utils import *


def _to_hostname(url: str) -> str:
    hostname = url.replace("https://", "")
    hostname = hostname.replace("http://", "")
    return hostname

def _to_url(hostname: str) -> str:
    return f"https://{hostname}"

def get_addr(hostname: str) -> str|None:
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
   
def detect_web_server(hostname: str) -> str:
    '''
    Detect the web server used by a given hostname.

    Args:
        hostname (str, optional): The hostname for which to detect the web server. Default is None.

    Returns:
        str: The name of the web server detected from the response headers, or "Unknown" if the detection fails.
    '''
    try:
        response = requests.head(_to_url(hostname), timeout=5)

        if "CF-RAY" in response.headers:
            return "cloudflare"
        
        return response.headers["Server"]
    except KeyError:
        return "unknown"

def get_certificate_info(hostname: str) -> dict|None:
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
        print(f"Error extracting SSL certificate information: {e}")
        return None

def ssl_analysis(hostname: str, filename: str):
    subdomains_found = []

    def check_subdomain(subdomain: str) -> None:
        subdomain_url = _to_url(f"{subdomain}.{hostname}")
        try:
            response = requests.get(subdomain_url, timeout=5)
            if response.status_code == 200:
                subdomains_found.append(subdomain_url)
                print(f" {G}\u2514\u27A4 {subdomain_url}{W}")
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

    print(f"\n{G} [+] {C}Total Subdomains Scanned:{W} {len(subdomains)}")
    print(f"{G} [+] {C}Total Subdomains Found:{W} {len(subdomains_found)}")

    for subdomain in subdomains_found:
        ip_addr = get_addr(_to_hostname(subdomain))
        if ip_addr:
            print(f"\n{Y}[+] {C}IP address found on {G}{hostname}: {R}{ip_addr}")

            ssl_info = get_certificate_info(_to_hostname(subdomain))
            if ssl_info:
                print(f"{R}   [+] {C}SSL certificate information:")
                for k,v in ssl_info.items():
                    print(f"{R}     \u2514\u27A4 {C}{k}: {W}{v}")



def get_securitytrails_ip_history(hostname: str) -> None:
    api_key = config.recover_api_key()

    if not api_key:
        print(f"\n{Y}[*] SecurityTrails API key not found. Skipping...")
        return

    url = f"https://api.securitytrails.com/v1/history/{hostname}/dns/a"
    headers = {
        "accept": "application/json",
        "APIKEY": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        print(f"\n{G}[+] {Y}Historical IP Address Info from {C}SecurityTrails{Y} for {G}{hostname}:{W}")
        for record in data.get('records', []):
            ip_addr = record.get("values", [{}])[0].get("ip", "N/A")
            first_seen = record.get("first_seen", "N/A")
            last_seen = record.get("last_seen", "N/A")
            organizations = record.get("organizations", ["N/A"])[0]

            print(f"\n{R} [+] {C}IP Address: {R}{ip_addr}{W}")
            print(f"{Y}  \u2514\u27A4 {C}First Seen: {G}{first_seen}{W}")
            print(f"{Y}  \u2514\u27A4 {C}Last Seen: {G}{last_seen}{W}")
            print(f"{Y}  \u2514\u27A4 {C}Organizations: {G}{organizations}{W}")
    except Exception as e:
        print(f"\n{R}[!] Error extracting Historical IP Address information from SecurityTrails")

    return

def get_viewdns_ip_history(hostname: str) -> None:
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
            print(f"\n{G}[+] {Y}Historical IP Address Info from {C}ViewDNS{Y} for {G}{hostname}:{W}")
            for row in table.find_all('tr')[2:]:
                columns = row.find_all('td')
                ip_addr = columns[0].text.strip()
                location = columns[1].text.strip()
                owner = columns[2].text.strip()
                last_seen = columns[3].text.strip()

                print(f"\n{R}[+] {C}IP Address: {R}{ip_addr}{W}")
                print(f"{Y} \u2514\u27A4 {C}Location: {G}{location}{W}")
                print(f"{Y} \u2514\u27A4 {C}Owner: {G}{owner}{W}")
                print(f"{Y} \u2514\u27A4 {C}Last Seen: {G}{last_seen}{W}")
        else:
            print(f"\n{R}[+] {C}No IP found on ViewDNS")
    except:
        print(f"\n{R}[!] Error extracting Historical IP Address information from ViewDNS{W}")

    return

