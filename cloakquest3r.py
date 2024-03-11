import os
import re
import sys

from core import cloakquester
from core import color_print as cp
from core import print_banner


def is_valid_file(arg):
    """
    Verify wheter a file exists within the system.
    """
    if not os.path.exists(arg):
        parser.error(f'The file "{arg}" does not exist!')
    else:
        return arg
    
def is_valid_url(arg):
    """
    Check if the given URL is valid.
    """
    # Regular expression pattern for validating URL
    pattern = "^https:\/\/[0-9A-z.]+.[0-9A-z.]+.[a-z]+$"

    if not re.match(pattern, arg):
        parser.error(f'The URL "{arg}" is not valid.')

    return cloakquester._to_hostname(arg)

def main():
    print("[!] Checking if website uses Cloudflare")
    ip_addr = cloakquester.get_addr(hostname)
    server_name = cloakquester.detect_web_server(hostname)

    if server_name != "cloudflare" and not args.force:
        op = input(f"[-] Website is using {server_name.capitalize()}. Proceed? (Y/N) ")

        if not re.match(r"^(?:yes|y)$", op, re.IGNORECASE):
            cp(f"[!] Operation aborted, exiting...", "red")
            sys.exit(0)

    cp(f"[+] Target Website: {hostname}", "cyan")
    cp(f"[+] Visible IP: {ip_addr}", "cyan")
    cp(f"[+] Website is using: {server_name}", "cyan")

    cloakquester.viewdns_ip_history(hostname)

    if not args.st_scan:
        cloakquester.securitytrails_ip_history(hostname)

    if not args.no_bruteforce:
        cp(f"\n[+] Scanning for subdomains...", "green")
        cloakquester.ssl_analysis(hostname, wordlist)


if __name__ == '__main__':
    import argparse

    # CLI Arguments
    parser = argparse.ArgumentParser(
        description="Uncover the true IP addresses Cloudflare safeguarded websites.",
        prog="cloakquest3r", 
        epilog="Created by Spyboy."
    )
    parser.add_argument(
        "-u", "--url",
        dest="url", 
        required=True, 
        help="set target URL", 
        metavar="URL", 
        type=is_valid_url
    )
    parser.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        required=False,
        default="wordlists/default.txt",
        help="wordlist file path (optional)",
        metavar="FILE",
        type=is_valid_file
    )
    parser.add_argument("-f", "--force", dest="force", required=False, action="store_true", help="don't ask for confirmation")
    parser.add_argument("--no-security-trails", dest="st_scan", required=False, action="store_true", help="disable Security Trails IP history verify (optional)")
    parser.add_argument("--no-bruteforce", dest="no_bruteforce", required=False, action="store_true", help="disable scanning for subdomains (optional)")
    parser.add_argument("--no-banner", dest="no_banner", required=False, action="store_true", help="hide banner during execution (optional)")
    args = parser.parse_args()

    hostname = args.url
    wordlist = args.wordlist

    print(wordlist)

    if not args.no_banner:
        cp(print_banner(), "green")

    main()