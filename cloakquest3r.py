import os
import re
import sys

from core import cloakquester, parser, print_banner
from core.utils import *


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
    # Regular expression pattern for validating domain or URL
    pattern = r"^(https?://[\w.-]+\.[a-zA-Z]{2,}(?:/\S*)?|[\w.-]+\.[a-zA-Z]{2,})$"

    if not re.match(pattern, arg):
        parser.error(f'The URL "{arg}" is not valid.')

    return cloakquester._to_hostname(arg)

def main():
    print(f"\n{G}[-] {C}Checking if the website uses Cloudflare...{W}\n")
    ip_addr = cloakquester.get_addr(hostname)
    server_name = cloakquester.detect_web_server(hostname)

    if server_name != "cloudflare" and not args.force:
        print(f"\n{G}[+] {C}Website is using: {G} {server_name}")
        op = input(f"\n{Y}> Do you want to proceed? {G}(y/N): ")

        if not re.match(r"^(?:yes|y)$", op, re.IGNORECASE):
            print(f"{R}[!] Operation aborted. Exiting...{W}")
            sys.exit(0)

    print(f"\n{R}Target Website: {W}{hostname}")
    print(f"{R}Visible IP Address: {W}{ip_addr}\n")
    print(f"{R}Website is using: {W}{server_name}")

    cloakquester.get_viewdns_ip_history(hostname)

    if not args.st_scan:
        cloakquester.get_securitytrails_ip_history(hostname)

    if not args.no_bruteforce:
        print(f"\n{G}[+] {Y}Scanning for subdomains...{W}")
        cloakquester.ssl_analysis(hostname, wordlist)


if __name__ == '__main__':
    from core import parser

    parser = parser.ArgumentParser(
        description="Uncover the true IP addresses Cloudflare safeguarded websites.",
        prog="cloakquest3r", 
        epilog="Created by Spyboy.",
    )
    parser.add_argument(
        "url",
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

    if not args.no_banner:
        print_banner()

    main()