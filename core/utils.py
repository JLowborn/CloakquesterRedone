from colorama import Fore, Style, init

# NOTE: Besides `info`, `warning`, `error` & `success` functions implementation, those are not currently
# being used, as they're just an idea.

init()

B = Fore.BLUE
C = Fore.CYAN
G = Fore.GREEN
R = Fore.RED
M = Fore.MAGENTA
Y = Fore.YELLOW
W = Fore.WHITE
RST = Style.RESET_ALL

def info(message: str) -> None:
    template = f"{Fore.CYAN}[-] {message}{Style.RESET_ALL}"
    print(template)

def warning(message: str) -> None:
    template = f"{Fore.YELLOW}[*] {message}{Style.RESET_ALL}"
    print(template)

def error(message: str) -> None:
    template = f"{Fore.RED}[!] {message}{Style.RESET_ALL}"
    print(template)

def success(message: str) -> None:
    template = f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}"
    print(template)