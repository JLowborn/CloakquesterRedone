import os
import sys

import toml

from .config import *
from .utils import *

try:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "config.toml")) as f:
        conf = toml.load(f)
except FileNotFoundError:
    print(f'{R}[!] Configuration file "config.toml" not found!{W}')
    create_config_file()
    sys.exit(2)

# Social Media Links
AUTHOR = conf['owner']['author']
TWITTER_LINK = conf['owner']['twitter']
DISCORD_LINK = conf['owner']['discord']
WEBSITE_LINK = conf['owner']['website']
BLOG_LINK = conf['owner']['blog']
GITHUB_LINK = conf['owner']['github']

VERSION_TAG = conf['version']['version_tag']

BANNER = f'''{R}
   ___ _             _      ____                 _   _____
  / __\ | ___   __ _| | __ /___ \_   _  ___  ___| |_|___ / _ __
 / /  | |/ _ \ / _` | |/ ///  / / | | |/ _ \/ __| __| |_ \| '__|
/ /___| | (_) | (_| |   </ \_/ /| |_| |  __/\__ \ |_ ___) | |
\____/|_|\___/ \__,_|_|\_\___,_\ \__,_|\___||___/\__|____/|_|
Uncover the true IP address of websites safeguarded by Cloudflare & others.

{G}[+] {Y}Version      : {W}{VERSION_TAG}
{G}[+] {Y}Created By   : {W}{AUTHOR}
{G} \u2514\u27A4 {Y}Twitter      : {W}{TWITTER_LINK}
{G} \u2514\u27A4 {Y}Discord      : {W}{DISCORD_LINK}
{G} \u2514\u27A4 {Y}Website      : {W}{WEBSITE_LINK}
{G} \u2514\u27A4 {Y}Blog         : {W}{BLOG_LINK}
{G} \u2514\u27A4 {Y}Github       : {W}{GITHUB_LINK}
{RST}'''

def print_banner() -> None:
    """Return banner string."""
    print(BANNER)