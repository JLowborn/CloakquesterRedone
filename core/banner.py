import os

import toml

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "config.toml")) as f:
    conf = toml.load(f)

# Social Media Links
AUTHOR = conf['owner']['author']
TWITTER_LINK = conf['owner']['twitter']
DISCORD_LINK = conf['owner']['discord']
WEBSITE_LINK = conf['owner']['website']
BLOG_LINK = conf['owner']['blog']
GITHUB_LINK = conf['owner']['github']

VERSION_TAG = conf['version']['version_tag']

BANNER = f'''
   ___ _             _      ____                 _   _____
  / __\ | ___   __ _| | __ /___ \_   _  ___  ___| |_|___ / _ __
 / /  | |/ _ \ / _` | |/ ///  / / | | |/ _ \/ __| __| |_ \| '__|
/ /___| | (_) | (_| |   </ \_/ /| |_| |  __/\__ \ |_ ___) | |
\____/|_|\___/ \__,_|_|\_\___,_\ \__,_|\___||___/\__|____/|_|
Uncover the true IP address of websites safeguarded by Cloudflare & others.

[+] Version      : {VERSION_TAG}
[+] Created By   : {AUTHOR}
 \u2514\u27A4 Twitter      : {TWITTER_LINK}
 \u2514\u27A4 Discord      : {DISCORD_LINK}
 \u2514\u27A4 Website      : {WEBSITE_LINK}
 \u2514\u27A4 Blog         : {BLOG_LINK}
 \u2514\u27A4 Github       : {GITHUB_LINK}
'''

def print_banner() -> str:
    """Return banner string."""
    return BANNER