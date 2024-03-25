import os

import toml

from .utils import *

# TODO: Verify the existence of `config.toml` before anything else, if it's missing, copy raw config file from github to get updated information.

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "config.toml")
CONFIG_DATA = {
    "api_key": {
        "security_trails": ""
    },
    "owner": {
        "author": "Spyboy",
        "twitter": "https://spyboy.in/twitter",
        "discord": "https://spyboy.in/Discord",
        "website": "https://spyboy.in/",
        "blog": "https://spyboy.blog/",
        "github": "https://github.com/spyboy-productions/CloakQuest3r"
    },
    "version": {
        "version_tag": "1.0.5"
    }
}

def create_config_file() -> None:
    with open(CONFIG_PATH, "w") as file:
        toml.dump(CONFIG_DATA, file)
     
    print(f"{G}[+] {C}New config.toml file created successfully. Make sure to add your SecurityTrails API key.")

def recover_api_key() -> str:
    try:
        with open(CONFIG_PATH) as file:
            conf = toml.load(file)

        return conf['api_key']['security_trails']

    except FileNotFoundError:
        print(f'{R}[!] Configuration file "config.toml" not found!{W}')
        create_config_file() 