import configparser

from pathlib import Path


CONFIG_FILE = Path(
    "security/config/parser.conf"
)


config = configparser.ConfigParser()

config.read(CONFIG_FILE)


def get(section, key):

    return config.get(section, key)
