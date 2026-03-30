import os
from pathlib import Path
from typing import Dict

from dotenv import dotenv_values, load_dotenv, set_key


BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

API_ENV_KEYS = {
    "SHODAN_API_KEY": "",
    "CENSYS_API_ID": "",
    "CENSYS_API_SECRET": "",
    "VIRUSTOTAL_API_KEY": "",
    "HIBP_API_KEY": "",
}


def load_api_keys_to_environment() -> None:
    try:
        load_dotenv(dotenv_path=ENV_FILE, override=True)
    except Exception:
        pass


def get_api_key_values() -> Dict[str, str]:
    load_api_keys_to_environment()
    file_values = dotenv_values(ENV_FILE)

    values: Dict[str, str] = {}
    for key, default_value in API_ENV_KEYS.items():
        env_value = os.getenv(key)
        file_value = file_values.get(key)
        values[key] = str(env_value or file_value or default_value)
    return values


def save_api_key_values(api_values: Dict[str, str]) -> bool:
    try:
        if not ENV_FILE.exists():
            ENV_FILE.touch()

        for key in API_ENV_KEYS:
            value = str(api_values.get(key, "")).strip()
            set_key(str(ENV_FILE), key, value)

        load_api_keys_to_environment()
        return True
    except Exception:
        return False
