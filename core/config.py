"""Configuration loader and manager for PyVPN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.crypto import generate_key, key_from_base64, key_to_base64

CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.json"
EXAMPLE_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.example.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "server_host": "127.0.0.1",
    "server_port": 51820,
    "client_ip": "10.8.0.2",
    "server_vpn_ip": "10.8.0.1",
    "subnet_mask": "255.255.255.0",
    "dns_server": "1.1.1.1",
    "pre_shared_key": "",
}


def load_config() -> Dict[str, Any]:
    """Loads configuration from config.json, or creates a default one with a freshly generated key."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            # Ensure all default keys exist
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg

    # If config.json does not exist, create a default one
    cfg = DEFAULT_CONFIG.copy()
    new_key = generate_key()
    cfg["pre_shared_key"] = key_to_base64(new_key)
    save_config(cfg)
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    """Save configuration dictionary to config.json."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def get_crypto_key(cfg: Dict[str, Any]) -> bytes:
    """Extract and validate 32-byte cryptographic key from configuration."""
    key_b64 = cfg.get("pre_shared_key", "").strip()
    if not key_b64 or key_b64 == "GENERATE_YOUR_BASE64_KEY_HERE":
        # Generate and save a new key
        raw_key = generate_key()
        cfg["pre_shared_key"] = key_to_base64(raw_key)
        save_config(cfg)
        return raw_key
    return key_from_base64(key_b64)
