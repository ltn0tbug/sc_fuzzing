import yaml
import sys
from pathlib import Path

MODULE_ROOT_PATH = Path(__file__).parent.parent.as_posix()
WORKSPACE_PATH = Path(__file__).parent.parent.parent.as_posix()
GLOBAL_CONFIG_PATH = Path(MODULE_ROOT_PATH, "config.yml").as_posix()

def load_yaml(file_path):
    """Load a YAML file and return its content."""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def get_config(config_path):
    """Load and return the configuration from the given YAML file path."""
    return load_yaml(config_path)

def get_global_config():
    """Load and return the global configuration from the default config path."""
    if not Path(GLOBAL_CONFIG_PATH).exists():
        raise FileNotFoundError(f"Global configuration file not found at {GLOBAL_CONFIG_PATH}")
    return get_config(GLOBAL_CONFIG_PATH)

GLOBAL_CONFIG = get_global_config()