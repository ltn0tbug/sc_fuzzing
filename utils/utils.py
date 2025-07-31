import logging
import yaml
from pathlib import Path
import sys

MODULE_ROOT_PATH = Path(__file__).parent.parent.as_posix()
WORKSPACE_PATH = Path.cwd()
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
GLOBAL_LOG_PATH = GLOBAL_CONFIG.get("log_path", Path(WORKSPACE_PATH, "logs").as_posix())

class TruncatingFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%', max_length=10_000):
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.max_length = max_length

    def format(self, record):
        msg = super().format(record)
        if len(msg) > self.max_length:
            print(len(msg))
            msg = msg[:self.max_length] + '... [truncated]'
        return msg

def set_logging(verbosity:int=2, log_file:str=None, truncate:bool=False):
    logger = logging.getLogger()

    formatter_class = TruncatingFormatter if truncate else logging.Formatter

    if log_file is None:
        handler = logging.StreamHandler(sys.stdout)
        formatter = formatter_class('[%(levelname)s] %(message)s') if verbosity >=2 else formatter_class('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        handler = logging.FileHandler(log_file)
        formatter = formatter_class('[%(asctime)s][%(name)s][%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level=[logging.NOTSET, logging.DEBUG, logging.INFO, logging.ERROR, logging.CRITICAL, logging.CRITICAL + 1][verbosity])