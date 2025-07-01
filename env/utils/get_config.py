import yaml
import sys

def load_yaml(file_path):
    """Load a YAML file and return its content."""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def get_config(config_path):
    """Load and return the configuration from the given YAML file path."""
    return load_yaml(config_path)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python get_config.py <config_path>")
        sys.exit(1)
    CONFIG_PATH = sys.argv[1]
    config = get_config(CONFIG_PATH)
    print(config)


