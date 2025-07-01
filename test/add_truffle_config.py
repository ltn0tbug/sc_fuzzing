import sys
sys.path.append(r"/home/ltn0tbug/workspace/")

from sc_fuzzing.env.utils import add_truffle_config

project_path = "./test"

config = {
    "host": "127.0.0.1",
    "port": 8545,
    "network_id": "*"
}

add_truffle_config(project_path, config)