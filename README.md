# 🔐 Smart Contract Fuzzing Framework

The **Smart Contract Fuzzing Framework** is a modular Python toolkit for automated fuzzing, dynamic analysis, and testing of Ethereum smart contracts. It is built to support research and development in smart contract security, with a plug-and-play architecture enabling easy integration of components such as:

- 🧠 **LLM-based fuzzing strategies**
- 🤖 **Reinforcement learning agents**
- 🔍 **Execution tracing and vulnerability detection tools**

The framework uses **Ganache** and **Truffle** for Ethereum simulation and contract deployment, and is designed with modularity in mind—each submodule has its own scope, logic, and documentation (`README.md`), making it easier to extend and maintain.

---

## 🧩 Project Modules

The main modules of the framework are organized under the `sc_fuzzing/` directory:

| Module                                           | Description                                      | Status             |
|--------------------------------------------------|--------------------------------------------------|--------------------|
| [`env/`](sc_fuzzing/env/README.md)               | Core environment setup and interaction logic     | ✅ Done             |
| [`data/`](sc_fuzzing/data/README.md)             | Preprocessed smart contracts in Truffle format   | ✅ Done             |
| [`llm/`](sc_fuzzing/llm/README.md)               | LLM-based fuzzing strategy implementation        | ⚠️ In Development   |
| [`rl/`](sc_fuzzing/rl/README.md)                 | Reinforcement learning-based fuzzing             | ⚠️ In Development   |



---

## 📦 Installation

### Requirements

- **Python** 3.8+
- **Node.js** 17+

### Setup

```bash
# Python environment
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt

# Node and Ethereum tools
npm install -g ganache@7.9.2 truffle@5.11.5