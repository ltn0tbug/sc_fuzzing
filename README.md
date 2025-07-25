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
| [`env/`](env/README.md)               | Core environment setup and interaction logic     | ✅ Done             |
| [`data/`](data/README.md)             | Preprocessed smart contracts in Truffle format   | ✅ Done             |
| [`llm/`](llm/README.md)               | LLM-based fuzzing strategy implementation        | ⚠️ In Development   |
| [`rl/`](rl/README.md)                 | Reinforcement learning-based fuzzing             | ⚠️ In Development   |



---

## 📦 Installation

```bash
# Python (3.8+) environment 
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt

# Node (17+) dependency 
npm install -g ganache@7.9.2 truffle@5.11.5
```

## 🤝 Collaborators

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/ltn0tbug/">
        <img src="https://avatars.githubusercontent.com/u/71972700?v=4" width="100px;" alt="ltn0tbug"/><br />
        <sub><b>ltn0tbug</b></sub>
      </a>
      <br />
      <!-- 💻 Project Lead -->
    </td>
    <td align="center">
      <a href="https://github.com/frogin-mag">
        <img src="https://avatars.githubusercontent.com/u/101979911?v=4" width="100px;" alt="frogin-mag"/><br />
        <sub><b>frogin-mag</b></sub>
      </a>
      <br />
      <!-- ⚙️ Blockchain Integration -->
    </td>
    <td align="center">
      <a href="https://github.com/hovikhanh">
        <img src="https://avatars.githubusercontent.com/u/85947145?v=4" width="100px;" alt="ViKa_618"/><br />
        <sub><b>ViKa_618</b></sub>
      </a>
      <br />
      <!-- 🧪 Testing & Examples -->
    </td>
  </tr>
</table>