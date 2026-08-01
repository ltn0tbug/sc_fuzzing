"""Render the sweep's actual CompileError fuzz_inputs through the REAL fuzzer path.

Earlier probe was unfair (called _normalize_arg directly, bypassing _render_args
which already builds memory arrays). This reconstructs each stored CompileError
iteration's calls, renders them via FoundryFuzzer._build_calls_code (the real path),
wraps them in a harness using the real interface, compiles, and reports the true
solc error + the offending rendered Solidity. Answers: what actually breaks?
"""
from __future__ import annotations
import glob, json, os, re, subprocess, sys, tempfile, shutil
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]      # src/experiment/eda → repo root
sys.path.insert(0, str(ROOT / "src"))
from fuzz.fuzzer.foundry import FoundryFuzzer
from fuzz.fuzzer.sol_interface import _render_interface, interface_eligible


def eligible_names(abi):
    """Function names the FIXED pipeline can select (Class A: tuple fns dropped)."""
    return {f["name"] for f in interface_eligible(abi)
            if f.get("type", "function") == "function" and f.get("name")}


def fixed_pipeline_calls(calls, names):
    """Model the fixed pool: drop any bare target-call to a function the fixed
    selectors can no longer choose (tuple-typed). Sentinels ('atk.setReentrantCall'),
    external '<var>.<method>' heads, and eligible functions are kept."""
    out = []
    for c in calls:
        head = c[0] if c else ""
        if head == "atk.setReentrantCall" or "." in str(head) or head in names:
            out.append(c)
    return out

def make_fuzzer(abi):
    f = FoundryFuzzer.__new__(FoundryFuzzer)
    f._external = {}
    f._external_consts = frozenset()
    f._external_callable = frozenset()
    f._abi_types, f._abi_outputs, f._abi_payable = {}, {}, set()
    for it in interface_eligible(abi):  # matches the fixed FoundryFuzzer.__init__
        if it.get("type") == "function" and it.get("name"):
            f._abi_types.setdefault(it["name"], []).append([i.get("type","") for i in it.get("inputs",[])])
            f._abi_outputs.setdefault(it["name"], []).append([o.get("type","") for o in it.get("outputs",[])])
            if it.get("stateMutability") == "payable":
                f._abi_payable.add(it["name"])
    f._referenced_rets = set()
    f._bound_rets = set()
    return f

def harness(iface, calls_code):
    return ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            'import "forge-std/Test.sol";\n'
            + iface.replace("interface IT", "interface ITT") + "\n"
            "contract H is Test {\n"
            "    ITT target;\n"
            "    Attacker attacker;\n"
            "    address attacker_address; address target_address; address deployer_address;\n"
            "    function run() external {\n        " + calls_code + "\n    }\n}\n"
            "contract Attacker { constructor(address){} }\n")

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    # Any results tree of per-contract run JSONs works; default to the canonical
    # experiment output. Override with SWEEP_DIR to replay a scratch/verify sweep.
    sweep = os.environ.get("SWEEP_DIR", str(ROOT / "output" / "experiment" / "defihacklabs"))
    abis = {}
    for f in glob.glob(str(ROOT / "data" / "defihacklabs" / "source" / "*" / "abi.json")):
        cid = os.path.basename(os.path.dirname(f))
        try: abis[cid] = json.load(open(f))
        except Exception: pass

    d = tempfile.mkdtemp(); os.makedirs(d + "/src")
    os.symlink(str(ROOT / "vault_test" / "lib"), d + "/lib")
    open(d + "/remappings.txt","w").write("forge-std/=lib/forge-std/src/\n")
    open(d + "/foundry.toml","w").write('[profile.default]\nsrc="src"\n')

    codes = Counter(); examples = {}; rendered_ok = fail = 0
    for jf in glob.glob(os.path.join(sweep, "**", "*.json"), recursive=True):
        if jf.endswith("_summary.json"): continue
        cid = os.path.basename(jf)[len("defihacklabs_"):-len(".json")]
        if only and only not in cid: continue
        abi = abis.get(cid)
        if not abi: continue
        try: data = json.load(open(jf))
        except Exception: continue
        iface = _render_interface("IT", abi)
        names = eligible_names(abi)
        for it in data.get("iterations") or []:
            fo = it.get("fuzzing_output", {})
            if fo.get("forge_status") != "CompileError" or "arena" in str(fo.get("raw_reason","")):
                continue
            calls = it.get("fuzz_input", {}).get("calls", [])
            # Model the FIXED pipeline: tuple-typed functions are no longer selectable.
            calls = fixed_pipeline_calls(calls, names)
            fz = make_fuzzer(abi)
            try:
                code = fz._build_calls_code(calls)
            except Exception as e:
                codes[f"RENDER-EXC:{type(e).__name__}"] += 1
                examples.setdefault(f"RENDER-EXC:{type(e).__name__}", (cid, str(e)[:120], ""))
                continue
            open(d + "/src/H.sol","w").write(harness(iface, code))
            r = subprocess.run(["forge","build","--root",d,"--force"], capture_output=True, text=True)
            if r.returncode == 0:
                rendered_ok += 1
                continue
            fail += 1
            m = re.search(r"Error \((\d+)\): ([^\n]{0,80})", r.stdout + r.stderr)
            key = m.group(1) if m else "?"
            codes[key] += 1
            if key not in examples:
                # find the offending call name
                examples[key] = (cid, (m.group(2).strip() if m else ""), code[:400])
    shutil.rmtree(d)

    print(f"Re-rendered stored CompileError inputs through REAL path:")
    print(f"  still fail: {fail}   now compile OK: {rendered_ok}\n")
    print("error codes:", dict(codes))
    for k,(cid,msg,snippet) in examples.items():
        print(f"\n--- code {k}  [{cid}] {msg}")
        if snippet: print("    rendered:", snippet[:300].replace(chr(10)," ⏎ "))

if __name__ == "__main__":
    main()
