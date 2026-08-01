"""Foundry-project scaffolding for both dataset kinds.

Merges the two legacy `_runner*.py` scaffolders into one module dispatched by
`Contract.kind`:

  - **inline** (SmartBugs): write the single source string to `src/<target>.sol`,
    auto-detect solc, no fork.
  - **fork** (DeFiHackLabs): copy the fetched multifile `src/` tree verbatim,
    emit remappings + a fork-aware `foundry.toml` ([rpc_endpoints] + the on-chain
    optimizer/runs/evm settings), pin the target's `pragma` to the exact on-chain
    solc version (coverage-fidelity — `_pin_target_pragma`), and hand back a
    `ForkConfig`. (An extra `--use` retry still covers a build that fails outright.)

`prepare(contract, dataset_spec)` does scaffold → build → artifact-load and
returns a `Prepared` carrying everything `run.py` needs (or a non-ok status +
reason, never raising for expected failures). Shared helpers
(`build_project`, `find_artifact`, `_ensure_forge_std`) are kept once.

Fork infra also lives here: `RPC_ENDPOINTS` (chain→ordered archive endpoint list,
best first), `resolved_endpoints` (health-gate selection over that list), and
`preflight_fork` — the pre-run gate run.py invokes for fork datasets that probes
RPC health (aborts a chain with no live archive endpoint) and warms the forge
cache per contract.

Bodies are lifted from the previous `experiment_run/_runner.py` and
`_runner_defihacklabs.py`.
"""

from __future__ import annotations

import atexit
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]          # src/experiment/run → repo root
sys.path.insert(0, str(ROOT / "src"))

from fuzz.config import ForkConfig  # noqa: E402

# src/experiment/dataloader/schema.py — typed Contract records.
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from schema import Contract  # noqa: E402

from registry import DatasetSpec  # noqa: E402

FORGE_STD_SRC = ROOT / "vault_test" / "lib" / "forge-std"  # in-repo checkout (stable)
RESULTS_ROOT = ROOT / "output" / "experiment"   # repo-root ./output/experiment/<dataset>/<method>

# Per-process scaffold root; atexit removes it on clean exit. SIGKILL leaves an
# orphan dir behind; OS tmp-cleanup handles that on reboot.
SCAFFOLD_ROOT = Path(tempfile.mkdtemp(prefix="exp_scaffold_"))
atexit.register(shutil.rmtree, str(SCAFFOLD_ROOT), True)

# Public archive RPCs used by vm.createSelectFork (fork kind). Each chain maps to
# an ORDERED list of archive endpoints (best/most-reliable first) so a run that
# hits a flaky endpoint can ROTATE to a spare (foundry.py::run_input rewrites the
# foundry.toml url on a transient fork-RPC failure). Foundry caches every
# (chain, block, slot) read under ~/.foundry/cache/rpc/, so cost only hits
# cold-start. The pre-flight health gate (`preflight_fork`) probes these at each
# contract's fork block and reorders `_SELECTED_ENDPOINTS` so a live archive node
# leads. (drpc/blastapi confirmed archive 2026-06-03; publicnode + ankr are the
# fallbacks — all serve historical state.)
# drpc.org is the confirmed-working primary for every chain (probed 2026-07-07 —
# archive, responds to a plain POST once a browser User-Agent is set; see
# _probe_endpoint). publicnode is the reqwest-usable archive fallback (its
# Cloudflare edge 403s a bare urllib probe but forge's own client reaches it) and
# blastapi is the long-standing BSC archive node. ankr/nodies were dropped —
# ankr now requires an API key and nodies is flaky.
RPC_ENDPOINTS: dict[str, list[str]] = {
    "mainnet":   ["https://eth.drpc.org",
                  "https://ethereum-rpc.publicnode.com",
                  "https://rpc.mevblocker.io"],
    "bsc":       ["https://bsc-mainnet.public.blastapi.io",
                  "https://bsc.drpc.org",
                  "https://bsc-rpc.publicnode.com"],
    "fantom":    ["https://fantom.drpc.org",
                  "https://fantom-rpc.publicnode.com"],
    "avalanche": ["https://avalanche.drpc.org",
                  "https://avalanche-c-chain-rpc.publicnode.com"],
    "arbitrum":  ["https://arbitrum.drpc.org",
                  "https://arbitrum-one-rpc.publicnode.com"],
    "polygon":   ["https://polygon.drpc.org",
                  "https://polygon-bor-rpc.publicnode.com"],
    "base":      ["https://base.drpc.org",
                  "https://base-rpc.publicnode.com"],
    "optimism":  ["https://optimism.drpc.org",
                  "https://optimism-rpc.publicnode.com"],
}

# Public RPC edges (drpc / cloudflare-fronted nodes) reject the default
# `Python-urllib/3.x` User-Agent with 403, so the health probe presents a
# browser UA. forge's own reqwest client sends its own UA and is unaffected.
_PROBE_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

# Pre-flight override (set by `preflight_fork`): chain → live endpoints, healthy
# node first. Empty → use RPC_ENDPOINTS as-is. `resolved_endpoints` reads this so
# scaffolding + ForkConfig.rpc_endpoints pick up the health-gate's ordering.
_SELECTED_ENDPOINTS: dict[str, list[str]] = {}


def resolved_endpoints(chain: str) -> list[str]:
    """Ordered archive endpoints for `chain` (pre-flight selection if any, else
    the static RPC_ENDPOINTS list). Empty list for an unknown chain."""
    return list(_SELECTED_ENDPOINTS.get(chain) or RPC_ENDPOINTS.get(chain, []))

# NOTE (carried from _runner_defihacklabs.py): no per-contract SIGALRM watchdog.
# Every blocking point is a `forge` subprocess that self-bounds via
# subprocess.run(timeout=…) in foundry.py; SIGALRM can't interrupt a blocked
# C-level communicate() and mislabels merely-slow contracts as stalled — a false
# skip. The forge-level timeout is the correct, sufficient guard.

_CONTRACT_RE = re.compile(
    r"^\s*(?P<abstract>abstract\s+)?(?P<kind>contract|library|interface)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
_SOLC_VER_RE = re.compile(r"v(\d+\.\d+\.\d+)")


class AmbiguousTargetError(ValueError):
    """Raised when inline source has multiple concrete contracts and no explicit target."""


# ── Target resolution (inline) ────────────────────────────────────────────────

def find_target_contract(source: str) -> str | None:
    """Pick the single deployable concrete contract, else raise/return None.

    Two+ concrete contracts → AmbiguousTargetError; the dataset entry must set
    `target_contract`. Silently guessing the last contract caused us to fuzz
    helper contracts instead of the real vulnerable one.
    """
    decls = [m.groupdict() for m in _CONTRACT_RE.finditer(source)]
    concrete = [d for d in decls if d["kind"] == "contract" and not d["abstract"]]
    if not concrete:
        return None
    if len(concrete) == 1:
        return concrete[0]["name"]
    names = [d["name"] for d in concrete]
    raise AmbiguousTargetError(
        f"source defines {len(concrete)} concrete contracts ({names}); "
        f"set `target_contract` to disambiguate"
    )


def _solc_version_from_meta(compiler_version: str | None) -> str | None:
    """'v0.8.10+commit.fc410830' → '0.8.10'."""
    if not compiler_version:
        return None
    m = _SOLC_VER_RE.search(compiler_version)
    return m.group(1) if m else None


def _default_evm_for_solc(solc_version: str | None) -> str | None:
    """solc's OWN built-in default `--evm-version` when it is pre-Constantinople.

    solc < 0.5.5 defaults to `byzantium` (no `SHR`), so its selector dispatcher
    shifts with `EXP/DIV`; a newer forge default makes the same solc emit an `SHR`
    dispatcher — a total opcode drift from the deployed code (2020-06_Bancor, 0.4.26).
    Returns None for newer solc (its default already aligns with forge's, and the
    shared build's artifact is fine). Floored implicitly at byzantium."""
    if not solc_version:
        return None
    try:
        parts = tuple(int(x) for x in solc_version.split("."))
    except ValueError:
        return None
    return "byzantium" if parts < (0, 5, 5) else None


def _coverage_evm_override(contract: Contract) -> str | None:
    """EVM to build the coverage artifact under when it must differ from the harness
    build's EVM (see `ForkConfig.coverage_evm_version`). Returns non-None only for a
    pre-Constantinople target whose meta `evm_version` is the non-canonical 'Default'
    (a concrete evm is already pinned in foundry.toml for the whole build). Today only
    Bancor (0.4.26) qualifies; newer/explicit rows get None → no extra build."""
    evm = (contract.extend.get("evm_version") or "").lower()
    if evm and evm not in ("default", ""):
        return None
    return _default_evm_for_solc(_solc_version_from_meta(contract.compiler))


def inline_source_text(contract: Contract) -> str:
    """Inline (SmartBugs) source text. Source now lives on disk under the
    dataset's source/ tree; `source.path` is repo-relative."""
    if contract.source.inline:
        return contract.source.inline
    if contract.source.path:
        return (ROOT / contract.source.path).read_text(errors="replace")
    return ""


def _find_target_source_path(work: Path, target: str) -> Path | None:
    """Path of the file declaring `contract <target>` (walks src/); None if none."""
    rx = re.compile(rf"^\s*(?:abstract\s+)?contract\s+{re.escape(target)}\b", re.M)
    for path in (work / "src").rglob("*.sol"):
        try:
            txt = path.read_text(errors="replace")
        except Exception:
            continue
        if rx.search(txt):
            return path
    return None


def read_target_source(work: Path, target: str) -> str:
    """Source text of the file declaring `target` (walks src/); '' if not found."""
    path = _find_target_source_path(work, target)
    return path.read_text(errors="replace") if path else ""


_PRAGMA_SOLIDITY_RE = re.compile(r"pragma\s+solidity[^;]*;")


def _pin_target_pragma(work: Path, target: str, solc_version: str | None) -> None:
    """Tighten the target file's `pragma solidity` to the EXACT on-chain compiler
    version so `auto_detect_solc` compiles it under that version instead of the
    highest *installed* solc that satisfies a caret range.

    This is the fork coverage-fidelity fix: e.g. BEC's source is `^0.4.16` but was
    deployed with 0.4.19; auto-detect would otherwise pick the newest installed
    0.4.x → a different dispatcher/opcode stream → the recompiled bytecode no
    longer matches on-chain and the source map (hence coverage) is invalid. The
    on-chain version always satisfies the original pragma (it compiled on-chain),
    so pinning to it is safe. Only the target's own file is rewritten; its imports
    keep their ranges and forge resolves the unit to this exact version. A
    pragma-less source gets one injected. No-op when the version is unknown.
    """
    if not solc_version:
        return
    path = _find_target_source_path(work, target)
    if path is None:
        return
    try:
        txt = path.read_text(errors="replace")
    except Exception:
        return
    pin = f"pragma solidity {solc_version};"
    if _PRAGMA_SOLIDITY_RE.search(txt):
        fixed = _PRAGMA_SOLIDITY_RE.sub(pin, txt)
    else:
        # Inject after the first SPDX line if present, else at the very top —
        # keeps SPDX first (solc requires it before any pragma on some versions).
        lines = txt.splitlines(keepends=True)
        insert_at = 0
        for i, ln in enumerate(lines[:5]):
            if _SPDX_LINE_RE.match(ln):
                insert_at = i + 1
                break
        nl = "\n" if not (lines and lines[0].endswith("\n")) else "\n"
        lines.insert(insert_at, pin + nl)
        fixed = "".join(lines)
    if fixed != txt:
        path.write_text(fixed)


# ── Shared project bits ───────────────────────────────────────────────────────

def _ensure_forge_std(work: Path) -> None:
    lib_dir = work / "lib"
    lib_dir.mkdir(exist_ok=True)
    fs_target = lib_dir / "forge-std"
    if fs_target.exists() or fs_target.is_symlink():
        return
    # Only symlink the in-repo checkout if it actually has Test.sol; a partially
    # wiped checkout would fail every harness compile silently.
    if (FORGE_STD_SRC / "src" / "Test.sol").is_file():
        fs_target.symlink_to(FORGE_STD_SRC.resolve())
    else:
        subprocess.run(
            ["forge", "install", "foundry-rs/forge-std", "--no-git", "--quiet"],
            cwd=work, check=False, capture_output=True,
        )


def build_project(work: Path, solc_version: str | None = None) -> tuple[bool, str]:
    """`forge build --ast --silent`; optional `--use <solc>`. Returns (ok, brief).

    `--ast` adds the source AST to each artifact (branch positions +
    ContractFeatures.from_ast). Forge auto-detect picks the highest *installed*
    solc, not the highest *compatible*, so legacy pragmas need the explicit pin.
    """
    cmd = ["forge", "build", "--ast", "--silent"]
    if solc_version:
        cmd.extend(["--use", solc_version])
    proc = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        return False, err.split("\n")[0][:240]
    return True, ""


def find_artifact(work: Path, target: str) -> Path | None:
    candidates = list((work / "out").glob(f"*/{target}.json"))
    return candidates[0] if candidates else None


# ── Source normalization ──────────────────────────────────────────────────────

_SPDX_LINE_RE = re.compile(r"^\s*//\s*SPDX-License-Identifier:", re.IGNORECASE)


def _dedup_spdx(text: str) -> str:
    """Keep the first SPDX-License-Identifier per file, neutralize the rest.

    Etherscan flattens multi-file verified sources into one blob, carrying each
    original file's SPDX line; solc rejects >1 SPDX identifier per file
    (Error 3716). Blanking the duplicates to bare `//` preserves line numbers so
    AST branch positions stay aligned. Files with ≤1 SPDX are returned unchanged.
    """
    seen = False
    out: list[str] = []
    for ln in text.splitlines(keepends=True):
        if _SPDX_LINE_RE.match(ln):
            if seen:
                out.append("//\n" if ln.endswith("\n") else "//")
                continue
            seen = True
        out.append(ln)
    return "".join(out)


def _normalize_sources(work: Path) -> None:
    """Rewrite each scaffolded .sol with deduped SPDX (only if changed)."""
    src = work / "src"
    if not src.exists():
        return
    for f in src.rglob("*.sol"):
        try:
            txt = f.read_text(errors="replace")
        except Exception:
            continue
        fixed = _dedup_spdx(txt)
        if fixed != txt:
            f.write_text(fixed)


# ── Inline (SmartBugs) scaffold ───────────────────────────────────────────────

def _scaffold_inline(contract: Contract) -> Path:
    work = SCAFFOLD_ROOT / contract.safe_id
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    (work / "src").mkdir()
    (work / "test").mkdir()
    (work / "foundry.toml").write_text(
        "[profile.default]\n"
        'src = "src"\n'
        'out = "out"\n'
        'libs = ["lib"]\n'
        "auto_detect_solc = true\n"
    )
    (work / "src" / f"{contract.target_contract}.sol").write_text(inline_source_text(contract))
    _normalize_sources(work)
    _ensure_forge_std(work)
    return work


# ── Fork (DeFiHackLabs) scaffold ──────────────────────────────────────────────

def _write_fork_foundry_toml(work: Path, evm_version: str | None,
                             optimizer: bool | None = None,
                             optimizer_runs: int | None = None) -> None:
    """foundry.toml with [rpc_endpoints] + the on-chain compiler settings.

    We deliberately do NOT pin a single `solc` version here: auto_detect_solc lets
    forge invoke a per-pragma compiler so a contract on 0.7.x coexists with
    forge-std (>=0.8.13) and our ^0.8 test file. The EXACT target version is
    instead pinned by tightening the target source's own `pragma` (see
    `_pin_target_pragma`), which constrains only the target's compilation unit.

    The optimizer / runs / evm_version DO belong here — they are global build
    settings (not per-file) and must match the on-chain deploy or the recompiled
    `deployedBytecode` drifts from what executes on the fork (coverage miss-map).
    forge's default is optimizer OFF / 200 runs, so a contract deployed with
    `optimizer=true, runs=999999` recompiles to a totally different opcode stream
    unless we thread its real settings through. Harmless to the ^0.8 test file
    (optimizer/evm apply uniformly; the target's bytecode is what we measure).
    """
    lines = [
        "[profile.default]",
        'src = "src"',
        'out = "out"',
        'libs = ["lib"]',
        "auto_detect_solc = true",
    ]
    if optimizer is not None:
        lines.append(f"optimizer = {'true' if optimizer else 'false'}")
    if optimizer_runs is not None:
        lines.append(f"optimizer_runs = {int(optimizer_runs)}")
    # 'Default'/'' is a non-canonical meta string forge ignores. We do NOT resolve it
    # to solc's built-in default HERE, because this toml drives the whole build incl.
    # the forge-std harness, and pinning byzantium for an old target (2020-06_Bancor,
    # 0.4.26) breaks forge-std's constantinople-only `shl`. A pre-Constantinople target
    # instead gets a SEPARATE target-only coverage build under its real EVM in
    # FoundryFuzzer.compile() (ForkConfig.coverage_evm_version); the harness stays modern.
    if evm_version and evm_version.lower() not in ("default", ""):
        lines.append(f'evm_version = "{evm_version.lower()}"')
    lines += ["", "[rpc_endpoints]"]
    # One url per chain — the currently-selected healthy endpoint (first of the
    # resolved list). run_input rotates it in place on a transient RPC failure.
    lines += [f'{chain} = "{resolved_endpoints(chain)[0]}"' for chain in RPC_ENDPOINTS]
    (work / "foundry.toml").write_text("\n".join(lines) + "\n")


def _write_remappings(work: Path) -> None:
    """Etherscan bundles ship deps in non-standard layouts solc can't resolve
    without remaps (src/@openzeppelin/…, src/lib/solmate/…). Emit one remap per
    top-level dir under src/ and src/lib/."""
    src = work / "src"
    if not src.exists():
        return
    remaps: dict[str, str] = {}
    for sub in src.iterdir():
        if sub.is_dir() and sub.name.startswith("@"):
            remaps[sub.name] = f"src/{sub.name}/"
    lib = src / "lib"
    lib_bases: dict[str, str] = {}   # dir name → its remap base, for @scope/pkg pairing
    if lib.is_dir():
        for sub in lib.iterdir():
            if not sub.is_dir():
                continue
            inner = sub / "src"
            base = f"src/lib/{sub.name}/src/" if inner.is_dir() else f"src/lib/{sub.name}/"
            remaps[sub.name] = base
            lib_bases[sub.name] = base
            if "openzeppelin" in sub.name.lower():
                nested = sub / "contracts"
                if nested.is_dir():
                    remaps["@openzeppelin/contracts"] = f"src/lib/{sub.name}/contracts/"
    # Scoped imports (`@uniswap/v3-core/…`) whose package dir was flattened on disk
    # to a bare name (`src/lib/v3-core/`): the bare-name remap above can't satisfy
    # them. Pair each `@scope/pkg` import whose last component matches a lib dir.
    scoped: set[str] = set()
    for f in src.rglob("*.sol"):
        try:
            txt = f.read_text(errors="replace")
        except Exception:
            continue
        for m in re.finditer(r"""import[^'"]*['"](@[\w.-]+/[\w.-]+)/""", txt):
            scoped.add(m.group(1))
    for prefix in scoped:
        pkg = prefix.rsplit("/", 1)[-1]
        if pkg in lib_bases and prefix not in remaps:
            remaps[prefix] = lib_bases[pkg]
    if remaps:
        lines = sorted(f"{prefix}/={path}" for prefix, path in remaps.items())
        (work / "remappings.txt").write_text("\n".join(lines) + "\n")


def _scaffold_fork(contract: Contract) -> Path:
    work = SCAFFOLD_ROOT / contract.safe_id
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    (work / "src").mkdir()
    (work / "test").mkdir()

    src_dir = ROOT / contract.source.dir
    if contract.source.multifile:
        shutil.copytree(src_dir / "src", work / "src", dirs_exist_ok=True)
    else:
        prim = contract.source.primary or contract.source.files[0]
        shutil.copy(src_dir / prim, work / "src" / Path(prim).name)

    _write_fork_foundry_toml(
        work,
        contract.extend.get("evm_version"),
        optimizer=contract.extend.get("optimizer"),
        optimizer_runs=contract.extend.get("optimizer_runs"),
    )
    _write_remappings(work)
    _normalize_sources(work)
    # Pin the target's pragma to the exact on-chain solc version so the recompiled
    # bytecode reproduces the deployed one (coverage-fidelity fix — see docstring).
    _pin_target_pragma(work, contract.target_contract, _solc_version_from_meta(contract.compiler))
    _ensure_forge_std(work)
    return work


# ── Public prepare() ──────────────────────────────────────────────────────────

@dataclass
class Prepared:
    ok: bool
    status: str                       # "ok" | "skip" | "build_fail"
    reason: str = ""
    work: Path | None = None
    target: str | None = None
    abi: list[dict] | None = None
    source: str | None = None
    fork_cfg: ForkConfig | None = None
    ctor_args: list | None = None      # extend.constructor_args (local deploy)
    ctor_value: object | None = None   # extend.constructor_value (payable ctor)
    pre_deploy: list | None = None     # extend.pre_deploy (co-located dep deploys)
    setup_calls: list | None = None    # extend.setup_calls (post-deploy wiring)
    external: list | None = None       # extend.external (declared non-target callable contracts, fork)
    setup_template: str | None = None  # extend.setup_template (per-sample full template, fork)


def prepare(contract: Contract, dataset_spec: DatasetSpec) -> Prepared:
    """Scaffold + build + load the artifact for one contract.

    Returns a `Prepared`; expected failures (ambiguous target, no concrete
    contract, build error) come back as non-ok statuses rather than exceptions.
    """
    if contract.is_fork:
        target = contract.target_contract
        if not target:
            return Prepared(False, "skip", "no target_contract in metadata")
        work = _scaffold_fork(contract)
        ok, msg = build_project(work)
        if not ok:  # retry with the pinned compiler for legacy pragmas
            pinned = _solc_version_from_meta(contract.compiler)
            if pinned:
                ok, msg = build_project(work, solc_version=pinned)
        if not ok:
            return Prepared(False, "build_fail", msg, work=work, target=target)
        art = find_artifact(work, target)
        if art is None or not art.is_file():
            return Prepared(False, "build_fail", f"artifact {target}.json not found", work=work, target=target)
        abi = json.loads(art.read_text()).get("abi", [])
        source = read_target_source(work, target)
        fork = contract.fork
        # Proxy: coverage anchors on the IMPLEMENTATION's code/PCs (the arena's
        # delegatecall frame runs impl code under the impl address); calls + the
        # financial-loss oracle stay on the proxy target_address.
        is_proxy = bool(contract.extend.get("proxy"))
        impl = contract.extend.get("implementation")
        code_address = impl if (is_proxy and impl) else fork.target_address
        fork_cfg = ForkConfig(
            chain=fork.chain,
            fork_block=fork.block,
            target_address=fork.target_address,
            code_address=code_address,
            is_proxy=is_proxy and bool(impl),
            coverage_evm_version=_coverage_evm_override(contract),
            # Ordered spares for run_input's on-failure endpoint rotation
            # (pre-flight health gate leads with a live one).
            rpc_endpoints=resolved_endpoints(fork.chain),
        )
        return Prepared(
            True, "ok", work=work, target=target, abi=abi, source=source, fork_cfg=fork_cfg,
            external=contract.extend.get("external"),
            setup_template=contract.extend.get("setup_template"),
        )

    # inline kind
    src_text = inline_source_text(contract)
    try:
        target = contract.target_contract or find_target_contract(src_text)
    except AmbiguousTargetError as e:
        return Prepared(False, "skip", f"ambiguous_target: {e}")
    if not target:
        return Prepared(False, "skip", "no concrete contract")
    work = _scaffold_inline(contract)
    ok, msg = build_project(work)
    if not ok:
        return Prepared(False, "build_fail", msg, work=work, target=target)
    art = find_artifact(work, target)
    if art is None or not art.is_file():
        return Prepared(False, "build_fail", f"artifact {target}.json not found", work=work, target=target)
    abi = json.loads(art.read_text())["abi"]
    return Prepared(
        True, "ok", work=work, target=target, abi=abi, source=src_text,
        ctor_args=contract.extend.get("constructor_args"),
        ctor_value=contract.extend.get("constructor_value"),
        pre_deploy=contract.extend.get("pre_deploy"),
        setup_calls=contract.extend.get("setup_calls"),
        # Inline rows may also opt into the fork-style escape hatch: declared
        # external vars + a per-sample full template. None for the common case.
        external=contract.extend.get("external"),
        setup_template=contract.extend.get("setup_template"),
    )


# ── Pre-flight fork-infra gate (RPC health + forge-cache warm-up) ─────────────
# A DeFiHackLabs (fork) experiment only starts once the fork infra is sound:
#   D. every REQUIRED chain has ≥1 live ARCHIVE endpoint at the fork block, and
#   E. every fork contract's storage is warm in ~/.foundry/cache/rpc/ (one
#      successful setUp), so measured iterations don't hit cold RPC mid-run — the
#      exact thing that 5xx'd and mislabelled iters as fork_setup_failed.
# D is a hard gate (abort if a required chain is fully dead). E is best-effort +
# reported (a cold contract is retried in-run by foundry.py's fork retry) — we do
# NOT abort per-contract on a cold cache, only when a whole chain is dead (D).

def _probe_endpoint(url: str, block: int, address: str, *, timeout: float = 8.0,
                    debug: bool = False) -> bool:
    """True iff `url` serves ARCHIVE state at `block` — an `eth_getBalance` of
    `address` at that historical block returns a result. A pruned / head-only
    node errors (or a dead endpoint raises) → False. Archive depth matters: the
    endpoint must serve the fork block's state, not just the chain head."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
        "params": [address, hex(block)],
    }).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": _PROBE_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception as e:  # URLError / timeout / HTTPError / JSON error
        if debug:
            print(f"      probe FAIL {url} → {type(e).__name__}: {str(e)[:80]}")
        return False
    if isinstance(data, dict) and data.get("result") is not None:
        return True
    if debug:
        print(f"      probe FAIL {url} → rpc error: {str(data.get('error'))[:80]}")
    return False


def _warm_contract(contract: Contract, dataset_spec: DatasetSpec, *,
                   debug: bool = False) -> tuple[bool, str]:
    """Warm one fork contract's forge RPC cache: scaffold + build + run ONE setUp
    (an empty fuzz input) so `vm.createSelectFork` + the target/externals' storage
    reads land in ~/.foundry/cache/rpc/. Uses the same retry machinery as a real
    iteration. Returns (warm, detail). A build/scaffold failure is NOT an RPC
    problem, so it reports (False, "build:…") without failing the chain gate."""
    from fuzz.fuzzer.foundry import FoundryFuzzer
    from fuzz.llm.agent import FuzzInput

    prep = prepare(contract, dataset_spec)
    if not prep.ok:
        return False, f"{prep.status}:{prep.reason[:60]}"
    fuzzer = FoundryFuzzer(
        str(prep.work), prep.target, abi=prep.abi,
        contract_source=prep.source, fork=prep.fork_cfg,
        external=prep.external, setup_template=prep.setup_template,
    )
    if not fuzzer.compile():
        return False, "compile_failed"
    try:
        res = fuzzer.run_input(FuzzInput([]))
    except Exception as e:  # never let warm-up crash the pre-flight
        return False, f"{type(e).__name__}:{str(e)[:60]}"
    if res.revert_reason == "fork_setup_failed":
        return False, f"rpc:{res.raw_reason[:60]}"
    return True, "ok"


def preflight_fork(contracts: list[Contract], dataset_spec: DatasetSpec, *,
                   warm: bool = True, debug: bool = False) -> tuple[bool, str]:
    """Gate a fork experiment: probe RPC health (abort if any required chain has
    0 live archive endpoints) then warm each fork contract's cache (best-effort,
    reported). Populates `_SELECTED_ENDPOINTS` so scaffolding leads with a live
    endpoint. Returns (ok, message); ok=False → the caller must abort. A no-fork
    contract set (inline dataset / no fork rows) passes trivially."""
    fork_contracts = [c for c in contracts if c.is_fork and c.fork]
    if not fork_contracts:
        return True, "no fork contracts — pre-flight skipped"

    # ── D. RPC health per required chain (archive check at the fork block) ──
    by_chain: dict[str, list[Contract]] = {}
    for c in fork_contracts:
        by_chain.setdefault(c.fork.chain, []).append(c)

    print("Pre-flight RPC health (archive check at fork block):")
    for chain in sorted(by_chain):
        cs = by_chain[chain]
        # Probe at the OLDEST block on this chain (deepest archive requirement).
        probe_c = min(cs, key=lambda c: c.fork.block)
        candidates = resolved_endpoints(chain)
        live = [u for u in candidates
                if _probe_endpoint(u, probe_c.fork.block, probe_c.fork.target_address, debug=debug)]
        if not live:
            msg = (f"chain '{chain}': 0/{len(candidates)} archive endpoints live "
                   f"(probed block {probe_c.fork.block}) — aborting")
            print(f"  ❌ {msg}")
            return False, msg
        # Live endpoints first, then the rest (still usable as rotation spares).
        _SELECTED_ENDPOINTS[chain] = live + [u for u in candidates if u not in live]
        print(f"  ✅ {chain}: {len(live)}/{len(candidates)} live (best={live[0]})")

    # ── E. forge-cache warm-up per fork contract (best-effort, reported) ──
    if not warm:
        return True, "health ok (warm-up skipped)"
    n_fc = len(fork_contracts)
    print(f"Pre-flight forge-cache warm-up ({n_fc} fork contract{'s' if n_fc != 1 else ''}):")
    warmed, cold = [], []
    for i, c in enumerate(fork_contracts, 1):
        ok, detail = _warm_contract(c, dataset_spec, debug=debug)
        (warmed if ok else cold).append((c.id, detail))
        mark = "✅" if ok else "🧊"
        print(f"  [{i:3d}/{len(fork_contracts)}] {mark} {c.id}"
              + ("" if ok else f" ({detail})"))
        time.sleep(0.2)  # gentle on rate-limited public endpoints
    if cold:
        # Best-effort: cold contracts are retried in-run (foundry.py fork retry),
        # so we PROCEED but surface them. Only a dead chain (D) aborts.
        print(f"  ⚠ {len(cold)} cold (retried in-run): "
              + ", ".join(cid for cid, _ in cold[:10])
              + (" …" if len(cold) > 10 else ""))
    return True, f"health ok, {len(warmed)} warm / {len(cold)} cold"
