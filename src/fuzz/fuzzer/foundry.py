"""Foundry/EVM integration for executing fuzz inputs."""

import json
import logging
import os
import random
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from string import Template

from .coverage import (
    BytecodeMeta,
    compute_coverage_from_dump,
    fetch_onchain_code,
    load_bytecode_meta,
    parse_dump,
    resolve_eip1967_impl,
)
from .results import CoverageStats, FuzzResult
from .sol_interface import (
    _CTOR_ADDR_ALIASES,
    _abi_to_interface,
    _constructor_encode_call,
    _detect_mode,
    _find_constructor_abi,
    _random_arg_for_type,
    _render_interface,
    _solidity_default_for,
    interface_eligible,
)

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
# Repo root (…/fuzz), used to resolve repo-relative per-sample setup
# templates passed via FuzzerConfig.setup_template.
_REPO_ROOT = Path(__file__).resolve().parents[3]

# Cap on the `forge test --debug --dump` trace file we'll load for coverage.
# parse_dump() does json.loads(read_text()) — peak memory is ~2× the file size
# in raw text plus the parsed-object overhead. A pathological random input on a
# complex forked contract (e.g. a fee/swap loop) can emit a multi-hundred-MB
# step trace; one DFS run measured a 2.7 GB RSS peak and got OOM-killed (Jetsam)
# inside the full runner. Above this size we skip coverage for that single
# iteration (logging a warning) rather than risk killing the whole contract run.
# Such gas-heavy inputs are rarely the coverage-expanding ones anyway.
# 1 GB cap: parsing a dump this size can spike RSS to several GB (raw text +
# decoded JSON), so keep an eye on headroom alongside torch in the runner; it
# sits far above normal dumps (<10 MB even for complex contracts at 15 iters)
# and only drops the pathological deep-loop traces that risk an OOM kill.
_MAX_DUMP_BYTES = 1024 * 1024 * 1024

# Live-RSS ceiling for a `forge test --debug --dump` subprocess. The _MAX_DUMP_BYTES
# guard above is post-hoc — it only fires once forge has WRITTEN the dump, after its
# in-memory step arena has already peaked. But forge holds the entire debug arena in
# RAM *before* serializing it, so a single pathological input (an LLM-generated call
# that drives a contract into a huge gas-bounded loop — CFToken hit 4.8 GB then 8.2 GB
# on consecutive runs) OOM-kills the whole process group before our file cap ever sees
# a dump. This ceiling is enforced live: a watchdog polls the forge process tree's RSS
# and SIGKILLs it if it crosses the cap, so one runaway iteration loses only its own
# coverage/outcome instead of taking down the contract run. Normal dumps peak far below
# this (forge RSS is a few hundred MB even for complex forked contracts). Override with
# SC_FUZZ_FORGE_MEM_CAP_MB.
_FORGE_MEM_CAP_MB = int(os.environ.get("SC_FUZZ_FORGE_MEM_CAP_MB", "3072"))
_FORGE_RSS_POLL_S = 0.3


class _BoundedProc:
    """subprocess.CompletedProcess-shaped result from `_run_forge_bounded`, plus
    flags saying whether the watchdog killed the run (memory) or it timed out."""

    __slots__ = ("stdout", "stderr", "returncode", "mem_exceeded", "timed_out")

    def __init__(self, stdout, stderr, returncode, mem_exceeded, timed_out):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.mem_exceeded = mem_exceeded
        self.timed_out = timed_out


def _proc_group_rss_kb(pgid: int) -> int:
    """Sum RSS (KB) of every process in process-group `pgid` (forge + any solc it
    forks). Uses `ps` so it stays dependency-free and works on macOS (no /proc)."""
    try:
        out = subprocess.run(
            ["ps", "-axo", "pgid=,rss="], capture_output=True, text=True, timeout=5
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return 0
    total = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                if int(parts[0]) == pgid:
                    total += int(parts[1])
            except ValueError:
                continue
    return total


def _run_forge_bounded(cmd, cwd, timeout: int, mem_cap_mb: int) -> _BoundedProc:
    """Run a forge command under BOTH a wall-clock timeout and a live-RSS ceiling.

    The debug/dump pass can balloon forge's memory without ever timing out, so a
    background watchdog polls the process group's total RSS and SIGKILLs it once it
    exceeds `mem_cap_mb`. Returns a CompletedProcess-shaped object; `mem_exceeded`
    / `timed_out` tell the caller the run was aborted so it can drop that iteration
    rather than trust a truncated dump."""
    proc = subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        pgid = proc.pid
    cap_kb = mem_cap_mb * 1024
    state = {"mem_exceeded": False}
    stop = threading.Event()

    def _watch() -> None:
        while not stop.wait(_FORGE_RSS_POLL_S):
            if _proc_group_rss_kb(pgid) > cap_kb:
                state["mem_exceeded"] = True
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                return

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        stdout, stderr = proc.communicate()
    finally:
        stop.set()
        watcher.join(timeout=1)
    return _BoundedProc(
        stdout or "", stderr or "", proc.returncode, state["mem_exceeded"], timed_out
    )

# Hard cap on reentrancy re-entry depth (`max_count` in setReentrantCall).
# Enforced at this single execution chokepoint so EVERY source — rlfuzz's random
# args, the LLM (gen/mut/seed), and the reentry_depth mutator — is bounded
# regardless of what it emits. Deep re-entry (the random generator used [1,20])
# rarely exercises new logic; it just replays the same path, and `forge --debug`
# records every EVM step of every re-entry, so deep traces ballooned to 17 GB
# and OOM-killed the run. 5 keeps re-entry tests meaningful while bounding the
# trace; the _MAX_DUMP_BYTES guard above remains the backstop.
MAX_REENTRY_COUNT = 5

# ── Fork-RPC failure detection + retry ────────────────────────────────────────
# A fork run can fail for a reason that has NOTHING to do with the fuzzed calls:
# the public archive RPC behind `vm.createSelectFork` rejects a request. This
# happens at TWO points, not just setup:
#   1. createSelectFork setup — the fork can't be instantiated at the block, OR
#   2. mid-execution storage fetch — an `eth_getStorageAt` during the run 5xxes /
#      times out / is rate-limited, so the `--debug --dump` pass aborts with no
#      arena (forge prints "debug arena is empty", which is only the SYMPTOM).
# The TRUE cause is a `sharedbackend` error line ("Failed to send/recv storage …
# HTTP error 5xx"), which forge emits on stdout (the arena line is on stderr).
# We detect either signal in either stream so the iteration is labelled a
# fork-RPC failure (retried below) rather than mislabelled a compile error.
_FORK_RPC_FAIL_SIGNS = (
    "debug arena is empty",
    "sharedbackend",
    "failed to get storage",
    "failed to send/recv",
    "could not instantiate forked environment",
    "backend: could not fetch",
    "error sending request",
)
_HTTP_ERR_RE = re.compile(r"http error (4\d\d|5\d\d)", re.IGNORECASE)
# Lines worth surfacing as the real cause (over the generic arena symptom).
_FORK_CAUSE_SIGNS = ("sharedbackend", "failed to get storage", "failed to send/recv")

# Retry a transient fork-RPC failure a few times with linear backoff; rotate to
# the next endpoint (ForkConfig.rpc_endpoints) when the chain has spares. Only
# fork_setup_failed is retried — never compile errors, genuine reverts, or bug
# signals. fork_setup_failed usually fails fast (an RPC 5xx returns immediately),
# so the retries don't multiply the 120s per-call timeout in the common case.
_FORK_RETRY_ATTEMPTS = 3
_FORK_RETRY_BACKOFF_S = 1.5


def _detect_fork_rpc_failure(stdout: str, stderr: str) -> str | None:
    """Return the real fork-RPC-failure cause line if either stream shows one,
    else None. Prefers the informative `sharedbackend`/HTTP-error line over the
    generic "debug arena is empty" symptom so logs name the actual cause."""
    blob = f"{stdout}\n{stderr}"
    low = blob.lower()
    if not (any(s in low for s in _FORK_RPC_FAIL_SIGNS) or _HTTP_ERR_RE.search(low)):
        return None
    for ln in blob.split("\n"):
        s = ln.strip()
        if not s:
            continue
        sl = s.lower()
        if any(sig in sl for sig in _FORK_CAUSE_SIGNS) or _HTTP_ERR_RE.search(sl):
            return s[:200]
    return next((l.strip()[:200] for l in blob.split("\n") if l.strip()), "fork RPC failure")


def _load_template(name: str) -> Template:
    return Template((_TEMPLATES_DIR / name).read_text())


# Shared Solidity harness (unified Attacker + SCFuzzHarness oracle base) that all
# three generated test files `import "./Harness.sol"`. It carries no ${...}
# placeholders, so it's copied verbatim next to the test (not string-substituted).
_HARNESS_SOL = (_TEMPLATES_DIR / "Harness.sol").read_text()


def _write_harness_file(test_dir: Path) -> None:
    """Write Harness.sol into the project's test dir so the relative import in the
    generated test resolves. Idempotent; only rewrites when the content differs."""
    test_dir.mkdir(parents=True, exist_ok=True)
    dst = test_dir / "Harness.sol"
    if not dst.exists() or dst.read_text() != _HARNESS_SOL:
        dst.write_text(_HARNESS_SOL)




class FoundryFuzzer:
    """Wraps Foundry to compile contracts and execute fuzz inputs."""

    # Revert signatures → human-readable reasons
    REVERT_SIGNATURES: dict[str, str] = {
        "Panic(uint256)": "arithmetic_overflow",
        "Error(string)": "assertion_failed",
        "0x4e487b71": "arithmetic_overflow",  # Panic selector
    }

    def __init__(
        self,
        foundry_project: str,
        contract_name: str,
        abi: list[dict] | None = None,
        initial_balance_native: int = 10,
        contract_source: str | None = None,
        fork=None,
        constructor_args: list | None = None,
        constructor_value=None,
        pre_deploy: list | None = None,
        setup_calls: list | None = None,
        external: list | None = None,
        setup_template: str | None = None,
    ):
        self.foundry_project = Path(foundry_project)
        self.contract_name = contract_name
        self.initial_balance_native = initial_balance_native
        self._abi = list(abi) if abi else []
        # ForkConfig | None — when set, _build_test() emits fork.sol.tpl.
        self.fork = fork
        # Deploy-time constructor arguments / payable value for local (non-fork)
        # targets. None args → synthesize type-default sentinels (prior behavior);
        # an explicit list is rendered with alias resolution. See _constructor_render.
        self.constructor_args = constructor_args
        self.constructor_value = constructor_value
        # Co-located dependency deploys + post-deploy wiring for local targets that
        # reference a sibling contract defined in the SAME source file (e.g. a
        # SmartBugs PrivateBank whose constructor/setter takes a Log address). Each
        # pre_deploy entry {"contract": <Name>, "name": <alias>, "args": [...]} is
        # deployed in setUp BEFORE the target and bound to `_depaddr_<alias>`; that
        # alias then resolves in constructor_args and in setup_calls. setup_calls
        # ({"fn": <name>, "args": [...]}) are issued on the target AFTER deploy to
        # wire the dependency via the contract's own public API. Both only deploy /
        # call what the source itself defines — no answer-key state. See
        # _dep_setup_render / _constructor_render.
        self.pre_deploy = list(pre_deploy) if pre_deploy else []
        self.setup_calls = list(setup_calls) if setup_calls else []

        # Per-sample full template path (fork mode). When set, _build_test loads
        # this complete contract and substitutes only ${calls_code}; the external
        # decls are baked into the file. See _load_setup_template.
        self.setup_template = setup_template

        # Declared non-target contracts the fuzzer may call. Each var → a resolved
        # record carrying the interface name, address, per-method input-type lists
        # (with overloads), output-type lists, and the payable set — the external
        # analogue of self._abi_types/_abi_outputs/_abi_payable below. A call whose
        # head is "<var>.<method>" renders against IInterface(<var>); the var name
        # itself is a Solidity address constant resolvable as an address argument.
        # An entry is CALLABLE when it carries an `abi` (renders an interface +
        # address constant; usable as a "<var>.<method>" head AND as an address
        # arg). An entry with NO abi is DATA-ONLY: it renders just an
        # `address constant <var>` — a named on-chain address (a victim/holder,
        # an LP pair, a token passed only as an arg) the PoC/LLM can reference by
        # name in an address slot, but cannot call. `interface` is None for those.
        self._external: dict[str, dict] = {}
        for ext in (external or []):
            var = ext.get("var")
            if not var:
                continue
            abi_items = ext.get("abi") or []
            callable_ = bool(abi_items)
            types: dict[str, list[list[str]]] = {}
            outputs: dict[str, list[list[str]]] = {}
            payable: set[str] = set()
            for item in abi_items:
                if item.get("type", "function") != "function":
                    continue
                fname = item.get("name")
                if not fname:
                    continue
                types.setdefault(fname, []).append(
                    [i.get("type", "") for i in item.get("inputs", [])]
                )
                outputs.setdefault(fname, []).append(
                    [o.get("type", "") for o in item.get("outputs", [])]
                )
                if item.get("stateMutability") == "payable":
                    payable.add(fname)
            self._external[var] = {
                "interface": (ext.get("interface") or f"I{var}") if callable_ else None,
                "address": ext.get("address"),
                "abi": abi_items,
                "types": types,
                "outputs": outputs,
                "payable": payable,
            }
        # The set of names usable as a Solidity address literal in an arg slot:
        # every declared external var (each is an `address constant`), callable or
        # data-only.
        self._external_consts: frozenset[str] = frozenset(self._external)
        # Names that may head a "<var>.<method>" call — callable entries only.
        self._external_callable: frozenset[str] = frozenset(
            v for v, r in self._external.items() if r["interface"]
        )

        # function name → list of input-type lists (one per overload), preserved in ABI order.
        # When the contract overloads a name (e.g. transfer(address,uint256) AND
        # transfer(uint256)), every signature lives here; `_select_overload(name, arity)`
        # picks the right one at call time.  `_abi_payable` is name-level and stays a set —
        # any-payable-wins is harmless because the EVM still rejects ETH at a non-payable call.
        self._abi_types: dict[str, list[list[str]]] = {}
        # function name → list of output-type lists (one per overload). Parallel to
        # _abi_types; backs $ret<idx> chaining (the return of a target call used as
        # a later arg needs its Solidity type to declare the local var).
        self._abi_outputs: dict[str, list[list[str]]] = {}
        self._abi_payable: set[str] = set()
        if abi:
            # Class A: the callable pool must match the synthesized interface —
            # drop tuple-typed functions here too (interface_eligible = the single
            # source of truth shared with _render_interface / GBNF / baselines).
            for item in interface_eligible(abi):
                if item.get("type") == "function":
                    types = [inp.get("type", "") for inp in item.get("inputs", [])]
                    self._abi_types.setdefault(item["name"], []).append(types)
                    self._abi_outputs.setdefault(item["name"], []).append(
                        [o.get("type", "") for o in item.get("outputs", [])]
                    )
                    if item.get("stateMutability") == "payable":
                        self._abi_payable.add(item["name"])

        # Detect pragma version of the contract under test. Contracts on solc <0.8
        # cannot share a compilation unit with our ^0.8.0 test file, so we switch
        # to a "legacy" template that talks to the contract via an interface and
        # deploys it through vm.getCode + assembly create.
        # Mode routing:
        #   "fork"   → DeFiHackLabs / on-chain target (fork.sol.tpl)
        #   "legacy" → pragma <0.8 SmartBugs contracts (inline_legacy.sol.tpl)
        #   "modern" → default (inline.sol.tpl)
        if self.fork is not None:
            self._mode = "fork"
            logger.info(
                "FoundryFuzzer: fork mode — chain=%s block=%d target=%s",
                self.fork.chain, self.fork.fork_block, self.fork.target_address,
            )
        else:
            self._mode = _detect_mode(contract_source)
            if self._mode == "legacy":
                logger.info(
                    "FoundryFuzzer: legacy-pragma mode (interface + vm.getCode deploy)"
                )

        self._contract_source: str | None = contract_source

        # Bytecode metadata for coverage. Loaded lazily in compile() (after forge
        # build produces the artifact). None means coverage is unavailable for
        # this contract — fuzz still runs, just without a coverage gradient.
        self._bc_meta: BytecodeMeta | None = None

        # Cumulative branch / line / function sets accumulated across all iterations.
        self._seen_branch_ids: set[tuple[int, int]] = set()      # source-level: (source_line, direction)
        self._seen_bc_branch_ids: set[tuple[int, int]] = set()   # bytecode-level: (jumpi_pc, direction)
        self._seen_line_ids: set[int] = set()
        self._seen_function_ids: set[str] = set()
        # Exploit-path memory for the bug-reward gate: each entry is the
        # bc_branches_this_run of an exploit that already earned the bug bonus.
        # A new exploit only scores if its path is distinct (Jaccard<0.9) from
        # all of these — mirrors `_seen_bc_branch_ids` coverage dedup, but for
        # whole attack paths. See fuzzer/paths.py.
        self._rewarded_exploit_paths: list[frozenset] = []

        self._last_coverage: CoverageStats = CoverageStats()

        # Resolved on-chain/local address of the target contract, used to map the
        # debug dump's arenas to the target. In fork mode it's known up front
        # (ForkConfig). In inline mode the target is deployed by our setUp at a
        # deterministic address, so we LEARN it on the first coverage pass (via
        # forge's identified_contracts) and cache it here. Once known, run_input
        # can collapse its two forge invocations into one (--json + --debug --dump
        # together) because coverage no longer needs the identified_contracts map
        # that --json blanks — we filter the dump arenas by this address instead.
        self._target_addr_cache: str | None = None

        # Fork coverage anchors on the EXECUTING code's address, which differs
        # from target_address for a proxy: the debug arena records the impl's
        # delegatecall frame under the impl (code) address, so the coverage dump
        # is filtered by THIS address (not target_address, which would collect
        # only the tiny proxy dispatcher). Seeded from ForkConfig.code_address;
        # overwritten by the EIP-1967 resolution in _fetch_onchain_bytecode.
        self._code_addr: str | None = (
            (fork.code_address or fork.target_address) if fork is not None else None
        )

        # Per-render scratch for $ret<idx> output chaining, reset at the start of
        # every _build_calls_code / _build_reentrancy_test. `_referenced_rets` =
        # call indices whose return is used by a later call's $ret token;
        # `_bound_rets` = those that actually got a `_ret<idx>` local emitted.
        self._referenced_rets: set[int] = set()
        self._bound_rets: set[int] = set()

    def compile(self) -> bool:
        """Compile the Foundry project. Returns True on success.

        `--ast` writes the source AST as a top-level field of each per-contract
        artifact under `out/<file>.sol/<Contract>.json`. We use it in
        `load_bytecode_meta` for ground-truth branch positions and in
        `ContractFeatures.from_ast` for the DQN state-vector features —
        replacing the prior regex heuristics.
        """
        # The generated tests `import "./Harness.sol"`; ensure it's present before any
        # forge build/test sees a (possibly lingering) test file referencing it.
        _write_harness_file(self.foundry_project / "test")
        try:
            result = subprocess.run(
                ["forge", "build", "--ast"],
                cwd=self.foundry_project,
                capture_output=True,
                text=True,
                # The only forge call that lacked a timeout. Build is local (no
                # fork RPC), but a cold solc download or a pathological compile
                # could otherwise hang the runner indefinitely. 300s is generous
                # for first-time solc fetch + AST build; the per-test forge calls
                # in run_input() use the tighter 120s fork-aware bound.
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.error("forge build timed out after 300s")
            return False
        if result.returncode != 0:
            logger.error("forge build failed:\n%s", result.stderr)
            return False
        logger.info("Compilation succeeded.")

        # A pre-Constantinople fork target (ForkConfig.coverage_evm_version) can't be
        # built under its real EVM in the shared build above — that build also compiles
        # the forge-std harness, which needs constantinople `shl`. Do a target-only
        # coverage build (--skip test/*, so forge-std isn't touched) under the target's
        # EVM into out_cov/; the main out/ (harness, modern) is untouched so forge test
        # is unaffected. load_bytecode_meta then reads the correctly-compiled target.
        cov_out_dir = self._build_coverage_artifact()

        # Fork mode: fetch the runtime bytecode that ACTUALLY executes on the fork
        # so coverage anchors on it (the artifact may not reproduce the deployed
        # bytecode). For a proxy that's the implementation's code — resolve the
        # EIP-1967 slot at the fork block (fall back to the meta-provided impl in
        # ForkConfig.code_address). None on RPC failure → coverage falls back to
        # the artifact denominator, flagged unreliable by load_bytecode_meta.
        onchain_bytecode = self._fetch_onchain_bytecode()

        # Load bytecode metadata for coverage (uniform across modern + legacy modes).
        # The artifact's runtime sourceMap is produced by solc — works for any version.
        self._bc_meta = load_bytecode_meta(
            self.foundry_project, self.contract_name, source_text=self._contract_source,
            onchain_bytecode=onchain_bytecode, out_dir=cov_out_dir,
        )
        if self._bc_meta is not None and self.fork is not None and onchain_bytecode is None:
            # Fork target we couldn't anchor (RPC fetch failed): the artifact
            # denominator is unverified, so bc + source are both best-effort — be
            # honest and flag the whole thing unreliable rather than reporting a
            # ratio we can't stand behind.
            self._bc_meta.coverage_unreliable = True
        if self._bc_meta is None:
            logger.warning("Coverage disabled — could not load bytecode metadata.")
        else:
            logger.info(
                "Coverage targets: %d branches (%d bc-branches), %d lines, %d functions%s.",
                self._bc_meta.total_branches, self._bc_meta.total_bc_branches,
                self._bc_meta.total_lines, self._bc_meta.total_functions,
                " [SOURCE UNRELIABLE — bc/function on-chain-anchored]"
                if self._bc_meta.coverage_unreliable else "",
            )
        return True

    def _build_coverage_artifact(self) -> "Path | None":
        """For a pre-Constantinople fork target, compile a target-only coverage
        artifact under its real EVM into out_cov/ and return that dir (for
        load_bytecode_meta). Returns None when no override is needed (the shared
        out/ artifact is already correct) or on build failure (fall back to out/).

        `--skip 'test/*'` excludes the forge-std harness, so its constantinople-only
        `shl` never sees the byzantium EVM; `--out out_cov` keeps the main out/
        (harness, modern) intact for forge test."""
        cov_evm = getattr(self.fork, "coverage_evm_version", None) if self.fork else None
        if not cov_evm:
            return None
        cov_out = self.foundry_project / "out_cov"
        try:
            r = subprocess.run(
                ["forge", "build", "--ast", "--skip", "test/*",
                 "--evm-version", cov_evm, "--out", "out_cov"],
                cwd=self.foundry_project, capture_output=True, text=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Coverage build (evm=%s) timed out — using default out/.", cov_evm)
            return None
        if r.returncode != 0:
            logger.warning(
                "Coverage build (evm=%s) failed — using default out/:\n%s", cov_evm, r.stderr[-400:])
            return None
        logger.info("Coverage artifact built under evm=%s (out_cov/).", cov_evm)
        return cov_out

    def _fetch_onchain_bytecode(self) -> bytes | None:
        """Runtime bytecode executing at the fork target (impl code for a proxy),
        or None for inline mode / on RPC failure. Used to anchor coverage on the
        deployed code. Resolves the proxy impl via the EIP-1967 slot at the fork
        block, falling back to ForkConfig.code_address (meta-provided impl)."""
        if self.fork is None:
            return None
        endpoints = list(self.fork.rpc_endpoints or [])
        block = self.fork.fork_block
        code_addr = self.fork.code_address or self.fork.target_address
        if self.fork.is_proxy:
            resolved = resolve_eip1967_impl(endpoints, self.fork.target_address, block)
            if resolved:
                code_addr = resolved
                self._code_addr = resolved  # arena filter uses the resolved impl
        code = fetch_onchain_code(endpoints, code_addr, block)
        if code is None:
            logger.warning(
                "Coverage: eth_getCode(%s @ %d) failed on all %d endpoint(s) — "
                "coverage falls back to the artifact denominator (flagged unreliable).",
                code_addr, block, len(endpoints),
            )
        return code

    def run_input(self, fuzz_input, strategy: str = "", debug: bool = False) -> FuzzResult:
        """Execute a single FuzzInput and return a FuzzResult.

        Single forge invocation per iteration:
          forge test --match-path <test> --json -vvv --debug --dump <dump.json> --allow-failure

        This produces both:
          - stdout JSON  → test result, gas, revert reason, decoded console.logs
          - dump.json    → per-call PC traces with stack/memory/storage

        The dump is parsed by `coverage.parse_dump` → `compute_coverage_from_dump`
        to extract branch / line / function coverage. The dump is deleted after parsing.
        """
        test_src = self._build_test(fuzz_input, strategy=strategy)
        if debug:
            debug_lines: list[str] = []
            for call in fuzz_input.calls:
                if call[0] == "atk.setReentrantCall" and len(call) > 1 and isinstance(call[1], dict):
                    d = call[1]
                    debug_lines += self._reentry_setup_lines(
                        d.get("reentrant_func", ""),
                        list(d.get("reentrant_args", [])),
                        int(d.get("max_count", 3)),
                    )
            debug_lines += [l.strip() for l in self._build_calls_code(fuzz_input.calls).splitlines()]
            logger.debug("calls_code:\n%s", "\n".join(debug_lines))

        # Use a stable filename rather than tempfile.NamedTemporaryFile —
        # forge's `identified_contracts` field is empty when the test file has
        # a random tmpXXX.t.sol name. With a stable name forge correctly maps
        # deployed addresses → contract names in the dump, which our coverage
        # parser relies on (see fuzzer/coverage.py::parse_dump).
        # Use absolute paths so subprocess.run(cwd=…) doesn't double-prefix.
        test_file = (self.foundry_project / "test" / "__sc_fuzz__.t.sol").resolve()
        _write_harness_file(test_file.parent)
        test_file.write_text(test_src)

        # Dump file holds per-call PC traces emitted by `forge test --debug --dump`.
        # We delete it after parsing to avoid disk bloat. Absolute path so the
        # forge call's cwd doesn't affect where the file is written.
        dump_file = test_file.with_suffix(".dump.json")

        # forge's --match-path glob is matched against project-relative paths,
        # so we must convert. Critical on macOS where /tmp → /private/tmp:
        # forge resolves cwd to `/private/tmp/...` but an absolute /tmp/... match
        # path would silently match no tests.
        try:
            rel_test_path = test_file.relative_to(self.foundry_project)
        except ValueError:
            rel_test_path = test_file

        # Coverage is only available when we loaded bytecode metadata at compile().
        want_coverage = self._bc_meta is not None
        # We can FUSE the outcome pass (--json) and the coverage pass
        # (--debug --dump) into ONE forge invocation once the target address is
        # known. The fused dump loses `identified_contracts` (--json blanks it),
        # but coverage no longer needs that map: it filters the dump's arenas by
        # the known target address instead. Fork mode knows the address up front;
        # inline mode learns it on the first coverage pass (see
        # _update_coverage_from_dump) and caches it, so only iteration 0 pays for
        # two forge calls. Coverage/outcomes are byte-identical either way.
        # `_force_two_call` (default absent → False) is an A/B measurement hook that
        # keeps the legacy split path even when the address is known; production
        # never sets it.
        fused = (want_coverage and self._resolved_target_addr() is not None
                 and not getattr(self, "_force_two_call", False))

        def _log_proc(p) -> None:
            if not debug:
                return
            if p.stdout.strip():
                _PREVIEW = 300
                out = p.stdout
                preview = out[:_PREVIEW] + f"\n... [{len(out) - _PREVIEW} more chars]" if len(out) > _PREVIEW else out
                logger.debug("forge stdout:\n%s", preview)
            if p.stderr.strip():
                logger.debug("forge stderr:\n%s", p.stderr[:2000])

        # A fork run may fail on a transient RPC error (5xx / storage-fetch); retry
        # it a few times with backoff, rotating to the next archive endpoint when
        # the chain has spares. Non-fork runs make a single attempt.
        endpoints = list(self.fork.rpc_endpoints) if self.fork is not None else []
        max_attempts = (_FORK_RETRY_ATTEMPTS + 1) if self.fork is not None else 1
        cmd = [
            "forge", "test",
            "--match-path", str(rel_test_path),
            "--json", "-vvv",
            "--allow-failure",
        ]
        if fused:
            cmd += ["--debug", "--dump", str(dump_file)]

        try:
            call_names = [c[0] for c in fuzz_input.calls]
            fuzz_result = None
            for attempt in range(max_attempts):
                proc = _run_forge_bounded(
                    cmd, self.foundry_project, timeout=120, mem_cap_mb=_FORGE_MEM_CAP_MB,
                )
                # A fused call carries --debug --dump; a runaway trace can blow past
                # the RSS cap (or time out) with no usable stdout. Abort just this
                # iteration rather than parse a truncated/killed run or OOM the host.
                if proc.mem_exceeded or proc.timed_out:
                    logger.warning(
                        "Forge %s on the debug/dump pass (an input drove a runaway "
                        "trace); dropping this iteration.",
                        f"exceeded the {_FORGE_MEM_CAP_MB} MB memory cap"
                        if proc.mem_exceeded else "timed out",
                    )
                    return FuzzResult(revert_reason="out_of_gas", reverted=True)
                _log_proc(proc)
                fuzz_result = self._parse_result(proc.stdout, proc.stderr, call_names)
                self._postprocess_result(fuzz_result, strategy)

                # Retry ONLY a transient fork-RPC failure — never a compile error,
                # a genuine revert, or a bug signal.
                if (self.fork is not None
                        and fuzz_result.revert_reason == "fork_setup_failed"
                        and attempt < max_attempts - 1):
                    if len(endpoints) > 1:
                        nxt = endpoints[(attempt + 1) % len(endpoints)]
                        self._set_fork_endpoint(nxt)
                        logger.warning(
                            "fork RPC failure (%s) — retry %d/%d via %s",
                            fuzz_result.raw_reason[:80], attempt + 1, max_attempts - 1, nxt,
                        )
                    else:
                        logger.warning(
                            "fork RPC failure (%s) — retry %d/%d (backoff)",
                            fuzz_result.raw_reason[:80], attempt + 1, max_attempts - 1,
                        )
                    time.sleep(_FORK_RETRY_BACKOFF_S * (attempt + 1))
                    continue
                break

            # Two-call fallback (inline, before the address is learned): a separate
            # --debug --dump call WITHOUT --json so the dump keeps
            # identified_contracts, which lets the coverage parser map name→address
            # and cache it. Skipped on a compile error (no coverage to gather) and
            # once fused. Both modes share forge's compile cache so this is fast.
            if want_coverage and not fused and fuzz_result.forge_status != "CompileError":
                dump_proc = _run_forge_bounded(
                    [
                        "forge", "test",
                        "--match-path", str(rel_test_path),
                        "--debug", "--dump", str(dump_file),
                        "--allow-failure",
                    ],
                    self.foundry_project, timeout=120, mem_cap_mb=_FORGE_MEM_CAP_MB,
                )
                # The outcome (--json) pass already succeeded above, so a runaway
                # coverage dump costs only this iteration's coverage — keep the
                # bug/outcome result and drop the (killed, possibly truncated) dump.
                if dump_proc.mem_exceeded or dump_proc.timed_out:
                    logger.warning(
                        "Forge %s building the coverage dump; skipping coverage for "
                        "this iteration (outcome kept).",
                        f"exceeded the {_FORGE_MEM_CAP_MB} MB memory cap"
                        if dump_proc.mem_exceeded else "timed out",
                    )
                    dump_file.unlink(missing_ok=True)
                elif debug and dump_proc.returncode != 0:
                    logger.debug("forge dump call rc=%d, stderr: %s", dump_proc.returncode, dump_proc.stderr[:400])

            if want_coverage:
                self._update_coverage_from_dump(dump_file, fuzz_result)

            return fuzz_result

        except subprocess.TimeoutExpired:
            logger.warning("Forge timed out.")
            return FuzzResult(revert_reason="out_of_gas", reverted=True)
        finally:
            test_file.unlink(missing_ok=True)
            dump_file.unlink(missing_ok=True)

    def _set_fork_endpoint(self, url: str) -> None:
        """Rewrite the foundry.toml `[rpc_endpoints] <chain> = "…"` line for the
        fork chain so a retry hits a different archive endpoint. On the next forge
        invocation `vm.createSelectFork("<chain>", …)` re-resolves the alias from
        the file, so no template/config change is needed. Best-effort: a missing
        or malformed toml leaves the run on its current endpoint."""
        if self.fork is None:
            return
        toml = self.foundry_project / "foundry.toml"
        try:
            text = toml.read_text()
        except OSError:
            return
        pat = re.compile(
            rf'^(\s*{re.escape(self.fork.chain)}\s*=\s*)".*?"\s*$', re.MULTILINE
        )
        new_text, n = pat.subn(rf'\g<1>"{url}"', text)
        if n:
            toml.write_text(new_text)

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # The cumulative coverage seen-sets + rewarded-exploit-path memory + learned
    # target address are the fuzzer's evolving state; the ABI/template/mode are
    # rebuilt identically on resume, so only these are persisted.
    def checkpoint_state(self) -> dict:
        return {
            "seen_branch_ids": self._seen_branch_ids,
            "seen_bc_branch_ids": self._seen_bc_branch_ids,
            "seen_line_ids": self._seen_line_ids,
            "seen_function_ids": self._seen_function_ids,
            "rewarded_exploit_paths": self._rewarded_exploit_paths,
            "target_addr_cache": self._target_addr_cache,
            "last_coverage": self._last_coverage,
        }

    def restore_checkpoint_state(self, d: dict) -> None:
        self._seen_branch_ids = set(d["seen_branch_ids"])
        self._seen_bc_branch_ids = set(d["seen_bc_branch_ids"])
        self._seen_line_ids = set(d["seen_line_ids"])
        self._seen_function_ids = set(d["seen_function_ids"])
        self._rewarded_exploit_paths = list(d["rewarded_exploit_paths"])
        self._target_addr_cache = d.get("target_addr_cache")
        self._last_coverage = d.get("last_coverage", CoverageStats())

    @property
    def unique_bc_branches(self) -> int:
        """Cumulative count of distinct bytecode-level branch edges hit so far
        (the reward-signal coverage). Read by the loops for the learning curve."""
        return len(self._seen_bc_branch_ids)

    def _resolved_target_addr(self) -> str | None:
        """Address used to map the debug dump's arenas to the target contract.

        Fork mode → the on-chain address from ForkConfig (known up front). Inline
        mode → the deterministic deploy address, learned + cached on the first
        coverage pass (None until then). When non-None, run_input can fuse its two
        forge calls into one (coverage no longer needs identified_contracts)."""
        if self.fork is not None:
            return self.fork.target_address
        return self._target_addr_cache

    def _resolved_code_addr(self) -> str | None:
        """Address the coverage dump is filtered by — the account whose runtime
        code executes. Fork: the target (or the resolved impl for a proxy). Inline:
        the learned deploy address (same as _resolved_target_addr)."""
        if self.fork is not None:
            return self._code_addr or self.fork.target_address
        return self._target_addr_cache

    def _update_coverage_from_dump(self, dump_file: Path, fuzz_result: FuzzResult) -> None:
        """Read forge's debug dump and populate fuzz_result's coverage fields.

        Sets branches_*, lines_*, and functions_* on the result. Updates the
        cumulative seen-sets so `coverage` is the running total fraction (matches
        the original behavior of `_update_coverage_from_lcov`).
        """
        if self._bc_meta is None or not dump_file.exists():
            return

        # Guard against OOM on pathological traces: parse_dump loads the whole
        # dump into memory, so an oversized trace can kill the process. Skip
        # coverage for this iteration if the dump exceeds the cap.
        dump_bytes = dump_file.stat().st_size
        if dump_bytes > _MAX_DUMP_BYTES:
            logger.warning(
                "Skipping coverage for this iteration: debug dump is %.0f MB "
                "(> %.0f MB cap) — would risk an OOM kill parsing it. The input "
                "likely hit a heavy loop; coverage delta for this run is dropped.",
                dump_bytes / 1024 / 1024, _MAX_DUMP_BYTES / 1024 / 1024,
            )
            return

        # Fork mode: the live contract isn't in forge's identified_contracts map
        # (not deployed by this test) → filter arenas by the ForkConfig address.
        # Inline mode: once we've learned the deterministic deploy address (cached
        # below on the first pass), reuse it as the override so the run_input call
        # can fuse into one forge invocation. Until then override is None and
        # parse_dump falls back to the identified_contracts name lookup.
        # Filter the arena by the EXECUTING code's address (impl for a proxy), not
        # the call target — see _resolved_code_addr. For a non-proxy the two are
        # identical; inline still uses the learned/cached target address.
        addr_override = self._resolved_code_addr()
        dump = parse_dump(dump_file, self.contract_name, target_address_override=addr_override)
        if dump.target_addr is None:
            # forge didn't identify the contract — possibly because deployment failed.
            return
        # Learn + cache the inline target address the first time forge identifies
        # it, so subsequent iterations can fuse the outcome + coverage forge calls.
        if self.fork is None and self._target_addr_cache is None:
            self._target_addr_cache = dump.target_addr
        cov = compute_coverage_from_dump(dump, self._bc_meta)
        unreliable = self._bc_meta.coverage_unreliable
        fuzz_result.coverage_unreliable = unreliable

        # Branches (source-level, run-log only). Suppressed (0/0) when the source
        # tier is unreliable — bc + functions below stay on-chain-anchored.
        branch_ids = cov.branches_hit
        new_branch_ids = branch_ids - self._seen_branch_ids
        self._seen_branch_ids |= branch_ids
        fuzz_result.branches_this_run = branch_ids
        fuzz_result.new_branches = len(new_branch_ids)
        fuzz_result.branches_total = 0 if unreliable else (self._bc_meta.total_branches or 1)

        # Bytecode-level branches (drive the reward signal)
        bc_branch_ids = cov.bc_branches_hit
        new_bc_branch_ids = bc_branch_ids - self._seen_bc_branch_ids
        self._seen_bc_branch_ids |= bc_branch_ids
        fuzz_result.bc_branches_this_run = bc_branch_ids
        fuzz_result.new_bc_branches = len(new_bc_branch_ids)
        fuzz_result.bc_branches_total = self._bc_meta.total_bc_branches or 1
        fuzz_result.bc_branch_hit_counts = dict(cov.bc_branch_hit_counts)
        # `coverage` follows the reward signal (bc-level), so cumulative ratio is comparable.
        fuzz_result.coverage = min(1.0, len(self._seen_bc_branch_ids) / fuzz_result.bc_branches_total)

        # Lines (run-log only)
        line_ids = cov.lines_hit
        new_line_ids = line_ids - self._seen_line_ids
        self._seen_line_ids |= line_ids
        fuzz_result.lines_this_run = line_ids
        fuzz_result.new_lines = len(new_line_ids)
        fuzz_result.lines_total = 0 if unreliable else self._bc_meta.total_lines
        fuzz_result.line_hit_counts = dict(cov.line_hit_counts)

        # Functions (run-log only)
        fn_ids = cov.functions_hit
        new_fn_ids = fn_ids - self._seen_function_ids
        self._seen_function_ids |= fn_ids
        fuzz_result.functions_this_run = fn_ids
        fuzz_result.new_functions = len(new_fn_ids)
        fuzz_result.functions_total = self._bc_meta.total_functions
        fuzz_result.function_hit_counts = dict(cov.function_hit_counts)

        logger.debug(
            "dump: +%d bc_branches (+%d src), +%d lines, +%d fns "
            "(cumulative bc %d/%d, src %d/%d)",
            len(new_bc_branch_ids), len(new_branch_ids), len(new_line_ids), len(new_fn_ids),
            len(self._seen_bc_branch_ids), fuzz_result.bc_branches_total,
            len(self._seen_branch_ids), fuzz_result.branches_total,
        )

    def measure_coverage(self) -> CoverageStats:
        """Return cumulative coverage at both granularities (source + bytecode)."""
        src_denom = self._bc_meta.total_branches if self._bc_meta else 0
        bc_denom  = self._bc_meta.total_bc_branches if self._bc_meta else 0
        unreliable = bool(self._bc_meta and self._bc_meta.coverage_unreliable)
        stats = CoverageStats(
            branches_hit=len(self._seen_branch_ids),
            branches_total=src_denom or len(self._seen_branch_ids) or 1,
            bc_branches_hit=len(self._seen_bc_branch_ids),
            bc_branches_total=bc_denom or len(self._seen_bc_branch_ids) or 1,
            coverage_unreliable=unreliable,
        )
        self._last_coverage = stats
        return stats

    def _build_test(self, fuzz_input, strategy: str = "") -> str:  # noqa: ARG002
        """Build a Solidity test using the unified template.

        All strategies share a single template (inline.sol.tpl) which deploys the
        unified Attacker contract at attacker_address in setUp().  Non-reentrancy
        strategies simply leave it unconfigured (Mode.NONE) — the attacker is present
        but never triggered.
        """
        return self._build_reentrancy_test(fuzz_input)

    def _build_calls_code(self, calls: list, default_caller: str = "attacker_address") -> str:
        """Render a list of calls to Solidity, prepending vm.prank() before each one.

        The caller for each call is taken from calls[i][3] when present, otherwise
        default_caller is used. This produces per-call prank isolation so mixed-actor
        sequences work correctly.

        The atk.setReentrantCall sentinel is configured separately by
        _build_reentrancy_test (it contributes no lines here). Every other entry is
        either a bare `target.fn(...)` call OR a `<var>.<method>(...)` call against a
        declared external contract (extend.external). $ret<idx> argument tokens chain
        an earlier call's return into a later call.
        """
        self._referenced_rets = self._referenced_ret_indices(calls)
        self._bound_rets = set()
        # Reset the per-iteration Tier-2 fallback counter (see _norm_default): the
        # count of args that couldn't be coerced to their declared type is a health
        # metric for the Tier-1 generators + unconstrained-LLM drift.
        FoundryFuzzer._norm_fallback_count = 0
        lines: list[str] = []
        for orig_idx, call in enumerate(calls):
            lines.extend(self._render_sequence_call(call, orig_idx, default_caller))
        return "\n        ".join(lines)

    def _render_sequence_call(self, call: list, idx: int, default_caller: str = "attacker_address") -> list[str]:
        """Render one call-sequence entry to Solidity lines (incl. its vm.prank).

        The atk.setReentrantCall sentinel is configured separately by
        _build_reentrancy_test (it contributes no lines here). A head of the form
        "<var>.<method>" where <var> is a declared external contract renders against
        that contract; any other head is a call on the main target.
        """
        if call[0] == "atk.setReentrantCall":
            return []
        caller_name = call[3] if len(call) > 3 else default_caller
        return [f"vm.prank({caller_name});", self._call_to_solidity(call, idx=idx)]

    @staticmethod
    def _referenced_ret_indices(calls: list) -> set[int]:
        """Scan every call's args for `$ret<idx>` tokens; return the referenced
        indices. These are the calls whose single return value must be bound to a
        function-scope `_ret<idx>` local so a later call can consume it."""
        refs: set[int] = set()
        pat = re.compile(r"^\$ret(\d+)")

        def scan(v):
            if isinstance(v, str):
                m = pat.match(v)
                if m:
                    refs.add(int(m.group(1)))
            elif isinstance(v, list):
                for x in v:
                    scan(x)

        for call in calls:
            if isinstance(call, list) and len(call) > 1:
                scan(call[1])
        return refs

    def _resolve_signature(
        self, method: str, arity: int,
        types_map: dict[str, list[list[str]]],
        outputs_map: dict[str, list[list[str]]],
    ) -> tuple[list[str], list[str]]:
        """Pick the overload of `method` matching `arity` and return BOTH its input
        and output type lists (same overload index), so $ret chaining can declare
        the return local with the right type. Mirrors _select_overload's resolution
        order but works for either the target maps or an external's maps."""
        overloads = types_map.get(method, [])
        if not overloads:
            return [], []
        outs = outputs_map.get(method, [])
        matches = [i for i, t in enumerate(overloads) if len(t) == arity]
        if len(matches) > 1:
            i = random.choice(matches)
            logger.warning(
                "%s has %d overloads at arity %d — choosing one at random", method, len(matches), arity
            )
        elif matches:
            i = matches[0]
        else:
            i = random.randrange(len(overloads))
        return overloads[i], (outs[i] if i < len(outs) else [])

    @staticmethod
    def _ret_decl_type(out_type: str) -> str:
        """Local-variable declaration type for a bound `_ret<idx>` — appends
        `memory` for reference types (string / bytes / arrays / tuples)."""
        ot = (out_type or "uint256").strip()
        if ot in ("string", "bytes") or ot.startswith("tuple") or ot.endswith("]"):
            return f"{ot} memory"
        return ot

    def _select_overload(self, name: str, args_arity: int) -> list[str]:
        """Pick the best-matching overload of `name` for the given arg arity.

        Resolution order:
          1. exactly one overload at `args_arity` → use it.
          2. multiple overloads at `args_arity` (same arity, types differ) →
             pick uniformly at random and log a warning so the run log can
             explain divergent behavior across iterations.
          3. no overload at `args_arity` (LLM passed wrong arg count) → pick a
             random overload of `name` and let the caller pad/truncate.
          4. `name` not in the ABI at all → return [] (caller handles it).

        Returns the arg-type list of the chosen overload.
        """
        overloads = self._abi_types.get(name, [])
        if not overloads:
            return []
        matches = [types for types in overloads if len(types) == args_arity]
        if len(matches) > 1:
            chosen = random.choice(matches)
            logger.warning(
                "%s has %d overloads with arity %d (%s) — choosing %s at random",
                name, len(matches), args_arity,
                [f"{name}({','.join(t)})" for t in matches],
                f"{name}({','.join(chosen)})",
            )
            return chosen
        if matches:
            return matches[0]
        return random.choice(overloads)

    def _reentry_setup_lines(self, reentrant_func: str, reentrant_args_raw: list, max_count: int, idx: int = 0) -> list[str]:
        """Return the Solidity lines that configure Attacker.setReentrantCall.

        The function name is resolved against the target ABI via `_select_overload`
        so name-only inputs from the LLM still land on a concrete (name, types)
        pair even when the contract overloads the name.  When `reentrant_func`
        isn't in the ABI at all (LLM hallucination), fall back to a random ABI
        function with random args of the right type.  When it IS in the ABI but
        the LLM-supplied args don't match the resolved arity, pad with random
        args / truncate.

        Returns [] when the contract has no callable functions to re-enter on.

        idx is the position of the atk.setReentrantCall entry in the original
        calls list, embedded in console.log so decoded_logs can be mapped back.
        """
        if not self._abi_types:
            return []  # nothing to re-enter on

        if reentrant_func in self._abi_types:
            arg_types = self._select_overload(reentrant_func, len(reentrant_args_raw))
            args = list(reentrant_args_raw)
            # Pad with random args of the right type if LLM gave too few;
            # truncate if it gave too many.
            if len(args) < len(arg_types):
                args.extend(_random_arg_for_type(t) for t in arg_types[len(args):])
            elif len(args) > len(arg_types):
                args = args[: len(arg_types)]
        else:
            # Fallback: pick a random target function + synthesize matching args.
            reentrant_func = random.choice(list(self._abi_types.keys()))
            arg_types = self._select_overload(reentrant_func, len(reentrant_args_raw))
            args = [_random_arg_for_type(t) for t in arg_types]

        reentrant_sig = f"{reentrant_func}({','.join(arg_types)})"

        lines: list[str] = []
        if arg_types:
            # Route through _render_args (not raw _normalize_arg) so ARRAY-typed
            # reentry args materialize as `T[] memory` temps instead of a garbage
            # scalar literal — abi.encodeWithSignature needs a typed array expr, and
            # _normalize_arg alone returns array/unknown types verbatim (the Bancor
            # claimAndConvert2(address[],…) reentry CompileError). Scalars still get
            # full Tier-2 coercion. Temp names key off `idx` (the setup entry's
            # position), distinct from the regular calls' indices → no collision.
            arg_setup, arg_exprs = self._render_args(args, arg_types, idx)
            lines.extend(arg_setup)
            normalized_args = ", ".join(arg_exprs)
            lines.append(f'bytes memory _reentrant_data = abi.encodeWithSignature("{reentrant_sig}", {normalized_args});')
        else:
            lines.append(f'bytes memory _reentrant_data = abi.encodeWithSignature("{reentrant_sig}");')
        lines.append("vm.prank(attacker_address);")
        lines.append(
            f"try attacker.setReentrantCall(_reentrant_data, {max_count}) {{}}\n"
            f'catch Error(string memory _r) {{ console.log("[{idx}] setReentrantCall fail:", _r); }}\n'
            f'catch (bytes memory) {{ console.log("[{idx}] setReentrantCall fail: low-level"); }}'
        )
        return lines

    def _ctor_value_wei(self) -> int:
        """Constructor payable value in wei (0 when unset/invalid)."""
        v = self.constructor_value
        if v is None or isinstance(v, bool):
            return 0
        if isinstance(v, int):
            return max(0, v)
        s = str(v).strip()
        try:
            return max(0, int(s, 16) if s.lower().startswith("0x") else int(s))
        except ValueError:
            return 0

    @staticmethod
    def _render_ctor_arg(value, sol_type: str, dep_names: frozenset[str] = frozenset()) -> str:
        """Render one constructor arg as a type-explicit Solidity literal.

        Type-explicit (e.g. `uint256(1)`, `address(uint160(…))`) so the same
        rendering is valid both inside `new T(…)` and inside the legacy
        `abi.encode(…)` (where a bare integer literal would mis-size the word).
        Address params accept the deploy-time aliases in _CTOR_ADDR_ALIASES plus
        any pre_deploy dependency alias in `dep_names` (→ `_depaddr_<alias>`, the
        address of a sibling contract deployed earlier in setUp).
        """
        st = (sol_type or "").strip()
        if st in ("address", "address payable"):
            s = str(value).strip()
            if s in dep_names:
                base = f"_depaddr_{s}"
                return f"payable({base})" if st == "address payable" else base
            if s in _CTOR_ADDR_ALIASES:
                base = s
            elif s == "target_address":
                raise ValueError(
                    f"constructor_args: alias {s!r} is not available at deploy time "
                    f"(target/attacker not yet deployed); use one of {sorted(_CTOR_ADDR_ALIASES)} or a raw 0x address"
                )
            else:
                base = f"address({FoundryFuzzer._normalize_address(s)})"
            return f"payable({base})" if st == "address payable" else base
        if re.match(r"^uint\d*$", st):
            ty = "uint256" if st == "uint" else st
            return f"{ty}({str(value).strip()})"
        if re.match(r"^int\d*$", st):
            ty = "int256" if st == "int" else st
            return f"{ty}({str(value).strip()})"
        if st == "bool":
            return FoundryFuzzer._normalize_arg(value, "bool")
        if re.match(r"^bytes\d+$", st):
            return f"{st}({str(value).strip()})"
        # string / dynamic bytes / fallback — _normalize_arg emits a valid literal.
        return FoundryFuzzer._normalize_arg(value, st)

    def _constructor_render(self) -> tuple[str, str, str, str]:
        """Resolve constructor args/value into template substitutions.

        Returns (modern_args, modern_value_clause, legacy_concat, legacy_value):
          modern_args        — comma-joined args for `new T(…)`  ("" if none)
          modern_value_clause— `{value: N}` or "" (payable ctor)
          legacy_concat      — `abi.encode`+`bytes.concat` block, or "" if no args
          legacy_value       — wei integer string for the assembly `create` value
        """
        ctor = _find_constructor_abi(self._abi)
        types = [i.get("type", "") for i in ctor.get("inputs", [])] if ctor else []

        wei = self._ctor_value_wei()
        modern_value = f"{{value: {wei}}}" if wei else ""
        legacy_value = str(wei)

        dep_names = frozenset(d["name"] for d in self.pre_deploy if d.get("name"))
        if self.constructor_args is not None:
            rendered = [
                self._render_ctor_arg(a, types[i] if i < len(types) else "", dep_names)
                for i, a in enumerate(self.constructor_args)
            ]
            if len(self.constructor_args) != len(types):
                logger.warning(
                    "constructor_args arity %d != constructor inputs %d for %s",
                    len(self.constructor_args), len(types), self.contract_name,
                )
            modern_args = ", ".join(rendered)
            legacy_concat = (
                f"bytes memory _ctorArgs = abi.encode({modern_args});\n"
                f"        _bc = bytes.concat(_bc, _ctorArgs);"
                if rendered else ""
            )
        elif types:
            # No explicit config — synthesize type-default sentinels so a
            # constructor-arg contract still deploys (previously modern couldn't).
            modern_args = ", ".join(
                _solidity_default_for(i.get("type", ""), i.get("components"))
                for i in ctor.get("inputs", [])
            )
            legacy_concat = _constructor_encode_call(self._abi)
        else:
            modern_args = ""
            legacy_concat = ""

        return modern_args, modern_value, legacy_concat, legacy_value

    def _dep_setup_render(self) -> tuple[str, str]:
        """Render co-located dependency deploys + post-deploy wiring for local targets.

        Returns (dep_deploys, dep_setup_calls):
          dep_deploys     — Solidity that deploys each `pre_deploy` sibling contract
                            (defined in the SAME source file as the target) and binds
                            its address to `_depaddr_<alias>`. Rendered in setUp BEFORE
                            the target so `constructor_args` can reference the alias.
                            Mode-aware: modern uses `new <C>(...)`; legacy uses the
                            same vm.getCode + assembly-create path as the target.
          dep_setup_calls — Solidity issued on the deployed target AFTER deploy, via a
                            low-level call, to wire the dependency through the
                            contract's own public API (e.g. SetLogFile). Empty when none.

        Both only deploy / call what the source itself defines — no answer-key state.
        """
        if not self.pre_deploy and not self.setup_calls:
            return "", ""

        dep_names = frozenset(d["name"] for d in self.pre_deploy if d.get("name"))

        deploys: list[str] = []
        for d in self.pre_deploy:
            name, cname = d.get("name"), d.get("contract")
            if not name or not cname:
                continue
            args = d.get("args") or []
            if self._mode == "legacy":
                # The dep is compiled into the same artifact dir as the target
                # (out/<contract_name>.sol/<cname>.json), so vm.getCode resolves it.
                deploys.append(f'bytes memory _depbc_{name} = vm.getCode("{self.contract_name}.sol:{cname}");')
                if args:  # rare — the SmartBugs Log/LogFile deps are parameterless
                    rendered = ", ".join(self._render_ctor_arg(a, "", dep_names) for a in args)
                    deploys.append(f"_depbc_{name} = bytes.concat(_depbc_{name}, abi.encode({rendered}));")
                deploys.append(f"address _depaddr_{name};")
                deploys.append("vm.prank(deployer_address);")
                deploys.append(f"assembly {{ _depaddr_{name} := create(0, add(_depbc_{name}, 0x20), mload(_depbc_{name})) }}")
                deploys.append(f'require(_depaddr_{name} != address(0), "dep deploy failed: {cname}");')
                deploys.append(f'vm.label(_depaddr_{name}, "{cname}");')
            else:
                rendered = ", ".join(self._render_ctor_arg(a, "", dep_names) for a in args)
                deploys.append("vm.prank(deployer_address);")
                deploys.append(f"address _depaddr_{name} = address(new {cname}({rendered}));")
                deploys.append(f'vm.label(_depaddr_{name}, "{cname}");')

        calls: list[str] = []
        for sc in self.setup_calls:
            fn = sc.get("fn")
            if not fn:
                continue
            raw_args = sc.get("args") or []
            arg_types = self._select_overload(fn, len(raw_args))
            if not arg_types and raw_args:  # fn not in ABI — infer (dep alias → address)
                arg_types = ["address" if str(a).strip() in dep_names else "uint256" for a in raw_args]
            rendered = [
                f"_depaddr_{str(a).strip()}" if str(a).strip() in dep_names
                else self._normalize_arg(a, arg_types[j] if j < len(arg_types) else "")
                for j, a in enumerate(raw_args)
            ]
            sig = f"{fn}({','.join(arg_types)})"
            argpart = (", " + ", ".join(rendered)) if rendered else ""
            calls.append("{")
            calls.append("    vm.prank(deployer_address);")
            calls.append(f'    bytes memory _sucd = abi.encodeWithSignature("{sig}"{argpart});')
            calls.append("    (bool _suok,) = target_address.call(_sucd);")
            calls.append(f'    require(_suok, "setup_call failed: {fn}");')
            calls.append("}")

        return "\n        ".join(deploys), "\n        ".join(calls)

    def _build_reentrancy_test(self, fuzz_input) -> str:
        """Build a test using the unified template (inline.sol.tpl).

        If fuzz_input.calls contains an "atk.setReentrantCall" entry, the unified
        Attacker is configured for re-entry.  Otherwise (non-reentrancy strategies,
        or reentrancy probe without explicit setup) the attacker is deployed but not
        configured (Mode.NONE) — calls are rendered directly.
        """
        setup_args: dict | None = None
        setup_idx: int = 0
        attack_calls: list[tuple[int, list]] = []  # (original_idx, call)
        for orig_idx, call in enumerate(fuzz_input.calls):
            if call[0] == "atk.setReentrantCall" and len(call) > 1 and isinstance(call[1], dict):
                setup_args = call[1]
                setup_idx = orig_idx
            else:
                attack_calls.append((orig_idx, call))

        if setup_args is not None:
            # The reentry-split path bypasses _build_calls_code, so initialize the
            # $ret chaining scratch here too (computed over the FULL calls list).
            self._referenced_rets = self._referenced_ret_indices(fuzz_input.calls)
            self._bound_rets = set()
            reentrant_func: str = setup_args.get("reentrant_func", "")
            reentrant_args_raw: list = list(setup_args.get("reentrant_args", []))
            # Clamp to [1, MAX_REENTRY_COUNT] — the single chokepoint that bounds
            # re-entry depth no matter which generator produced the value.
            max_count: int = max(1, min(MAX_REENTRY_COUNT, int(setup_args.get("max_count", 3))))

            setup_lines: list[str] = self._reentry_setup_lines(reentrant_func, reentrant_args_raw, max_count, idx=setup_idx)
            for orig_idx, call in attack_calls:
                setup_lines.extend(self._render_sequence_call(call, orig_idx))
            calls_code = "\n        ".join(setup_lines)
        else:
            calls_code = self._build_calls_code(fuzz_input.calls)

        if self._mode == "fork":
            # Wrap raw hex addresses through `address(uint160(...))` so solc
            # skips its EIP-55 checksum validation (dataset stores lowercased
            # hex; checksumming per-contract is unnecessary noise).
            t_addr  = f"address(uint160({int(self.fork.target_address, 16)}))"
            ext_ifaces, ext_consts = self._render_external_decls()
            # When a per-sample full template is set, the external decls are baked
            # into it and these kwargs are simply ignored (substitute drops keys the
            # template lacks). Otherwise they fill the built-in fork.sol.tpl holes.
            return self._load_setup_template().substitute(
                contract_name=self.contract_name,
                interface_decl=_abi_to_interface(self._abi, self.contract_name),
                external_interfaces=ext_ifaces,
                external_consts=ext_consts,
                target_address=t_addr,
                chain=self.fork.chain,
                fork_block=self.fork.fork_block,
                calls_code=calls_code,
                initial_balance=self.initial_balance_native,
            )

        modern_args, modern_value, legacy_concat, legacy_value = self._constructor_render()
        dep_deploys, dep_setup_calls = self._dep_setup_render()

        # Inline/legacy custom-template escape hatch (mirrors the fork path): when a
        # per-sample full template is declared (extend.setup_template) the author owns
        # the whole file — deploying the target + deps and exposing declared external
        # vars themselves. We provide the union of inline holes (+ rendered external
        # decls) and safe_substitute so a template references only what it needs.
        if self.setup_template:
            p = Path(self.setup_template)
            if not p.is_file():
                p = _REPO_ROOT / self.setup_template
            if p.is_file():
                ext_ifaces, ext_consts = self._render_external_decls()
                return Template(p.read_text()).safe_substitute(
                    contract_name=self.contract_name,
                    interface_decl=_abi_to_interface(self._abi, self.contract_name),
                    external_interfaces=ext_ifaces,
                    external_consts=ext_consts,
                    ctor_args=modern_args,
                    ctor_value=modern_value,
                    ctor_args_concat=legacy_concat,
                    ctor_value_create=legacy_value,
                    dep_deploys=dep_deploys,
                    dep_setup_calls=dep_setup_calls,
                    calls_code=calls_code,
                    initial_balance=self.initial_balance_native,
                )
            logger.warning(
                "inline setup_template %r not found — using built-in inline template",
                self.setup_template,
            )

        if self._mode == "legacy":
            return _load_template("inline_legacy.sol.tpl").substitute(
                contract_name=self.contract_name,
                interface_decl=_abi_to_interface(self._abi, self.contract_name),
                ctor_args_concat=legacy_concat,
                ctor_value_create=legacy_value,
                dep_deploys=dep_deploys,
                dep_setup_calls=dep_setup_calls,
                calls_code=calls_code,
                initial_balance=self.initial_balance_native,
            )

        return _load_template("inline.sol.tpl").substitute(
            contract_name=self.contract_name,
            ctor_args=modern_args,
            ctor_value=modern_value,
            dep_deploys=dep_deploys,
            dep_setup_calls=dep_setup_calls,
            calls_code=calls_code,
            initial_balance=self.initial_balance_native,
        )

    def _load_setup_template(self) -> Template:
        """Template for the fork harness. A per-sample full template (the user's
        'full file per sample' — interfaces + address constants + any hand-added
        mocks baked in) when `setup_template` is set and resolvable; otherwise the
        built-in fork.sol.tpl (external decls injected at runtime). The path is
        tried as-is (absolute / cwd) then relative to the repo root."""
        if self.setup_template:
            p = Path(self.setup_template)
            if not p.is_file():
                p = _REPO_ROOT / self.setup_template
            if p.is_file():
                return Template(p.read_text())
            logger.warning(
                "setup_template %r not found — falling back to built-in fork.sol.tpl",
                self.setup_template,
            )
        return _load_template("fork.sol.tpl")

    def _render_external_decls(self) -> tuple[str, str]:
        """Render (interface declarations, address-constant declarations) for the
        declared external contracts. Both empty in target-only mode. Used to fill
        the built-in fork.sol.tpl holes at runtime AND by gen_setup_template.py to
        bake the decls into a per-sample full template."""
        if not self._external:
            return "", ""
        iface_blocks: list[str] = []
        const_lines: list[str] = []
        seen_iface: set[str] = set()
        for var, rec in self._external.items():
            iface = rec["interface"]
            # Data-only entries (no interface) emit just the address constant.
            if iface and iface not in seen_iface:
                seen_iface.add(iface)
                iface_blocks.append(_render_interface(iface, rec["abi"]))
            addr = rec.get("address")
            if addr:
                s = str(addr).strip()
                try:
                    dec = int(s, 16) if s.lower().startswith("0x") else int(s)
                except ValueError:
                    logger.warning("external %r has unparseable address %r — skipped", var, addr)
                    continue
                const_lines.append(f"address constant {var} = address(uint160({dec}));")
        return "\n".join(iface_blocks), "\n".join(const_lines)

    def _postprocess_result(self, result: FuzzResult, strategy: str) -> None:
        """Single source of truth for bug detection: any BUG_SIGNAL line → bug_signal_found.

        Templates emit console.log("BUG_SIGNAL: <name>") when a balance invariant is
        violated instead of reverting. Reward-threshold heuristics are no longer
        consulted — a bug fires iff the harness asserts one.

        Bug *reward* is gated separately by exploit-path novelty: `new_exploit_path`
        is 1 only when this exploit's branch path is distinct (Jaccard<0.9) from
        every already-rewarded exploit, so padded reruns of the same attack earn
        nothing. `bug_signal_found` (detection) is unaffected by the gate.
        """
        signals = [
            str(line).strip() for line in result.decoded_logs
            if str(line).strip().startswith("BUG_SIGNAL:")
        ]
        if not signals:
            return

        result.bug_signal_found = True
        # Structured parse of each signal line (heuristic asset/token_address or value
        # fields) for EDA and the future graded reward (T2 reads `amount`). Detection
        # (bug_signal_found) stays a plain OR over BUG_SIGNAL lines — unchanged.
        result.bug_signals = [self._parse_bug_signal(s) for s in signals]
        # Precision flag: a tier=high signal (attacker_profit / target_loss) is a proved
        # net profit/loss — surfaces as `signal=High` in the LLM history. Heuristic-only
        # runs (suspicious balance move, maybe a fair trade) leave this False.
        # bug_signal_found stays the recall flag (any BUG_SIGNAL line).
        result.high_bug_signal_found = any(s.get("tier") == "high" for s in result.bug_signals)
        # Label the run by strategy: reentrancy probe → reentrancy, else a generic drain.
        result.bug_type = "reentrancy" if strategy == "reentrancy_probe" else "drain"
        # new_exploit_path is a per-RUN 0/1 (path-novelty gate), NOT len(signals):
        # several distinct BUG_SIGNAL lines in one run still bank one exploit path.
        result.new_exploit_path, result.bug_path_dup_of = self._score_bug_novelty(
            result.bc_branches_this_run)

    @staticmethod
    def _parse_bug_signal(line: str) -> dict:
        """Parse one BUG_SIGNAL line into a dict of its fields.

        Three shapes (emitted by Harness.sol), sharing a generic k=v parser:
          native heuristic: BUG_SIGNAL: <name> tier=heuristic asset=<SYM> value=<wei>
          ERC20 heuristic:  BUG_SIGNAL: <name> tier=heuristic asset=<SYM> token_address=<addr> amount=<raw>
          value verdict:    BUG_SIGNAL: <name> tier=high total_asset=<count> target_asset=<SYM> value=<wei>
        `asset`/`target_asset` are currency SYMBOLS (native symbol, ERC20 symbol() or
        "UnknownERC20Token", or the wrapped-native numéraire). `token_address` is present
        only for an ERC20 heuristic. The magnitude key encodes the unit: `value=` = native
        numéraire wei (18-dec); `amount=` = ERC20 raw base-units (decimals unknown). Both
        land in the single `amount` field here (display/reward pick scaling via
        `token_address`), so a legacy `amount=` native line still parses. The leading token
        after the prefix is the signal name; the rest are k=v pairs. Integer fields default
        to 0, the rest to "". Tolerant of a bare name-only line so the parser never raises.
        """
        body = line.split("BUG_SIGNAL:", 1)[-1].strip()
        parts = body.split()
        out: dict = {"name": parts[0] if parts else "", "tier": "", "asset": "",
                     "token_address": "", "total_asset": 0, "target_asset": "", "amount": 0}
        for tok in parts[1:]:
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            if k == "value":       # native numéraire magnitude → shared `amount` field
                k = "amount"
            if k in ("amount", "total_asset"):
                try:
                    out[k] = int(v)
                except ValueError:
                    out[k] = 0
            elif k in out:
                out[k] = v
        return out

    def _score_bug_novelty(self, branches: frozenset) -> tuple[int, int]:
        """Score an exploit path's novelty.

        Returns (1, -1) for a novel exploit path (and banks it); (0, i) when the
        path duplicates already-rewarded path `i` (the most similar one, the
        reason it was rejected). Global (not per-bug-class): the only thing that
        matters is whether this attack path was already rewarded. First exploit
        always scores (empty memory ⇒ distinct).
        """
        from .paths import EXPLOIT_PATH_SIM_THRESHOLD, jaccard

        best_i, best_sim = -1, -1.0
        for i, w in enumerate(self._rewarded_exploit_paths):
            s = jaccard(branches, w)
            if s > best_sim:
                best_sim, best_i = s, i
        if best_i == -1 or best_sim < EXPLOIT_PATH_SIM_THRESHOLD:
            self._rewarded_exploit_paths.append(branches)
            return 1, -1
        return 0, best_i

    def _call_to_solidity(self, call: list, idx: int = 0) -> str:
        """Convert a [head, [args], value_wei?] call to Solidity.

        Call format:
          ["fn", [args]]            → target.fn(args);
          ["fn", [args], value]     → target.fn{value: V}(args);
          ["WETH.deposit", [], v]   → IWETH9(WETH).deposit{value: v}();   (external)

        When a later call references this one's single return via `$ret<idx>`, the
        call is rendered as a function-scope `<type> _ret<idx> = <call>;` assignment
        (no try/catch — a revert breaks the chain, same as a hand-written PoC).
        Otherwise it keeps the revert-tolerant try/catch wrapper.

        idx is the call's position in the original calls list and is embedded in
        console.log output so decoded_logs can be mapped back to the call sequence.
        """
        head = call[0]
        args = call[1] if len(call) > 1 and call[1] is not None else []
        raw_value = call[2] if len(call) > 2 else 0
        try:
            value = int(str(raw_value), 0) if raw_value else 0
        except (ValueError, TypeError):
            value = 0

        # Receiver + signature maps: external "<var>.<method>" vs a bare target fn.
        if "." in head and head.split(".", 1)[0] in self._external_callable:
            var, method = head.split(".", 1)
            rec = self._external[var]
            receiver = f'{rec["interface"]}({var})'
            arg_types, out_types = self._resolve_signature(method, len(args), rec["types"], rec["outputs"])
            is_payable = method in rec["payable"]
            label = f"{var}.{method}"
        else:
            method = head
            receiver = "target"
            arg_types, out_types = self._resolve_signature(
                method, len(args), self._abi_types, self._abi_outputs
            )
            is_payable = method in self._abi_payable
            label = method

        setup_lines, arg_exprs = self._render_args(args, arg_types, idx)
        args_str = ", ".join(arg_exprs)
        if value and not is_payable:
            logger.warning("LLM sent value_wei=%d to non-payable %s — ignored", value, label)
        value_part = f"{{value: {value}}}" if is_payable and value else ""
        setup_block = "\n        ".join(setup_lines) + ("\n        " if setup_lines else "")
        call_expr = f"{receiver}.{method}{value_part}({args_str})"

        if idx in self._referenced_rets and len(out_types) == 1:
            self._bound_rets.add(idx)
            decl = self._ret_decl_type(out_types[0])
            return f"{setup_block}{decl} _ret{idx} = {call_expr};"
        return (
            f"{setup_block}"
            f"try {call_expr} {{}}\n"
            f'        catch Error(string memory _r) {{ console.log("[{idx}] {label} fail:", _r); }}\n'
            f'        catch (bytes memory) {{ console.log("[{idx}] {label} fail: low-level"); }}'
        )

    def _render_args(self, args: list, arg_types: list[str], idx: int) -> tuple[list[str], list[str]]:
        """Render arg expressions plus any required Solidity setup lines.

        Returns `(setup_lines, arg_exprs)`. Most args produce zero setup lines
        and a single inline expression. Array-typed args (`T[]` / `T[N]`) cannot
        be expressed as inline Solidity literals for dynamic sizes — solc infers
        `T[K] memory` from an inline `[a, b]`, which doesn't unify with `T[]`
        parameters. So for any array slot we declare a memory temp:

            T[] memory _arr_<callIdx>_<slot> = new T[](K);
            _arr_<callIdx>_<slot>[0] = ...; _arr_<callIdx>_<slot>[1] = ...;

        and pass the var by name. Works uniformly for dynamic and fixed-size
        arrays, and the temp-var name is unique per (call, slot) so multiple
        array args in the same sequence don't collide.
        """
        setup_lines: list[str] = []
        arg_exprs: list[str] = []
        for slot, arg in enumerate(args):
            sol_type = arg_types[slot] if slot < len(arg_types) else ""
            arr = self._parse_array_type(sol_type) if sol_type else None
            if arr is None:
                arg_exprs.append(self._arg_expr(arg, sol_type))
                continue
            elem_type, fixed_size = arr
            elements = list(arg) if isinstance(arg, list) else []
            if fixed_size is not None:
                # Pad / trim so the temp's length matches the declared size.
                if len(elements) > fixed_size:
                    elements = elements[:fixed_size]
                while len(elements) < fixed_size:
                    elements.append(self._default_for_type(elem_type))
                n = fixed_size
                var = f"_arr_{idx}_{slot}"
                setup_lines.append(f"{elem_type}[{n}] memory {var};")
            else:
                n = len(elements)
                var = f"_arr_{idx}_{slot}"
                setup_lines.append(f"{elem_type}[] memory {var} = new {elem_type}[]({n});")
            for i, el in enumerate(elements):
                setup_lines.append(f"{var}[{i}] = {self._arg_expr(el, elem_type)};")
            arg_exprs.append(var)
        return setup_lines, arg_exprs

    def _arg_expr(self, arg, sol_type: str = "") -> str:
        """Render one scalar arg, resolving the special tokens that the external /
        chaining mechanism introduces before falling back to the type-aware
        literal coercion in _normalize_arg:

          - a declared external var name  → the Solidity `address constant <var>`
          - "$ret<idx>"                   → the bound `_ret<idx>` local (or 0 if the
                                            referenced call produced no usable return)
          - "max"                         → type(uint256).max          (non-string slots)
          - "now" / "block.timestamp"     → block.timestamp            (non-string slots)
        """
        if isinstance(arg, str):
            if arg in self._external_consts:
                return arg
            if arg.startswith("$ret"):
                ref = arg[4:]
                try:
                    base = int(ref.split("_")[0])
                except ValueError:
                    base = -1
                if base in self._bound_rets:
                    return f"_ret{ref}"
                # Unbound $ret (self-reference or a producer with no usable return):
                # substitute a TYPE-CORRECT default, not a bare `0` — solc rejects
                # `0` in an address slot (Pledge pledgeU($ret0,…) with an address
                # arg0 → "invalid conversion int_const→address"). Route the default
                # through _normalize_arg so every family renders validly.
                logger.warning("arg %r references an unbound return — substituting default for %r", arg, sol_type or "?")
                return self._normalize_arg(self._default_for_type(sol_type), sol_type)
            if sol_type != "string":
                if arg == "max":
                    return "type(uint256).max"
                if arg in ("now", "block.timestamp"):
                    return "block.timestamp"
        return self._normalize_arg(arg, sol_type)

    @staticmethod
    def _parse_array_type(sol_type: str) -> tuple[str, int | None] | None:
        """Split `T[]` / `T[N]` into (element_type, size). size=None for dynamic.
        Returns None if `sol_type` isn't an array type."""
        t = (sol_type or "").strip()
        if not (t.endswith("]") and "[" in t):
            return None
        bracket = t.rindex("[")
        size_str = t[bracket + 1:-1]
        if size_str == "":
            return (t[:bracket], None)
        if size_str.isdigit():
            return (t[:bracket], int(size_str))
        return None  # unrecognized — fall through to scalar handler

    @staticmethod
    def _default_for_type(sol_type: str):
        """Zero-default literal for the given Solidity type. Used to pad fixed
        arrays when the LLM gave fewer elements than the signature requires.
        The return value is fed back through `_normalize_arg`, so we emit it in
        the same JSON-ish shape the LLM would have produced."""
        t = (sol_type or "").strip()
        if t == "address" or t.startswith("uint") or t.startswith("bytes"):
            return "0x0"
        if t.startswith("int"):
            return "0"
        if t == "bool":
            return "false"
        if t == "string":
            return ""
        return "0x0"

    @staticmethod
    def _normalize_address(addr: str) -> str:
        """Return a Solidity-safe address expression for use inside address(...).

        Converts hex to decimal integer — Solidity applies EIP-55 checksum validation
        to ANY 40-hex-digit 0x literal regardless of surrounding cast, but never
        validates decimal literals.  address(uint160(1234...)) compiles cleanly.
        """
        addr = str(addr).strip()
        if addr.startswith(("0x", "0X")):
            try:
                return f"uint160({int(addr, 16) & ((1 << 160) - 1)})"
            except ValueError:
                pass
        # Plain integer — mask to uint160 range
        try:
            return f"uint160({int(addr) & ((1 << 160) - 1)})"
        except ValueError:
            pass
        return "uint160(0)"

    # Named address aliases that are Solidity variables already in scope in every
    # generated test.  When one of these is used as an address-type argument we
    # emit it verbatim (no cast needed).
    # Includes the fork-only var target_address so sentinel calldata can reference
    # it; in non-fork modes those simply aren't emitted. deployer_address is a
    # valid in-scope var (setUp pranks through it) and is a member of the baselines'
    # inline address pool (fuzzer.arg_sampling.build_address_pool) so RLFuzz/MADFuzz
    # can target owner-only paths; it is dropped from the fork pool.
    _ADDR_ALIASES: frozenset[str] = frozenset({
        "attacker_address", "target_address", "deployer_address",
    })

    # Per-iteration count of Tier-2 normalization fallbacks (an arg that could not
    # be coerced to its declared type → replaced by a compile-safe default). Reset
    # at the top of every _build_calls_code; incremented in _norm_default. A
    # non-zero value flags a Tier-1 generator bug or unconstrained-LLM drift.
    _norm_fallback_count: int = 0

    @staticmethod
    def _sol_str_literal(text: str) -> str:
        """Render `text` as a Solidity-valid double-quoted string literal.

        NOTE: do NOT use json.dumps here — Solidity's string-literal grammar
        rejects the `\\b` (0x08) and `\\f` (0x0c) escapes that json.dumps emits,
        so a fuzzer-generated string containing a backspace/form-feed byte would
        fail to COMPILE (verified against solc). Instead emit only escapes solc
        accepts: printable ASCII verbatim, `\\"`/`\\\\` for quote/backslash, `\\xNN`
        for any other byte ≤0x7f (valid single-byte UTF-8), and `\\uNNNN` for code
        points ≥0x80 (inserted as UTF-8). Any input thus renders compilably.
        """
        out = ['"']
        for ch in text:
            o = ord(ch)
            if ch == '"':
                out.append('\\"')
            elif ch == '\\':
                out.append('\\\\')
            elif 0x20 <= o <= 0x7e:
                out.append(ch)
            elif o <= 0x7f:
                out.append(f'\\x{o:02x}')
            else:
                out.append(f'\\u{o:04x}')
        out.append('"')
        return ''.join(out)

    @staticmethod
    def _norm_default(arg, sol_type: str) -> str:
        """Tier-2 last resort: a value could not be coerced to `sol_type`. Emit a
        compile-safe `_default_for_type` literal and log a WARNING — the warning
        (and the per-iteration `_norm_fallback_count`) is the signal that a Tier-1
        generator or an unconstrained LLM produced something wrong. NEVER return a
        value verbatim on failure; that is the compile-error footgun this replaces.
        """
        logger.warning("normalize fallback: arg=%r type=%r → default", arg, sol_type)
        FoundryFuzzer._norm_fallback_count += 1
        # _default_for_type emits a coercible literal (0x0 / 0 / false / ""), so
        # this single re-entry always terminates.
        return FoundryFuzzer._normalize_arg(
            FoundryFuzzer._default_for_type(sol_type), sol_type
        )

    @staticmethod
    def _normalize_arg(arg, sol_type: str = "") -> str:
        """Render a function argument as a valid Solidity literal for its declared
        Solidity type (Tier-2 defense-in-depth — the single render chokepoint).

        Dispatches on the type family and ATTEMPTS coercion; on any coercion
        failure it degrades to a compile-safe default + WARNING (via _norm_default)
        rather than returning the value verbatim. Widths are parsed only through
        `arg_sampling.type_width` (the single source shared with Tier-1 and GBNF).

          address        → alias var verbatim, else address(uint160(decimal))
          bool           → true/false
          string         → escaped Solidity literal (_sol_str_literal; hex → UTF-8)
          bytes (dyn)    → hex"…" (0x hex) or bytes("…") (plain)
          uintN          → decimal, masked to N bits (folds address-shaped hex too)
          intN           → decimal, clamped to the signed range
          bytesN         → 0x + exactly 2N hex (pad/truncate)
          alias in a numeric/bytesN slot → cast (uint160(alias) / bytesN(…))
          empty / unknown type → conservative verbatim (already-valid literal)

        Symbolic tokens ($ret/max/now) are resolved upstream in `_arg_expr`, so
        this method only ever sees literal values.
        """
        from .arg_sampling import type_width, parse_int, bytesN_hex

        s = str(arg)
        st = (sol_type or "").strip()

        if st in ("address", "address payable"):
            if s in FoundryFuzzer._ADDR_ALIASES:
                return s
            raw = s[2:] if s.lower().startswith("0x") else s
            try:
                return f"address(uint160({int(raw, 16) & ((1 << 160) - 1)}))"
            except ValueError:
                try:
                    return f"address(uint160({int(raw) & ((1 << 160) - 1)}))"
                except ValueError:
                    return "address(uint160(0))"
        if st == "bool":
            if isinstance(arg, bool):
                return "true" if arg else "false"
            return "true" if s.lower() in ("true", "1") else "false"
        if st == "string":
            # LLMs often emit hex-shaped strings for string slots — coerce to a valid literal.
            if s.lower().startswith("0x"):
                try:
                    decoded = bytes.fromhex(s[2:]).decode("utf-8", errors="ignore").rstrip("\x00")
                    return FoundryFuzzer._sol_str_literal(decoded) if decoded else '""'
                except ValueError:
                    return '""'
            return FoundryFuzzer._sol_str_literal(s)
        if st == "bytes":
            # Dynamic `bytes` cannot use raw `0x...` as an arg literal — use `hex"..."`.
            if s.lower().startswith("0x"):
                hex_body = s[2:]
                if not all(c in "0123456789abcdefABCDEF" for c in hex_body):
                    return FoundryFuzzer._norm_default(arg, sol_type)
                if len(hex_body) % 2:
                    hex_body = "0" + hex_body  # pad to even
                return f'hex"{hex_body}"'
            return f"bytes({FoundryFuzzer._sol_str_literal(s)})"

        # An address ALIAS used in a NUMERIC / bytesN slot — e.g. a PoC that writes the
        # attacker's address into a `uint256` storage slot (arbitrary-write → become
        # owner). The alias is only valid bare in an `address` context; elsewhere it
        # must be cast. attacker_address is now a runtime-deployed CONTRACT, so a
        # hardcoded literal can't express it — the cast resolves at render time.
        if s in FoundryFuzzer._ADDR_ALIASES:
            if type_width(st) is not None:
                return f"uint160({s})"                      # widens to any uint≥160
            m = re.fullmatch(r"bytes(\d+)", st)
            if m:
                n = int(m.group(1))
                return f"bytes{n}(uint{n * 8}(uint160({s})))"
            # alias in some other/unknown slot — emit bare (valid iff address slot).
            return s

        # uintN / intN — mask (uint) / clamp (int), always decimalize any numeric
        # hex (folds the old len==42 address-shaped special case for every width).
        w = type_width(st)
        if w is not None:
            kind, bits = w
            try:
                n = parse_int(arg)
            except (ValueError, TypeError):
                return FoundryFuzzer._norm_default(arg, sol_type)
            if kind == "uint":
                return str(n & ((1 << bits) - 1))
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
            return str(max(lo, min(hi, n)))

        # bytesN — pad/truncate to exactly 2N hex chars. Raw short hex (0x1b) or a
        # bare int_const otherwise fails the bytesN literal type check.
        m = re.fullmatch(r"bytes(\d+)", st)
        if m:
            n = int(m.group(1))
            body = s[2:] if s.lower().startswith("0x") else s
            if not all(c in "0123456789abcdefABCDEF" for c in body):
                return FoundryFuzzer._norm_default(arg, sol_type)
            return bytesN_hex(s, n)

        # Empty / unknown type — no declared type to coerce against. The value
        # already came from a width-aware Tier-1 generator (or was resolved
        # upstream); emit verbatim.
        return s

    def _parse_result(
        self, stdout: str, stderr: str, call_names: list[str] | None = None
    ) -> FuzzResult:
        """Parse forge test JSON output into a FuzzResult.

        If forge produced no test results (empty JSON), this usually means the
        test file failed to compile. We surface that as `forge_status="CompileError"`
        instead of silently defaulting to "Success", and stash the first error
        line from stderr in `raw_reason` so it's visible in the run log.

        A separate case looks similar but is NOT a compile error: a transient
        fork-RPC failure. The public archive RPC behind `vm.createSelectFork` can
        reject a request either at createSelectFork SETUP or on a MID-EXECUTION
        `eth_getStorageAt` (5xx / timeout / rate-limit). Either way the
        `--debug --dump` pass aborts with no arena — forge prints "debug arena is
        empty" (the symptom, on stderr) while the true cause is a `sharedbackend`
        error line on stdout ("Failed to send/recv storage … HTTP error 5xx").
        The contract built fine; the harness just never executed (or didn't finish)
        the fuzzed calls. `_detect_fork_rpc_failure` scans BOTH streams for that
        signal and we label it `forge_status="SetupFailed"` /
        `revert_reason="fork_setup_failed"` (stashing the real cause line in
        `raw_reason`) so it stops masquerading as a compile error — and so
        `run_input` can RETRY it (the failure is transient).
        """
        result = FuzzResult()

        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            data = {}

        found_test_data = False
        for test_suite in data.values():
            for test_name, test_data in test_suite.get("test_results", {}).items():
                found_test_data = True
                result.gas_used = test_data.get("kind", {}).get("Unit", {}).get("gas", 0)
                result.forge_status = test_data.get("status", "Success")
                result.reverted = result.forge_status == "Failure"
                result.trace = self._format_trace(test_data.get("traces", []))
                result.decoded_logs = test_data.get("decoded_logs", [])

                if result.reverted:
                    reason = test_data.get("reason", "")
                    result.raw_reason = reason
                    result.revert_reason = self._classify_revert(reason)

        # A fork-RPC failure (createSelectFork setup OR a mid-execution storage
        # fetch that 5xx'd / timed out) makes the coverage dump print "debug arena
        # is empty" and yields no trace. Depending on where it failed, forge may or
        # may not still emit a setUp()/test JSON entry, so we scan BOTH streams for
        # the signal directly and let it take priority over the loop's
        # classification. This is NOT a compile error — the contract built fine;
        # the harness just never ran (or never finished) the fuzzed calls. The real
        # cause (a `sharedbackend`/HTTP-error line) goes into raw_reason.
        fork_cause = _detect_fork_rpc_failure(stdout, stderr)
        if fork_cause is not None:
            result.forge_status = "SetupFailed"
            result.reverted = True
            result.raw_reason = fork_cause
            result.revert_reason = "fork_setup_failed"
        elif not found_test_data:
            # Empty JSON with no arena signature → forge skipped the test file
            # (almost always a genuine compile error; stderr carries "Compilation
            # failed"). Surface that explicitly instead of looking like a pass.
            result.forge_status = "CompileError"
            result.reverted = True
            err_line = next(
                (l.strip() for l in stderr.split("\n")
                 if l.strip().startswith("Error") or "error:" in l.lower()),
                stderr.strip().split("\n")[0] if stderr.strip() else "",
            )
            result.raw_reason = err_line[:200]
            result.revert_reason = "compile_error"

        # new_branches and coverage are filled in by _update_coverage_from_dump
        # after this method returns.
        return result

    def _format_trace(self, raw_traces: list) -> str:
        """Build a human-readable indented call tree from forge's trace arena.

        Only the 'Execution' trace is shown (not 'Deployment').
        Output example:
          CALL withdrawAll() [gas:11622] → Revert
            CALL transfer() [gas:800] → ok
        """
        lines: list[str] = []

        for entry in raw_traces:
            if not (isinstance(entry, list) and len(entry) == 2):
                continue
            kind, arena_obj = entry[0], entry[1]
            if kind != "Execution":
                continue
            arena = arena_obj.get("arena", []) if isinstance(arena_obj, dict) else []
            if not arena:
                continue

            def walk(idx: int, depth: int) -> None:
                if idx >= len(arena):
                    return
                node = arena[idx]
                t = node.get("trace", {})
                decoded = t.get("decoded") or {}
                func = decoded.get("func_name") or t.get("data", "")[:10] or "call"
                status = t.get("status", "?")
                gas = t.get("gas_used", 0)
                indent = "  " * depth
                lines.append(f"{indent}{t.get('kind','CALL')} {func} [gas:{gas}] → {status}")
                for child in node.get("children", []):
                    walk(child, depth + 1)

            walk(0, 0)

        return "\n".join(lines) if lines else ""

    def _classify_revert(self, reason: str) -> str:
        """Map the raw forge 'reason' string to a canonical revert category.

        Categories (in match priority order):
          arithmetic_overflow  — Solidity 0.8 panic / explicit overflow/underflow
          assertion_failed     — forge-std assert*, Solidity assert(), or require with
                                 "assertion"/"assert" in the message
          out_of_gas           — execution ran out of gas
          custom_error         — 4-byte selector (0x…)
          reverted             — everything else: require() without a message,
                                 EvmError: Revert, unknown strings

        The default is "reverted" (not "assertion_failed") so that generic EVM
        reverts (e.g. "EvmError: Revert" from a failed require(s)) do not
        incorrectly set bug_signal_found = True. Strategy-specific bugs that use
        custom assertLe messages are promoted to bug_signal_found by _postprocess_result.
        """
        if not reason:
            return "reverted"
        reason_lower = reason.lower()
        if "overflow" in reason_lower or "underflow" in reason_lower or "panic" in reason_lower:
            return "arithmetic_overflow"
        if "assertion" in reason_lower or "assert" in reason_lower:
            return "assertion_failed"
        if "evmerror" in reason_lower:
            return "reverted"
        if "gas" in reason_lower:
            return "out_of_gas"
        if reason.startswith("0x"):
            return "custom_error"
        return "reverted"
