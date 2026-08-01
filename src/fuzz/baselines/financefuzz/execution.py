"""Forge execution backend for the FinanceFuzz competitor.

Reuses our project's forge harness *only* as the EVM execution engine (the one
permitted reuse). `FinanceExecutor` subclasses `FoundryFuzzer` so it inherits the
compile path, the call renderer (`_build_calls_code` / reentrancy sentinel handling),
constructor/dep deploy rendering, the forge invocation, coverage parsing and
console-log decoding — but overrides `_build_test` to render `finance.sol.tpl`, which
runs the sequence T and every detector-flavored variant T′ from a single snapshot and
emits a balance fingerprint per block.

One forge invocation per individual evaluates T + all variants (snapshot/revert),
keeping the per-individual cost comparable to the other baselines.
"""

from __future__ import annotations

import subprocess

from ...fuzzer.foundry import (
    MAX_REENTRY_COUNT,
    FoundryFuzzer,
    FuzzResult,
    _abi_to_interface,
    _load_template,
    _write_harness_file,
    logger,
)
from ...llm.agent import FuzzInput
from .generator import ADDRESS_ARG_POOL
from .oracle import Variant

# Differential test template per target mode (modern >=0.8 inline / legacy <0.8 inline
# via vm.getCode / on-chain fork). All three share the same blocks/fingerprint body.
_FINANCE_TPLS = {
    "modern": "finance.sol.tpl",
    "legacy": "finance_legacy.sol.tpl",
    "fork": "finance_fork.sol.tpl",
}


def is_erc20(abi: list[dict]) -> bool:
    """True if the ABI exposes the ERC20 core read/transfer surface."""
    names = {i.get("name") for i in abi if i.get("type") == "function"}
    return {"balanceOf", "transfer", "totalSupply"}.issubset(names)


class FinanceExecutor(FoundryFuzzer):
    """FoundryFuzzer specialized to render + run the FinanceFuzz differential test."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ff_token_expr = "target_address" if is_erc20(self._abi) else "address(0)"
        self._ff_T: list = []
        self._ff_variants: list[Variant] = []

    # ── Public API ──────────────────────────────────────────────────────────────

    def run_individual(self, calls: list, variants: list[Variant], *, debug: bool = False):
        """Evaluate one individual (GA hot path): json-only forge run (no coverage
        dump — the differential test runs T + ≤4 variants, and full opcode tracing
        of that is both slow and prone to multi-GB dumps on re-entrant loops). Returns
        a FuzzResult with the FinanceFuzz fingerprints/blocks in `decoded_logs`."""
        self._ff_T = calls
        self._ff_variants = variants
        return self._run_json_only(calls, debug=debug)

    def run_coverage(self, calls: list):
        """Coverage pass for ONE sequence (T only, no variants) using the parent's
        full --debug --dump path so `measure_coverage()` reflects real branch
        coverage. Called by the runner on the best individual at the end."""
        self._ff_T = calls
        self._ff_variants = []
        return self.run_input(FuzzInput(calls=calls))

    def _run_json_only(self, calls: list, *, debug: bool = False) -> FuzzResult:
        test_src = self._build_test(FuzzInput(calls=calls))
        test_file = (self.foundry_project / "test" / "__sc_fuzz__.t.sol").resolve()
        _write_harness_file(test_file.parent)
        test_file.write_text(test_src)
        try:
            rel = test_file.relative_to(self.foundry_project)
        except ValueError:
            rel = test_file
        try:
            proc = subprocess.run(
                ["forge", "test", "--match-path", str(rel), "--json", "-vvv", "--allow-failure"],
                cwd=self.foundry_project, capture_output=True, text=True, timeout=120,
            )
            if debug and proc.stderr.strip():
                logger.debug("forge stderr:\n%s", proc.stderr[:1500])
            result = self._parse_result(proc.stdout, proc.stderr, [c[0] for c in calls])
            self._postprocess_result(result, "")
            return result
        except subprocess.TimeoutExpired:
            logger.warning("FinanceFuzz forge run timed out.")
            return FuzzResult(revert_reason="out_of_gas", reverted=True)
        finally:
            test_file.unlink(missing_ok=True)

    # ── Rendering ────────────────────────────────────────────────────────────────

    def _render_calls(self, calls: list) -> str:
        """Render a call-list to Solidity, honouring the atk.setReentrantCall
        sentinel (mirrors FoundryFuzzer._build_reentrancy_test's calls_code branch)."""
        setup_args = None
        setup_idx = 0
        attack: list[tuple[int, list]] = []
        for i, c in enumerate(calls):
            if c and c[0] == "atk.setReentrantCall" and len(c) > 1 and isinstance(c[1], dict):
                setup_args, setup_idx = c[1], i
            else:
                attack.append((i, c))

        self._referenced_rets = self._referenced_ret_indices(calls)
        self._bound_rets = set()

        if setup_args is not None:
            func = setup_args.get("reentrant_func", "")
            args = list(setup_args.get("reentrant_args", []))
            max_count = max(1, min(MAX_REENTRY_COUNT, int(setup_args.get("max_count", 3))))
            lines = self._reentry_setup_lines(func, args, max_count, idx=setup_idx)
            for oi, c in attack:
                lines.extend(self._render_sequence_call(c, oi))
            return "\n        ".join(lines)
        return self._build_calls_code(calls)

    def _variant_pre(self, v: Variant) -> str:
        """Solidity emitted before a variant's calls (warp / gasless etch)."""
        lines: list[str] = []
        if v.warp is not None:
            lines.append(f"vm.warp({int(v.warp)});")
        if v.gasless_recipient:
            # Etch a reverting recipient onto the attacker address so the target's
            # value transfers fail; an unchecked send still advances state.
            lines.append("vm.etch(attacker_address, type(FFRejectEther).runtimeCode);")
        return "\n        ".join(lines)

    def _t_block(self, calls: list) -> str:
        """Render the T block with a PER-CALL token-supply invariant, faithful to
        upstream TokenBalanceDetector (which prepares the detector before each tx and
        runs it after — `execution_trace_analysis.py:142-180`). For each call: capture
        the watched set's balances, run the single call, read just that call's Transfer
        events (`vm.getRecordedLogs()` clears its buffer per read) and emit one
        `FF_INV <preSum> <postSum>` over the call's changed accounts. Calls run
        sequentially with NO inter-call reverts, so `_ffEmit("T")` sees the true
        end-of-sequence state; only then do we revert to the pre-T snapshot for the
        variants. This replaces the old whole-sequence bracket, which false-positived
        on mintable ERC20s (a legit mint leaked into the diff)."""
        tok = self._ff_token_expr
        self._referenced_rets = self._referenced_ret_indices(calls)
        self._bound_rets = set()
        # Each block opens its own `{ }` scope so per-call temps (array-arg memory
        # temps `_arr_*`, bound-return locals `_ret*`) that key off the call index
        # can't collide with the identically-named temps rendered by sibling blocks
        # — all blocks share the single test_fuzz_input() function scope, and
        # without the brace they'd redeclare the same identifier (solc 2333).
        lines = [
            'console.log("FF_BLOCK T");',
            "{",
            "uint256[] memory _pre;",
        ]
        for idx, call in enumerate(calls):
            call_lines = self._render_sequence_call(call, idx)
            if not call_lines:
                continue
            lines.append(f"_pre = _ffBalances({tok}, _ffAccts);")
            lines.extend(call_lines)
            lines.append(f"_ffInvEmit({tok}, _ffAccts, _pre, vm.getRecordedLogs());")
        lines.append(f'_ffEmit("T", {tok}, _ffAccts);')
        lines.append("}")
        lines.append("vm.revertToState(_s0);")
        lines.append("_s0 = vm.snapshotState();")
        return "\n        ".join(lines)

    def _variant_block(self, tag: str, calls_code: str, *, pre: str = "") -> str:
        """Render one T′ block: restore snapshot, mark the block, run, fingerprint.

        The block body is wrapped in a `{ }` scope so its per-call temps (`_arr_*`,
        `_ret*`) don't collide with the T block's or another variant's — every block
        renders into the same function scope (see `_t_block`)."""
        pre_block = f"{pre}\n        " if pre else ""
        return (
            "vm.revertToState(_s0);\n        _s0 = vm.snapshotState();\n        "
            f'console.log("FF_BLOCK {tag}");\n        {{\n        '
            f"{pre_block}{calls_code}\n        "
            f'_ffEmit("{tag}", {self._ff_token_expr}, _ffAccts);\n        }}'
        )

    def _accounts_init(self) -> str:
        # Watched-account set for the fingerprint. Fork mode has no deployer (the
        # target is already on-chain), so it is omitted there.
        lines = [
            "_ffAccts.push(attacker_address);",
            "_ffAccts.push(target_address);",
        ]
        if self._mode != "fork":
            lines.append("_ffAccts.push(deployer_address);")
        for addr in ADDRESS_ARG_POOL:
            lines.append(f"_ffAccts.push(address(uint160({int(addr, 16)})));")
        return "\n        ".join(lines)

    def _build_test(self, fuzz_input, strategy: str = "") -> str:  # noqa: ARG002
        blocks = [self._t_block(self._ff_T)]
        for v in self._ff_variants:
            blocks.append(self._variant_block(v.tag, self._render_calls(v.calls), pre=self._variant_pre(v)))
        blocks_code = "\n\n        ".join(blocks)

        tpl = _load_template(_FINANCE_TPLS[self._mode])
        common = dict(
            contract_name=self.contract_name,
            ff_accounts_init=self._accounts_init(),
            ff_token=self._ff_token_expr,
            blocks=blocks_code,
            initial_balance=self.initial_balance_native,
        )

        if self._mode == "fork":
            ext_ifaces, ext_consts = self._render_external_decls()
            return tpl.substitute(
                **common,
                interface_decl=_abi_to_interface(self._abi, self.contract_name),
                external_interfaces=ext_ifaces,
                external_consts=ext_consts,
                target_address=f"address(uint160({int(self.fork.target_address, 16)}))",
                chain=self.fork.chain,
                fork_block=self.fork.fork_block,
            )

        modern_args, modern_value, legacy_concat, legacy_value = self._constructor_render()
        dep_deploys, dep_setup_calls = self._dep_setup_render()
        if self._mode == "legacy":
            return tpl.substitute(
                **common,
                interface_decl=_abi_to_interface(self._abi, self.contract_name),
                ctor_args_concat=legacy_concat,
                ctor_value_create=legacy_value,
                dep_deploys=dep_deploys,
                dep_setup_calls=dep_setup_calls,
            )
        # modern
        return tpl.substitute(
            **common,
            ctor_args=modern_args,
            ctor_value=modern_value,
            dep_deploys=dep_deploys,
            dep_setup_calls=dep_setup_calls,
        )
