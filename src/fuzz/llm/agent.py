"""LLM agent for generating semantically meaningful fuzz inputs.

Supports two backends, selected via LLMConfig.backend:

  "anthropic"   — Direct Anthropic API (requires ANTHROPIC_API_KEY).
  "claude-code" — Claude Agent SDK, which delegates to the local `claude`
                  CLI (requires `pip install claude-agent-sdk` and the
                  Claude Code CLI in PATH). No API key needed; uses the
                  CLI's existing auth.
"""

from __future__ import annotations

import logging
import re

from ..config import LLMConfig
from .backends import (
    LlamaTokenStats,
    TokenUsage,
    _AnthropicBackend,
    _ClaudeCodeBackend,
    _LLMBackend,
    _LlamaCppBackend,
)
from .prompts import SYSTEM_PROMPT as _SYSTEM_PROMPT
from .source_budget import (
    _truncate_prompt,
    apply_source_budget,
    extract_target_contract_source,
    format_abi_signatures,
    minify_solidity,
)

logger = logging.getLogger(__name__)

# Re-export surface: the backends, token-usage dataclasses, and source-budget
# helpers moved to sibling modules but are still imported as `fuzz.llm.agent.*`
# across the codebase. Listing them in __all__ marks the imports above as an
# intentional public re-export (not dead) for import * and linters alike.
__all__ = [
    "FuzzInput",
    "TokenUsage",
    "LlamaTokenStats",
    "_LLMClient",
    "_LLMBackend",
    "_AnthropicBackend",
    "_ClaudeCodeBackend",
    "_LlamaCppBackend",
    "minify_solidity",
    "format_abi_signatures",
    "extract_target_contract_source",
    "apply_source_budget",
    "_truncate_prompt",
]


# ── Data model ────────────────────────────────────────────────────────────────

class FuzzInput:
    """A single fuzz input: a sequence of contract calls.

    Reentrancy setup is encoded as a special call in the calls list:
      ["atk.setReentrantCall", {"reentrant_func": "fnName", "reentrant_args": [], "max_count": 3}, "0x0", "attacker_address"]
    reentrant_func is the *bare* function name on the target contract — the
    Solidity signature is built locally from the ABI's input types.  Unknown
    names fall back to a random ABI function with random args (see
    fuzzer/foundry.py::_reentry_setup_lines).
    All other calls follow the standard 4-element format:
      ["functionName", [arg1, arg2], value_wei, "caller_name"]

    Per-call value and caller live in the 3rd and 4th elements of each call entry.
    No top-level value/caller — those would be redundant since foundry.py executes
    each call with its own value/caller via vm.prank() and call{value:...}.
    """

    def __init__(
        self,
        calls: list[list],
        description: str = "",
        lineage: list[dict] | None = None,
    ):
        # Sanitize the calls list at the boundary: LLM output occasionally contains
        # malformed entries (a bare int, a string, a dict, an empty list). Downstream
        # consumers (`_build_calls_code`, `_call_to_solidity`, postprocess hooks) all
        # index `call[0]`, `call[1]`, … assuming each entry is a 2-4 element list
        # whose first element is the function name string. Dropping bad entries here
        # keeps a partially-corrupt LLM response usable instead of crashing the run
        # with `TypeError: 'int' object is not subscriptable`.
        self.calls = [c for c in (calls or []) if FuzzInput._is_well_formed_call(c)]
        self.description = description
        # Lineage = ordered history of gen/mut steps that produced this input.
        # Each entry: {"mode": "gen"|"mut", "name": str, "iter": int}.
        # The first entry is always a "gen" step; subsequent entries are "mut".
        self.lineage: list[dict] = list(lineage) if lineage else []

    @staticmethod
    def _is_well_formed_call(c) -> bool:
        """A call entry must be a list whose first element is a non-empty string
        (the function name). Anything else is LLM garbage we silently drop."""
        return (
            isinstance(c, list)
            and len(c) >= 1
            and isinstance(c[0], str)
            and c[0]
        )

    @property
    def signature(self) -> str:
        """Human-readable lineage, e.g. 'gen:reentrancy_probe@5 → mut:call_insert@7'."""
        return " → ".join(
            f"{s.get('mode','?')}:{s.get('name','?')}@{s.get('iter','?')}"
            for s in self.lineage
        )

    @property
    def depth(self) -> int:
        """Mutation depth: 0 = pure generation, N = N mutations applied since the gen step."""
        return max(0, len(self.lineage) - 1)

    @classmethod
    def from_dict(cls, d: dict) -> FuzzInput:
        return cls(
            calls=d.get("calls", []),
            description=d.get("description", ""),
            lineage=d.get("lineage", []),
        )

    def to_dict(self) -> dict:
        return {
            "calls": self.calls,
            "description": self.description,
            "lineage": self.lineage,
            "signature": self.signature,
        }


# ── Shared LLM infrastructure ─────────────────────────────────────────────────

class _LLMClient:
    """Backend wrapper + history + shared helpers used by Generator and Mutator."""

    def __init__(self, config: LLMConfig, initial_balance_native: int = 10):
        self.config = config
        self.initial_balance_native = initial_balance_native
        self.history: list[dict] = []
        self._abi_set = False
        self.last_prompt: str = ""
        self.last_response: str = ""
        # Fallback tracking — set by Generator.generate() / Mutator.llm_mutate()
        # when the LLM call+parse loop exhausts retries and degrades to the
        # ABI-level path. orchestrator.py reads this after each iteration to emit
        # `fallback: bool` + `fallback_reason: str | None` into the run log.
        # Reset to None by gen/mut at the start of each invocation; remains
        # None on the happy path.
        self.last_fallback_reason: str | None = None
        # Source-budget context: AST + target contract name. Set via
        # `set_source_context()` once after `forge build --ast` succeeds; used
        # by `build_contract_context` to enable stage-2 (target extraction)
        # of the source budget pipeline.
        self._ast: dict | None = None
        self._target_name: str | None = None
        # Declared non-target contracts the fuzzer may call (extend.external). Set
        # once at startup via set_external; drives both the prompt section and the
        # llama-cpp grammar. Empty → target-only (prompt + grammar unchanged).
        self._external: list[dict] = []

        if config.backend == "claude-code":
            self._backend: _LLMBackend = _ClaudeCodeBackend(
                model=config.model if config.model else None
            )
        elif config.backend == "llama-cpp":
            self._backend = _LlamaCppBackend(url=config.backend_url)
        else:
            self._backend = _AnthropicBackend(model=config.model)

    @property
    def token_stats(self) -> TokenUsage:
        return self._backend.token_stats

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # Persist the conversation history (drives prompt dedup/context) + the
    # cumulative token counters so an interrupted LLM run resumes with continuous
    # context and correct token totals. The backend/grammar are rebuilt on resume.
    def checkpoint_state(self) -> dict:
        ts = self.token_stats
        return {
            "history": self.history,
            "tokens_in": getattr(ts, "input_tokens", 0),
            "tokens_out": getattr(ts, "output_tokens", 0),
        }

    def restore_checkpoint_state(self, d: dict) -> None:
        self.history = list(d.get("history", []))
        stats = getattr(self._backend, "_stats", None)
        if stats is not None:
            stats.input_tokens = d.get("tokens_in", 0)
            stats.output_tokens = d.get("tokens_out", 0)

    def setup_abi(self, abi: list[dict]) -> None:
        if not self._abi_set and isinstance(self._backend, _LlamaCppBackend):
            self._backend.set_abi(
                abi,
                max_calls_per_item=self.config.max_calls_per_item,
                max_items_per_request=self.config.max_items_per_request,
            )
            self._abi_set = True

    def set_external(self, external: list[dict] | None) -> None:
        """Register the declared external contracts. Forwards to the llama-cpp
        backend so the GBNF grammar legalizes `<var>.<method>` heads + $ret tokens;
        also backs `external_prompt_section()` for every backend."""
        self._external = list(external or [])
        if isinstance(self._backend, _LlamaCppBackend):
            self._backend.set_external(self._external)

    def external_prompt_section(self) -> str:
        """Markdown block injected into the gen/mut prompts. The external-contract
        listing is emitted only when `extend.external` is declared; the universal
        special-argument vocab (`max`/`now`/`$ret` + the address-slot rule) is
        ALWAYS emitted, so every target — even target-only contracts — is told
        about value chaining and the sentinel uint/address values."""
        exts = self._external
        callable_ = [e for e in exts if e.get("abi")]
        data_only = [e for e in exts if not e.get("abi")]
        lines: list[str] = [""]
        if callable_:
            lines.append(
                "**Callable external contracts** (besides the main target). To call "
                'one, use a call head of the form `"<var>.<method>"`; a bare head '
                "still calls the main target:"
            )
            for e in callable_:
                var = e.get("var", "")
                iface = e.get("interface", "") or f"I{var}"
                addr = e.get("address", "")
                sigs = []
                for m in e.get("abi", []):
                    if m.get("type", "function") != "function":
                        continue
                    ins = ",".join(i.get("type", "") for i in m.get("inputs", []))
                    outs = ",".join(o.get("type", "") for o in m.get("outputs", []))
                    sigs.append(f"{m.get('name')}({ins})" + (f" -> {outs}" if outs else ""))
                lines.append(f"- `{var}` ({iface} @ {addr}): {', '.join(sigs)}")
        if data_only:
            lines.append(
                "**Named addresses** (not callable — pass them in an address-typed "
                "argument slot by name, e.g. a victim/holder, an LP pair, or a token "
                "address):"
            )
            for e in data_only:
                lines.append(f"- `{e.get('var', '')}` (@ {e.get('address', '')})")
        # Universal special-argument vocab — always emitted.
        var_clause = "any `<var>` name above (its address), " if (callable_ or data_only) else ""
        lines += [
            "**Special argument values:**",
            f"- address-typed args accept {var_clause}`target_address`, "
            "`attacker_address`, or a raw 0x literal.",
            '- `"max"` → uint256 max; `"now"` → block.timestamp.',
            '- `"$ret<idx>"` → feed the RETURN VALUE of the call at 0-based index '
            "<idx> in this sequence into this argument (that call must return "
            "exactly one value).",
        ]
        return "\n".join(lines)

    def set_source_context(self, ast: dict | None, target_name: str | None) -> None:
        """Provide the AST + target contract name once at fuzzer startup so
        `build_contract_context` can use the 3-stage source budget pipeline
        (stage 2 = extract target + bases from a multi-contract file).

        Both args optional: when AST is missing (older artifact without
        `forge build --ast`) the budget pipeline degrades gracefully to
        minify + truncate, no stage-2 extraction.
        """
        self._ast = ast
        self._target_name = target_name

    def complete(self, user_prompt: str, cache_prefix: str | None = None) -> str:
        self.last_prompt = user_prompt
        result = self._backend.complete(
            _SYSTEM_PROMPT, user_prompt, self.config.max_tokens, self.config.temperature,
            cache_prefix=cache_prefix,
        )
        self.last_response = result
        return result

    def build_contract_context(self, contract_source: str, contract_abi: list[dict]) -> str:
        if self.config.approach == "greybox":
            # Compact signature list instead of a raw indented ABI JSON dump:
            # same information the ABI carries (names, param types, arity,
            # payable/view/pure) at a fraction of the tokens. Mirrors the
            # whitebox head so both approaches describe the target identically.
            target = getattr(self, "_target_name", None)
            sigs = format_abi_signatures(contract_abi)
            head = f"## Target contract: `{target}`\n" if target else "## Target contract\n"
            head += "A bare call head (no `<var>.` prefix) targets this contract."
            if sigs:
                head += " Its callable functions (exact signatures from the ABI):\n" + sigs
            return head
        budgeted = apply_source_budget(
            contract_source,
            self.config.max_source_chars,
            ast=getattr(self, "_ast", None),
            target_name=getattr(self, "_target_name", None),
        )
        target = getattr(self, "_target_name", None)
        sigs = format_abi_signatures(contract_abi)
        parts: list[str] = []
        if target or sigs:
            head = f"## Target contract: `{target}`\n" if target else "## Target contract\n"
            head += "A bare call head (no `<var>.` prefix) targets this contract."
            if sigs:
                head += " Its callable functions (exact signatures from the ABI):\n" + sigs
            parts.append(head)
        parts.append(f"## Contract Source\n```solidity\n{budgeted}\n```")
        return "\n\n".join(parts)

    def record_run(
        self,
        fuzz_input: FuzzInput,
        reward: float,
        forge_status: str,
        raw_reason: str = "",
        new_branches: int = 0,
        decoded_logs: list[str] = (),
        strategy: str = "",
        mode: str = "",
        fallback: bool = False,
    ) -> None:
        self.history.append({
            "input": fuzz_input.to_dict(),
            "reward": reward,
            "forge_status": forge_status,
            "raw_reason": raw_reason,
            "new_branches": new_branches,
            "decoded_logs": list(decoded_logs),
            "strategy": strategy,
            "mode": mode,
            # True when this input carried NO real LLM intent — an ε-greedy random
            # injection OR the deterministic ABI mutation/random used when the LLM
            # retry loop exhausted. Drives desc=N/A in the history (a synthetic label
            # like "mut:<strategy>@iter<n>" is not a model description).
            "fallback": bool(fallback),
        })
        # Keep the newest `history_window` entries PER strategy (not globally) so
        # each strategy retains a full window of its own runs even when the RL
        # controller interleaves 17 strategies. format_history() renders one
        # strategy's slice per prompt, so per-call token cost stays ~window entries.
        kept: list[dict] = []
        counts: dict[str, int] = {}
        for e in reversed(self.history):
            k = e.get("strategy", "")
            if counts.get(k, 0) < self.config.history_window:
                counts[k] = counts.get(k, 0) + 1
                kept.append(e)
        kept.reverse()  # restore chronological (oldest-first) order
        self.history = kept

    @staticmethod
    def _fmt_eth_mag(eth: float) -> str:
        """Format an ETH magnitude for display. A value ≥ 0.001 ETH prints plainly
        (`2.5`, `0.001`); a smaller NON-ZERO value prints in scientific notation
        (`1.50e-06`) so a sub-milli-ETH amount — a tiny reward delta, a dust drain, or
        a small wei value passed as a call arg — never rounds to a misleading `0` or a
        long unreadable decimal. Shared by the signal magnitude and the call-value tag."""
        if eth != 0 and abs(eth) < 1e-3:
            return f"{eth:.2e}"
        return f"{eth:g}"

    @staticmethod
    def _fmt_raw(n: int) -> str:
        """Format a RAW ERC20 base-unit amount (decimals unknown, so NOT scaled). Short
        integers print verbatim; a >12-digit value (a scaled transfer, an overflow mint)
        prints in scientific notation (`5.79e76`) so the line stays readable."""
        s = str(n)
        if len(s) <= 12:
            return s
        return f"{float(n):.2e}".replace("e+0", "e").replace("e+", "e").replace("e-0", "e-")

    @staticmethod
    def _build_call_parts(calls: list, fail_reasons: dict[int, str]) -> list[str]:
        """Tag each call [ok] or [fail:reason]. `fail_reasons` is keyed by the
        call's POSITION in the sequence (the `[N]` index emitted by
        foundry._call_to_solidity), so a function called twice with only the
        second reverting is tagged correctly — matching by name would mislabel
        both occurrences."""
        parts = []
        for i, c in enumerate(calls):
            base = _LLMClient._fmt_call(c)
            if i in fail_reasons:
                parts.append(f"{base}[fail:{fail_reasons[i]}]")
            else:
                parts.append(f"{base}[ok]")
        return parts

    # ── Financial-signal tier rendering ───────────────────────────────────────
    # Priority for choosing the ONE authoritative headline when several
    # BUG_SIGNAL lines fire in a run (amounts are NOT summed — attacker_profit
    # already nets every asset; the per-asset heuristics overlap it). The winner's
    # tier also sets the column label (attacker_profit/target_loss are tier=high).
    _SIGNAL_PRIORITY = {
        "attacker_profit": 0,   # tier=high: net attacker gain (best)
        "target_loss": 1,       # tier=high: net victim loss
        "attacker_gained": 2,   # tier=heuristic: per-asset attacker delta
        "target_drained": 3,    # tier=heuristic: per-asset victim drain
    }

    @staticmethod
    def _parse_bug_signal(line: str) -> dict | None:
        """Parse one BUG_SIGNAL line into a dict, or None if it isn't one. Three shapes:
          native heuristic: BUG_SIGNAL: <name> tier=heuristic asset=<SYM> value=<wei>
          ERC20 heuristic:  BUG_SIGNAL: <name> tier=heuristic asset=<SYM> token_address=<addr> amount=<raw>
          value verdict:    BUG_SIGNAL: <name> tier=high total_asset=<count> target_asset=<SYM> value=<wei>
        `asset`/`target_asset` are currency SYMBOLS; `token_address` marks an ERC20 heuristic
        (absent → native). The magnitude key encodes the unit — `value=` is native numéraire
        wei (18-dec), `amount=` is ERC20 raw base-units — but both land in the single `amount`
        field here (display picks scaling via `token_address`), so a legacy `amount=` native
        line still parses."""
        s = str(line).strip()
        if not s.startswith("BUG_SIGNAL"):
            return None
        body = s.split("BUG_SIGNAL:", 1)[-1].strip() if "BUG_SIGNAL:" in s else s[len("BUG_SIGNAL"):].strip()
        parts = body.split()
        if not parts:
            return None
        sig: dict = {"name": parts[0], "tier": "", "asset": "", "token_address": "",
                     "total_asset": None, "target_asset": "", "amount": None}
        for kv in parts[1:]:
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k == "value":       # native numéraire magnitude → shared `amount` field
                k = "amount"
            if k in ("amount", "total_asset"):
                try:
                    sig[k] = int(v)
                except ValueError:
                    sig[k] = None
            elif k in sig:
                sig[k] = v
        return sig

    @classmethod
    def _render_signal(cls, logs) -> str:
        """Render the oracle-signal column: `signal=N`, or `signal=<High|Heuristic> [detail]`.
        The tier (from the emitted bug signal) is the headline — High = confirmed net
        profit/loss, Heuristic = a balance moved past a threshold (value moved but net theft
        not yet proven). The [detail] carries a signed amount so the model sees how much moved.

        Amount + currency MIRROR the winning decoded-log line's own SYMBOL (chain-aware):
          • value verdict (attacker_profit / target_loss) → the numéraire `target_asset`, the
            native coin (ETH mainnet / BNB BSC / …), 18-dec scaled; `total_asset` trails as
            `, N assets`. target_loss adds `, attacker gain unconfirmed` (value left the target
            but its capture by the attacker is unproven).
          • native heuristic (no `token_address`) → the native coin `asset`, 18-dec scaled.
          • ERC20 heuristic (`token_address` set) → decimals unknown, so the RAW base-unit
            `amount` is shown with the token's `asset` symbol (or `UnknownERC20Token`) — e.g.
            `attacker +5.79e76 UnknownERC20Token`.
        Examples: `signal=High [attacker +12.04 ETH, 3 assets]`,
        `signal=High [target -1.8 ETH, attacker gain unconfirmed, 3 assets]`,
        `signal=Heuristic [attacker +1000 WETH]`, `signal=Heuristic [target -1.5e9 USDC]`."""
        sigs = [s for s in (cls._parse_bug_signal(l) for l in logs) if s]
        if not sigs:
            return "signal=N"
        chosen = min(sigs, key=lambda s: cls._SIGNAL_PRIORITY.get(s["name"], 99))
        tier = "High" if chosen.get("tier") == "high" else "Heuristic"
        name = chosen["name"]
        is_value = name in ("attacker_profit", "target_loss")
        is_erc20_heur = (not is_value) and bool(chosen.get("token_address"))
        amt = chosen.get("amount")

        # Magnitude string (no sign): an 18-dec coin (numéraire or native heuristic) is scaled
        # by 1e18 and shown with the coin symbol; an ERC20 heuristic's decimals are unknown, so
        # the RAW base-unit amount is shown with the token symbol.
        unit = ((chosen.get("target_asset") if is_value else chosen.get("asset")) or "").strip()
        if not (amt and unit):
            mag = None
        elif is_erc20_heur:
            mag = f"{cls._fmt_raw(amt)} {unit}"
        else:
            mag = f"{cls._fmt_eth_mag(amt / 1e18)} {unit}"

        if name in ("attacker_profit", "attacker_gained"):
            body = f"attacker +{mag}" if mag else "attacker gain"
        elif name == "target_loss":
            core = f"target -{mag}" if mag else "target loss"
            body = f"{core}, attacker gain unconfirmed"
        else:  # target_drained (heuristic) — amount only, no attribution word
            body = f"target -{mag}" if mag else "target drain"

        # Value verdicts carry total_asset = how many holdings were netted into net worth.
        n = chosen.get("total_asset")
        if is_value and n:
            body = f"{body}, {n} asset{'' if n == 1 else 's'}"
        return f"signal={tier} [{body}]"

    def _entry_line(self, entry: dict, idx: int) -> str:
        """Render one history entry as a single line:
        `[n] caller:call(args)[ok|fail:reason]→… | <r>r +<br>br | signal=… | desc="…"`
        """
        inp = entry.get("input", {})
        reward = entry.get("reward", 0.0)
        new_branches = entry.get("new_branches", 0)
        logs = entry.get("decoded_logs", [])

        # Fail reasons keyed by call POSITION, parsed from the `[N] label fail: reason`
        # console.log lines (index = the call's position in the original calls list).
        fail_reasons: dict[int, str] = {}
        for log in logs:
            m = re.match(r"^\[(\d+)\]\s*.*?\s+fail:\s*(.*)$", str(log).strip())
            if m:
                fail_reasons[int(m.group(1))] = m.group(2).strip() or "revert"

        call_seq = "→".join(self._build_call_parts(inp.get("calls", []), fail_reasons))
        signal = self._render_signal(logs)

        # Description of the attempt — replays the model's own prior intent so it
        # doesn't re-propose it. Fallback/random inputs carry no real intent → N/A:
        # the recorded `fallback` flag (ε-random OR LLM-exhausted deterministic path)
        # is authoritative; the empty / "random:"-prefixed checks are belt-and-suspenders
        # for inputs recorded without the flag (e.g. older callers).
        desc = str(inp.get("description") or "").strip()
        if entry.get("fallback") or not desc or desc.lower().startswith("random:"):
            desc_part = "desc=N/A"
        else:
            if len(desc) > 80:
                desc = desc[:79] + "…"
            desc_part = f'desc="{desc}"'

        return f"[{idx}] {call_seq} | {reward:+.1f}r +{new_branches}br | {signal} | {desc_part}"

    def format_history(self, strategy: str | None = None) -> str:
        """Render run history (entry lines only; the column legend lives in the
        cached SYSTEM_PROMPT, not this uncached tail). When *strategy* is given,
        show only that strategy's own runs; otherwise show every run."""
        entries = self.history
        if strategy is not None:
            entries = [e for e in entries if e.get("strategy") == strategy]
        if not entries:
            return "No runs yet."
        return "\n".join(self._entry_line(entry, idx=i) for i, entry in enumerate(entries, 1))

    def format_history_rich(self, strategy: str | None = None) -> str:
        """Same as format_history() but with Rich color markup for terminal display."""
        from rich.markup import escape

        plain = self.format_history(strategy)

        # Replace status markers with NUL-delimited placeholders BEFORE escaping
        # so that rich.markup.escape() (which only escapes some bracket patterns)
        # doesn't leave [Fail:reason] or [1ETH] as unescaped Rich markup.
        plain = re.sub(r"\[ok\]", "\x00OK\x00", plain)
        plain = re.sub(
            r"\[fail:([^\]]*)\]",
            lambda m: f"\x00FAIL\x00{m.group(1)}\x00ENDFAIL\x00",
            plain,
        )
        plain = plain.replace("signal=High", "\x00SIGH\x00")
        s = escape(plain)  # escapes all remaining [ safely (entry numbers, ETH values, signal headline, etc.)

        # Restore placeholders as Rich markup
        s = s.replace("\x00OK\x00", r"[green]\[ok][/green]")
        s = re.sub(r"\x00FAIL\x00([^\x00]*)\x00ENDFAIL\x00", r"[red]\[fail:\1][/red]", s)
        s = s.replace("\x00SIGH\x00", "[bold red]signal=High[/bold red]")
        return s

    @staticmethod
    def extract_json(text: str) -> str:
        import re
        text = re.sub(r"```(?:json)?\s*", "", text).strip()
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
        return text

    @staticmethod
    def normalize_items(items):
        """Repackage bare-list LLM responses into FuzzInput dicts.

        The GBNF grammar requires `[{"calls":[...], "description":"..."}]`, but
        non-GBNF backends (or any path where the grammar isn't enforced) sometimes
        return `[[fn, args, val, caller], ...]` — a bare list of call entries with
        no `{"calls": ...}` wrapper. Downstream `FuzzInput.from_dict` calls `.get`
        and crashes with `'list' object has no attribute 'get'`.

        If every top-level entry is a list whose first element is a non-empty
        string (i.e. a function-name-led call entry), treat the whole array as
        one FuzzInput's calls and wrap it.
        """
        if not isinstance(items, list) or not items:
            return items
        if all(
            isinstance(it, list) and len(it) >= 1 and isinstance(it[0], str) and it[0]
            for it in items
        ):
            return [{"calls": items, "description": "(auto-wrapped from bare call list)"}]
        return items

    @staticmethod
    def _fmt_call(c: list) -> str:
        if not c:
            return "?"
        caller = (
            c[3].replace("attacker_address", "atk")
            if len(c) > 3 and isinstance(c[3], str) else "?"
        )
        if c[0] == "atk.setReentrantCall" and len(c) > 1 and isinstance(c[1], dict):
            fn = c[1].get("reentrant_func", "?")
            n = c[1].get("max_count", "?")
            # Show caller + the real method on the unified attacker instead of a
            # bare "setup(…)" so the arming call reads like any other <var>.<method>.
            return f"{caller}:atk.setReentrantCall({fn},×{n})"

        # Show sentinel hex values symbolically and keep short hex intact — the
        # boundary strategies need to see whether `max`/`0`/`1` was already tried;
        # only genuinely long, non-sentinel hex (addresses / bytes blobs) is truncated.
        _SENTINEL_HEX = {
            0: "0", 1: "1", 2**64 - 1: "2^64-1", 2**128 - 1: "2^128-1",
            2**255: "2^255", 2**256 - 1: "max",
        }

        def _trunc(a: object) -> str:
            s = str(a)
            if not s.startswith("0x"):
                return s
            try:
                v = int(s, 16)
            except ValueError:
                return (s[:8] + "…") if len(s) > 10 else s
            if v in _SENTINEL_HEX:
                return _SENTINEL_HEX[v]
            return (s[:8] + "…") if len(s) > 10 else s

        args = ",".join(_trunc(a) for a in (c[1] if len(c) > 1 and isinstance(c[1], list) else []))
        value = c[2] if len(c) > 2 else 0
        value_suffix = ""
        if value not in (0, "0", "0x0"):
            try:
                wei = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
                eth = wei / 1e18
                value_suffix = f"[{_LLMClient._fmt_eth_mag(eth)}ETH]"
            except (ValueError, TypeError):
                value_suffix = f"[{value}]"
        fn_part = f"{c[0]}({args})" if args else c[0]
        return f"{caller}:{fn_part}{value_suffix}"
