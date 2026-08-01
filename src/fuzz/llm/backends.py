"""LLM provider backends + token accounting — split out of `agent.py`.

Holds the three `_LLMBackend` implementations (`anthropic` / `claude-code` /
`llama-cpp`, the last with its GBNF grammar builder) plus the `TokenUsage` /
`LlamaTokenStats` accounting dataclasses they produce. These live here rather
than in `agent.py` because the backends construct them at runtime and
`agent.py` imports the backends — keeping the types here avoids an import
cycle. `agent.py` re-exports every public name, so
`from ..llm.agent import TokenUsage` / `_LlamaCppBackend` keep working.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

import anthropic

from .prompts import CHATML_TEMPLATE as _CHATML_TEMPLATE

logger = logging.getLogger(__name__)

# SSL context that skips certificate verification — used for llama-cpp servers
# behind self-signed or private-CA certificates (e.g. homelab HTTPS endpoints).
_SSL_NO_VERIFY = ssl.create_default_context()
_SSL_NO_VERIFY.check_hostname = False
_SSL_NO_VERIFY.verify_mode = ssl.CERT_NONE


@dataclass
class TokenUsage:
    """Accumulated token usage across all LLM calls for a fuzzing run."""
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def __str__(self) -> str:
        return (
            f"requests={self.requests} | "
            f"in={self.input_tokens:,} out={self.output_tokens:,} "
            f"total={self.total_tokens:,}"
        )


@dataclass
class LlamaTokenStats(TokenUsage):
    """Accumulated token and timing stats for the llama-cpp backend."""
    total_ms: float = 0.0    # wall time across all requests
    max_tokens: int = 0      # n_predict limit configured for requests
    truncated: int = 0       # requests that hit the n_predict limit (stopped_limit=true)

    @property
    def output_tokens_per_sec(self) -> float:
        return (self.output_tokens / self.total_ms * 1000) if self.total_ms else 0.0

    def __str__(self) -> str:
        trunc = f" truncated={self.truncated}/{self.requests}" if self.truncated else ""
        return (
            f"requests={self.requests} | "
            f"input={self.input_tokens:,} output={self.output_tokens:,} "
            f"total={self.total_tokens:,} tokens{trunc} | "
            f"wall={self.total_ms/1000:.1f}s | "
            f"speed={self.output_tokens_per_sec:.1f} tok/s"
        )


# ── Backend interface ─────────────────────────────────────────────────────────

class _LLMBackend(ABC):
    """Internal interface — call an LLM with a system + user prompt.

    `cache_prefix`, when given, is the leading slice of `user` that is stable
    across many calls (the contract context: source + ABI). Backends that
    support explicit prompt caching mark that slice as a cache breakpoint so
    the whole run reuses it; backends that cache implicitly (llama-cpp) or
    manage caching internally (claude-code) ignore it.
    """

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 4096,
                 temperature: float | None = 0.7,
                 cache_prefix: str | None = None) -> str:
        ...


class _AnthropicBackend(_LLMBackend):
    """Direct Anthropic API backend."""

    def __init__(self, model: str):
        self._client = anthropic.Anthropic()
        self._model = model
        self._stats = TokenUsage()

    @property
    def token_stats(self) -> TokenUsage:
        return self._stats

    def complete(self, system: str, user: str, max_tokens: int = 4096,
                 temperature: float | None = 0.7,
                 cache_prefix: str | None = None) -> str:
        # Prompt caching: split the stable contract-context prefix into its own
        # content block with an ephemeral cache breakpoint. The prefix is
        # byte-identical across every strategy and iteration in a run, so the
        # cached span (system + context) is re-read at ~0.1× input cost instead
        # of re-billed in full. A breakpoint on this message block also caches
        # the `system` prompt that renders before it. The volatile tail (task
        # framing + history) stays uncached. Falls back to a plain string when
        # there's no prefix or `user` doesn't start with it (keeps caching a
        # prefix-exact match; see prompt-caching prefix invariant).
        content: str | list[dict]
        if cache_prefix and user.startswith(cache_prefix):
            tail = user[len(cache_prefix):]
            content = [
                {"type": "text", "text": cache_prefix,
                 "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": tail},
            ]
        else:
            content = user
        kwargs: dict = dict(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": content}],
        )
        if temperature is not None:        # None → omit, use API default (1.0)
            kwargs["temperature"] = temperature
        response = self._client.messages.create(**kwargs)
        self._stats.requests += 1
        self._stats.input_tokens += response.usage.input_tokens
        self._stats.output_tokens += response.usage.output_tokens
        return response.content[0].text.strip()


class _ClaudeCodeBackend(_LLMBackend):
    """Claude Agent SDK backend — calls the local `claude` CLI.

    Requires:
      pip install "sc-fuzzing[claude-code]"   (adds claude-agent-sdk)
      Claude Code CLI installed and authenticated
    """

    def __init__(self, model: str | None = None):
        import importlib
        if importlib.util.find_spec("claude_agent_sdk") is None:
            raise ImportError(
                "claude-agent-sdk is not installed. "
                'Run: pip install "sc-fuzzing[claude-code]"'
            )
        self._model = model  # None = use CLI default
        self._stats = TokenUsage()

    @property
    def token_stats(self) -> TokenUsage:
        return self._stats

    def complete(self, system: str, user: str, max_tokens: int = 4096,
                 temperature: float | None = 0.7,
                 cache_prefix: str | None = None) -> str:
        """Run the Agent SDK query synchronously."""
        del max_tokens, temperature  # Agent SDK manages sampling internally
        del cache_prefix             # Agent SDK manages prompt caching internally
        from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query  # type: ignore[import]

        options = ClaudeAgentOptions(
            system_prompt=system,
            allowed_tools=[],          # pure text generation — no tools needed
            permission_mode="dontAsk", # non-interactive
            **({"model": self._model} if self._model else {}),
        )

        result_msg: ResultMessage | None = None

        async def _run() -> None:
            nonlocal result_msg
            async for message in query(prompt=user, options=options):
                if isinstance(message, ResultMessage):
                    result_msg = message

        asyncio.run(_run())

        if result_msg is None:
            return ""

        # ResultMessage exposes usage (dict or object) and total_cost_usd from the CLI JSON output
        usage = getattr(result_msg, "usage", {}) or {}
        def _usage_get(key: str) -> int:
            return usage.get(key, 0) if isinstance(usage, dict) else getattr(usage, key, 0)
        self._stats.requests += 1
        self._stats.input_tokens += (
            _usage_get("input_tokens")
            + _usage_get("cache_creation_input_tokens")
            + _usage_get("cache_read_input_tokens")
        )
        self._stats.output_tokens += _usage_get("output_tokens")

        return (result_msg.result or "").strip()


class _LlamaCppBackend(_LLMBackend):
    """Native llama.cpp /completion endpoint with full GBNF grammar support.

    Uses the native (non-OpenAI) endpoint which accepts:
      POST /completion
      { "prompt": "...", "n_predict": N, "grammar": "<GBNF>" }
    and returns:
      { "content": "..." }

    The model is loaded at server startup — no model field in requests.
    Grammar hard-constrains token sampling to produce valid fuzz input JSON.

    Configure via:
      --backend-url http://localhost:8080/completion
      or LLAMA_CPP_URL env var
      or LLMConfig.backend_url
    """

    # ChatML prompt template — canonical home: fuzz.llm.prompts.CHATML_TEMPLATE
    # Bound as a class attribute so subclasses / instance code keeps the old shape.
    _PROMPT_TEMPLATE = _CHATML_TEMPLATE

    def __init__(self, url: str, prompt_template: str | None = None):
        self._url = url if url.endswith("/completion") else url.rstrip("/") + "/completion"
        self._base_url = self._url[: self._url.rfind("/")]  # http://host:port
        self._template = prompt_template or self._PROMPT_TEMPLATE
        # Grammar inputs are stored so set_abi can rebuild the grammar.
        self._abi: list[dict] = []
        self._external: list[dict] = []   # declared non-target contracts (extend.external)
        self._mcpi: int = 10            # max_calls_per_item
        self._mipr: int = 1             # max_items_per_request
        self._grammar = self._fallback_grammar()
        self._stats = LlamaTokenStats()
        # Grammars already confirmed accepted by the server (active probe in
        # _ensure_grammar_active). Keyed by grammar string so a rebuild re-checks.
        self._validated_grammars: set[str] = set()
        # True once a grammar was rejected and we degraded to the generic fallback.
        self._grammar_degraded = False

    def detect_model_name(self) -> str:
        """Query /props to get the loaded model name. Returns 'local-model' on failure."""
        import os
        props_url = self._base_url + "/props"
        try:
            ctx = _SSL_NO_VERIFY if props_url.startswith("https") else None
            req = urllib.request.Request(props_url, method="GET")
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                props = json.loads(resp.read())
            # /props returns {"model_path": "/path/to/model.gguf", ...}
            model_path = props.get("model_path") or props.get("default_generation_settings", {}).get("model", "")
            if model_path:
                return os.path.splitext(os.path.basename(model_path))[0]
        except Exception:
            pass
        return "local-model"

    @property
    def token_stats(self) -> LlamaTokenStats:
        """Read-only view of accumulated token usage."""
        return self._stats

    def reset_stats(self) -> LlamaTokenStats:
        """Reset counters and return the final snapshot before reset."""
        snapshot = self._stats
        self._stats = LlamaTokenStats()
        return snapshot

    def set_abi(self, abi: list[dict], max_calls_per_item: int = 10, max_items_per_request: int = 1) -> None:
        """Rebuild the GBNF grammar constrained to functions in the ABI.
        Call once after the ABI is loaded — grammar is reused for all requests.
        """
        self._abi = abi
        self._mcpi = max_calls_per_item
        self._mipr = max_items_per_request
        self._rebuild_grammar()

    def set_external(self, external: list[dict]) -> None:
        """Set the declared external contracts and rebuild the grammar so
        `<var>.<method>` call heads + $ret chaining tokens are legalized."""
        self._external = list(external or [])
        self._rebuild_grammar()

    def _rebuild_grammar(self) -> None:
        self._grammar = self._build_gbnf(
            self._abi,
            max_calls_per_item=self._mcpi,
            max_items_per_request=self._mipr,
            external=self._external,
        )
        logger.debug(
            "llama-cpp: grammar updated for %d ABI functions (max_calls_per_item=%d, "
            "max_items_per_request=%d)",
            sum(1 for f in self._abi if f.get("type") == "function"),
            self._mcpi, self._mipr,
        )

    # ── Grammar builders ──────────────────────────────────────────────────────

    @staticmethod
    def _arg_rule(sol_type: str, aux: dict[str, str]) -> str:
        """Return a GBNF *rule name* for one Solidity arg type, registering the
        rule's body in `aux` (name → body) on first use.

        Every arg type is emitted as a NAMED rule and referenced by name rather
        than inlined into the call/array rules. This is the key to staying under
        llama.cpp's repetition-expansion limit ("number of rules that are going
        to be repeated multiplied by the new repetition exceeds sane defaults"):
        a `{0,N}` dynamic-array repetition or a `[n]` fixed-array fan-out then
        repeats a single atomic rule REFERENCE, not a multi-node inline group.

        Inlining used to multiply out catastrophically — e.g. dynamic `bytes`
        (body `[0-9a-fA-F]{0,256}`) nested inside an array's `{0,9}` repetition
        expanded to ~2300 nodes, so any function with a `bytes[]`/multi-array
        signature (a common `batchTransfer`-style shape) made llama-server
        silently REJECT the whole grammar and fall back to free sampling.
        Defining the element once as a named rule confines that `{0,256}` to a
        single expansion regardless of how many times it's referenced.
        """
        t = sol_type.strip()

        # Array: T[n] (fixed) or T[] (dynamic). The element is itself a named rule,
        # so the repetition only ever multiplies a single reference.
        if t.endswith("]") and "[" in t:
            bracket = t.rindex("[")
            elem = _LlamaCppBackend._arg_rule(t[:bracket], aux)
            size_str = t[bracket + 1:-1]
            if size_str.isdigit():
                n = max(int(size_str), 1)
                name = f"arr-{elem}-{n}"
                if name not in aux:
                    aux[name] = '"[" ws ' + ' ws "," ws '.join([elem] * n) + ' ws "]"'
                return name
            # dynamic array: type[] — bounded to 10 elements via `{0,9}` repetition.
            # Unbounded `*` here let the model run away to context-window edge.
            name = f"arrdyn-{elem}"
            if name not in aux:
                aux[name] = f'"[" ws ({elem} ("," ws {elem}){{0,9}})? ws "]"'
            return name

        # Tuple types never reach here: functions with a tuple in their signature
        # are dropped from the call pool by interface_eligible (Class A), so the
        # old `tuple-arg` rule is dead and removed. A tuple that somehow slips
        # through falls to the str-val default below (safe, never a free slot).

        # uint / int families — uint uses hex (compact), int keeps decimal (supports
        # negatives). Both also accept the symbolic tokens the renderer resolves in a
        # numeric slot: $ret<idx> (chained return), "max" (type(uint).max), "now"
        # (block.timestamp). Per-width caps (one NAMED rule per distinct width):
        #   uintN → hex capped to N/4 digits → value ≤ 2**N-1 EXACTLY (N is a
        #           multiple of 8, so N/4 hex digits is the exact bound).
        #   intN  → decimal digit-count capped to len(str(2**(N-1))) → a safe
        #           OVER-approximation (grammar can't express the exact signed
        #           range), so Tier-2 _normalize_arg's clamp stays authoritative.
        # Widths parsed via arg_sampling.type_width (the single width source shared
        # with Tier-1/Tier-2). See rule/update_grammar.md.
        from ..fuzzer.arg_sampling import type_width
        if t.startswith("uint"):
            w = type_width(t)
            bits = w[1] if w else 256
            hexdigits = max(1, bits // 4)
            name = f"uint{bits}-arg"
            aux.setdefault(
                name,
                r'"\"0x" [0-9a-fA-F]{1,' + str(hexdigits) + r'} "\"" | ret-val | "\"max\"" | "\"now\""',
            )
            return name
        if t.startswith("int"):
            w = type_width(t)
            bits = w[1] if w else 256
            tail = max(0, len(str(1 << (bits - 1))) - 1)
            name = f"int{bits}-arg"
            aux.setdefault(
                name,
                r'"-"? "0" | "-"? [1-9] [0-9]{0,' + str(tail) + r'} | ret-val',
            )
            return name
        if t.startswith("bytes"):
            # bytesN (fixed-size): exactly 2N hex chars. Dynamic bytes: bounded {0,256}.
            # Defined as a named rule so the {0,256} expansion happens ONCE in the
            # rule body, no matter how many args/arrays reference it.
            rest = t[5:]
            if rest.isdigit():
                n = int(rest)
                name = f"bytes{n}-arg"
                aux.setdefault(name, r'"\"0x" [0-9a-fA-F]{' + str(2 * n) + r'} "\""')
                return name
            aux.setdefault("bytesdyn-arg", r'"\"0x" [0-9a-fA-F]{0,256} "\""')
            return "bytesdyn-arg"
        if t == "bool":
            return "bool-val"        # defined in the base grammar
        if t == "address":
            return "addr-arg-val"    # defined in the base grammar (raw 0x + named aliases)
        # string + any unknown solidity type → bounded string slot (str-val, {0,300}).
        return "str-val"             # defined in the base grammar

    @staticmethod
    def _sanitize_rule_name(name: str) -> str:
        """Make a Solidity function name safe to use as a GBNF rule-name suffix.

        llama.cpp's grammar parser only accepts [a-zA-Z0-9-] in rule NAMES
        (underscore is NOT allowed — confirmed empirically against
        qwen2.5-coder-1.5b on Cover's ABI). A rule like `call-START_TIME`
        makes the parser truncate the name at `_`, treat the suffix as a
        syntax error, and silently disable the grammar for the whole request.
        The model then samples freely — returning markdown fences and bare
        arrays instead of the constrained `[{"calls":...}]` shape.

        We replace every non-conformant char with `-`. Identifier-clean
        camelCase names pass through unchanged; underscored / numeric-leading
        / dollar-sign names get rewritten. The LITERAL function name embedded
        in the rule body (`"\"START_TIME\""`) is untouched, so the JSON the
        model emits still uses the real Solidity name.
        """
        return "".join(c if c.isalnum() or c == "-" else "-" for c in name)

    @classmethod
    def _build_gbnf(cls, abi: list[dict], max_calls_per_item: int = 10,
                    max_items_per_request: int = 1, external: list[dict] | None = None) -> str:
        """Build a GBNF grammar where `call` is restricted to ABI functions only.

        The `calls` rule is bounded to at most *max_calls_per_item* entries via a
        chain of N-1 optional tail rules instead of the unbounded ("," ws call)*
        pattern. The top-level `root` array is bounded to at most
        *max_items_per_request* fuzz-items — matches the LLMConfig knob so the
        grammar never legalizes more items than the prompt asks for.
        """
        # Class A: only interface-callable functions become `call` alternatives, so
        # even a grammar-constrained model can't select a tuple-typed function the
        # interface omits (pool == interface == grammar).
        from ..fuzzer.sol_interface import interface_eligible
        functions = [f for f in interface_eligible(abi) if f.get("type") == "function"]

        func_rules: list[str] = []
        call_alts: list[str] = []
        # Per-arg-type rule definitions accumulated by _arg_rule (name → body).
        # Emitting these once and referencing them by name (instead of inlining
        # each type's expression at every call/array site) is what keeps the
        # grammar within llama.cpp's repetition-expansion limit.
        aux_rules: dict[str, str] = {}
        # Track rule-name collisions: overloaded Solidity functions (same name,
        # different arity) and post-sanitization name clashes (`_foo` and `-foo`
        # both → `-foo`) get a `-vN` suffix on every entry after the first.
        rule_counts: dict[str, int] = {}

        for func in functions:
            name = func["name"]
            inputs = func.get("inputs", [])
            payable = func.get("stateMutability") == "payable"
            base_rule = f"call-{cls._sanitize_rule_name(name)}"
            n = rule_counts.get(base_rule, 0) + 1
            rule_counts[base_rule] = n
            rule = base_rule if n == 1 else f"{base_rule}-v{n}"

            if not inputs:
                args_gbnf = '"[]"'
            else:
                parts = [cls._arg_rule(inp["type"], aux_rules) for inp in inputs]
                args_gbnf = '"[" ws ' + ' ws "," ws '.join(parts) + ' ws "]"'

            # Third element: value_wei (ETH sent with the call).
            # Payable functions allow any wei amount (hex string); non-payable is the
            # zero hex string "0x0" — matches the dataset convention (value is always a
            # hex string, never a bare 0) so authored PoCs and grammar output agree.
            value_gbnf = "uint-wei" if payable else r'"\"0x0\""'

            func_rules.append(
                f'{rule} ::= "[" ws "\\"{name}\\"" ws "," ws {args_gbnf} ws "," ws {value_gbnf} ws "," ws caller-val ws "]"'
            )
            call_alts.append(rule)

        # Declared external contracts: one call alternative per <var>.<method>, with
        # a permissive `ext-args` body (args may be scalars, $ret tokens, var names,
        # or one level of array nesting — foundry.py coerces them against the looked-up
        # types, so strict per-type grammar isn't needed for these advanced heads).
        ext_rules: list[str] = []
        ext_vars: list[str] = []
        for ext in (external or []):
            var = ext.get("var")
            if not var:
                continue
            ext_vars.append(var)
            payable_methods = {
                m.get("name") for m in ext.get("abi", [])
                if m.get("type", "function") == "function" and m.get("stateMutability") == "payable"
            }
            _seen_m: set[str] = set()
            for m in ext.get("abi", []):
                if m.get("type", "function") != "function":
                    continue
                method = m.get("name")
                if not method or method in _seen_m:
                    continue
                _seen_m.add(method)
                rule = f"call-ext-{cls._sanitize_rule_name(var)}-{cls._sanitize_rule_name(method)}"
                val_gbnf = "uint-wei" if method in payable_methods else r'"\"0x0\""'
                ext_rules.append(
                    f'{rule} ::= "[" ws "\\"{var}.{method}\\"" ws "," ws ext-args ws "," ws '
                    f'{val_gbnf} ws "," ws caller-val ws "]"'
                )
                call_alts.append(rule)

        # Reentrancy setup call: only valid when the ABI has functions to re-enter.
        # When ABI is empty (fallback grammar used pre-set_abi), omit the branch
        # entirely — there's no legal function name the model could emit.
        # Dedupe LITERAL names so overloaded functions don't produce a duplicate
        # alternation (the literal is just the JSON string the model emits — same
        # text from both overloads is fine, but listing it twice still parses).
        _seen: set[str] = set()
        fn_name_alts = " | ".join(
            f'"\\"{f["name"]}\\""' for f in functions
            if f["name"] not in _seen and not _seen.add(f["name"])
        )
        if functions:
            call_alts.append("call-reentrancy-setup")
        call_rule = ("call ::= " + " | ".join(call_alts)) if call_alts else (
            r'call ::= "[" ws "\"" [a-zA-Z_][a-zA-Z0-9_]* "\"" ws "," ws "[" ws (value ("," ws value)*)? ws "]" ws "," ws uint-val ws "]"'
        )

        # Bounded calls rule: at most max_calls_per_item entries via `{0,N-1}` repetition.
        # N=1 special-cased to drop the degenerate `{0,0}` tail.
        n = max(1, max_calls_per_item)
        if n == 1:
            calls_rule = r'calls ::= "[]" | "[" ws call ws "]"'
        else:
            calls_rule = f'calls ::= "[]" | "[" ws call ("," ws call){{0,{n - 1}}} ws "]"'

        # Bounded to at most `max_items_per_request` fuzz-items. The mandatory head
        # `fuzz-item` enforces min=1; the optional tail `("," ws fuzz-item){0,N-1}`
        # adds up to N-1 more. N=1 special-cased to drop the degenerate `{0,0}` tail.
        n_inputs = max(1, max_items_per_request)
        if n_inputs == 1:
            root_rule = r'root ::= "[" ws fuzz-item ws "]"'
        else:
            root_rule = f'root ::= "[" ws fuzz-item ("," ws fuzz-item){{0,{n_inputs - 1}}} ws "]"'

        lines = [
            root_rule,
            r'fuzz-item ::= "{" ws "\"calls\"" ws ":" ws calls ws "," ws "\"description\"" ws ":" ws str-val ws "}"',
            calls_rule,
            call_rule,
            # Special call: configures the unified Attacker's reentrancy callback (args is a JSON object,
            # not a list). `reentrant_func` is constrained to ABI function names — Python builds the
            # Solidity sig from the ABI's input types, so the LLM can't emit a malformed signature.
            # `reentrant_args` accepts generic values; foundry.py::_normalize_arg coerces them against
            # the looked-up types. The sentinel head is `atk.setReentrantCall`; caller is attacker_address.
            *([
                r'call-reentrancy-setup ::= "[" ws "\"atk.setReentrantCall\"" ws "," ws reentrant-obj ws "," ws "\"0x0\"" ws "," ws caller-val ws "]"',
                # max_count constrained to 1..5 (foundry.MAX_REENTRY_COUNT): a single 1-5 digit.
                r'reentrant-obj ::= "{" ws "\"reentrant_func\"" ws ":" ws reentrant-func-val ws "," ws "\"reentrant_args\"" ws ":" ws value-arr ws "," ws "\"max_count\"" ws ":" ws [1-5] ws "}"',
                f'reentrant-func-val ::= {fn_name_alts}',
                # Bounded to 10 entries via `{0,9}` repetition — unbounded `*` was a runaway hazard.
                r'value-arr ::= "[]" | "[" ws value ("," ws value){0,9} ws "]"',
            ] if functions else []),
            *func_rules,
            *ext_rules,
            # External-call argument list: scalars / $ret tokens / var names, plus
            # one level of array nesting (e.g. a swap `path` of addresses).
            *([
                r'ext-args ::= "[]" | "[" ws ext-arg ("," ws ext-arg){0,9} ws "]"',
                r'ext-arg  ::= value | "[" ws (value ("," ws value){0,9})? ws "]"',
            ] if ext_rules else []),
            # $ret<idx> chains an earlier call's single return value into a later arg.
            r'ret-val    ::= "\"$ret" [0-9]{1,3} "\""',
            # Symbolic value tokens: type(uint256).max, block.timestamp, and each
            # declared external var name (resolves to that contract's address).
            'name-val   ::= ' + " | ".join(
                ['"\\"max\\""', '"\\"now\\""',
                 '"\\"target_address\\""', '"\\"attacker_address\\""']
                + [f'"\\"{v}\\""' for v in ext_vars]
            ),
            r'value      ::= uint-val | int-val | addr-val | bool-val | str-val | ret-val | name-val | "null"',
            r'uint-val   ::= "\"0x" [0-9a-fA-F]{1,64} "\""',
            r'uint-wei   ::= "\"0x" [0-9a-fA-F]{1,64} "\""',
            r'int-val    ::= "-"? "0" | "-"? [1-9] [0-9]{0,77}',
            r'addr-val     ::= "\"0x" [0-9a-fA-F]{40} "\""',
            r'caller-val   ::= "\"attacker_address\""',
            # Address-typed args (target calls too) accept a declared external/data-only
            # var name — that's how a PoC passes a victim/holder/token/pair by name.
            ('addr-arg-val ::= addr-val | caller-val | target-address-val | ret-val' + (
                " | " + " | ".join(f'"\\"{v}\\""' for v in ext_vars) if ext_vars else ""
            )),
            r'target-address-val ::= "\"target_address\""',
            r'bool-val   ::= "true" | "false"',
            # Cap description/string length at 300 chars. The original unbounded `*` was the
            # primary cause of context-window runaways: once the model committed to a description
            # at temp>0, nothing in the grammar could force it to close the quote, so it filled
            # the entire ctx_size with text. 300 chars is plenty for any reasonable description.
            r'str-val    ::= "\"" ([^"\\] | "\\" ["\\/bfnrt]){0,300} "\""',
            # Whitespace must be bounded — `ws` appears ~20× in this grammar and every
            # occurrence is a runaway site. Sampling rolls that prefer space (token 220)
            # were filling the whole context with ' ' until ctx_size hit. 16 chars per
            # span is plenty for any pretty-printing the model wants to do.
            r'ws         ::= [ \t\n\r]{0,16}',
            # Per-arg-type rules collected by _arg_rule (per-width uint{N}-arg /
            # int{N}-arg, bytesN-arg, arrdyn-*, arr-*-N, …). Referenced by name from
            # the call rules above so repetitions never multiply an inline expression.
            *[f'{name} ::= {body}' for name, body in aux_rules.items()],
        ]
        return "\n".join(lines)

    @classmethod
    def _fallback_grammar(cls, max_calls_per_item: int = 10, max_items_per_request: int = 1) -> str:
        """Generic grammar used before set_abi() is called."""
        return cls._build_gbnf([], max_calls_per_item=max_calls_per_item, max_items_per_request=max_items_per_request)

    # ── Grammar self-test ──────────────────────────────────────────────────────

    def _grammar_is_active(self, grammar: str) -> bool | None:
        """Probe whether the server actually APPLIED `grammar`, or silently
        rejected it and is sampling freely.

        llama-server returns HTTP 200 with no error field when a grammar fails to
        parse — the only client-visible signal is that output is unconstrained.
        We exploit the fact that our `root` rule forces `[` as the first non-ws
        token: send a tiny deterministic (temp 0) request whose prompt would NOT
        free-sample to `[`, and check the first char. cache_prompt is off so this
        throwaway probe never pollutes the real prompt cache.

        Returns True (active) / False (rejected) / None (probe failed, unknown).
        """
        body = {
            "prompt": self._template.format(system="You output JSON.", user="ping"),
            "n_predict": 4,
            "grammar": grammar,
            "temperature": 0,
            "cache_prompt": False,
        }
        req = urllib.request.Request(
            self._url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            ctx = _SSL_NO_VERIFY if self._url.startswith("https") else None
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                data = json.loads(resp.read())
        except Exception as exc:  # noqa: BLE001 — probe is best-effort
            logger.debug("llama-cpp grammar probe failed (skipping check): %s", exc)
            return None
        return data.get("content", "").lstrip().startswith("[")

    def _ensure_grammar_active(self) -> None:
        """Validate the current grammar once (per distinct grammar string). On a
        confirmed rejection, degrade to the generic fallback grammar so output is
        at least shape-constrained instead of fully free, and log loudly."""
        grammar = self._grammar
        if grammar in self._validated_grammars:
            return
        active = self._grammar_is_active(grammar)
        if active is None:
            return  # couldn't determine — don't mark validated, retry next call
        self._validated_grammars.add(grammar)
        if active:
            self._grammar_degraded = False
            return
        # Rejected: fall back to the always-parseable generic grammar.
        fallback = self._fallback_grammar(self._mcpi, self._mipr)
        self._grammar = fallback
        self._validated_grammars.add(fallback)
        self._grammar_degraded = True
        logger.error(
            "llama-cpp: the ABI-constrained GBNF grammar was REJECTED by the server "
            "(silent parse failure — check the server log for 'failed to parse grammar'). "
            "Falling back to a generic JSON-shape grammar: output will be valid-JSON "
            "but NOT constrained to real ABI function names. This usually means the "
            "grammar hit llama.cpp's repetition-expansion limit for an unusually large "
            "or array-heavy ABI."
        )

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def complete(self, system: str, user: str, max_tokens: int = 4096,
                 temperature: float | None = 0.7,
                 cache_prefix: str | None = None) -> str:
        # cache_prefix is ignored: llama-cpp caches implicitly via the warm
        # shared prefix (cache_prompt:true below), so no explicit breakpoint is
        # needed. The context still leads the prompt, so that reuse happens.
        del cache_prefix
        # One-time self-test: confirm the server actually applied this grammar.
        # Degrades to a generic grammar + logs loudly if it was silently rejected.
        self._ensure_grammar_active()
        prompt = self._template.format(system=system, user=user)
        body: dict = {
            "prompt": prompt,
            "n_predict": max_tokens,
            "grammar": self._grammar,
            "cache_prompt": True,
            # Belt-and-suspenders: even with the bounded grammar, give the server an
            # explicit ChatML end-of-turn stop. Stops sampling immediately if the model
            # naturally emits <|im_end|> after closing the JSON array.
            "stop": ["<|im_end|>"],
        }
        if temperature is not None:        # None → omit, server samples at its default (~0.8)
            body["temperature"] = temperature
        payload = json.dumps(body).encode()

        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            ctx = _SSL_NO_VERIFY if self._url.startswith("https") else None
            with urllib.request.urlopen(req, timeout=None, context=ctx) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"llama-cpp unreachable at {self._url}: {exc}") from exc

        try:
            content = data["content"].strip()
        except KeyError as exc:
            raise RuntimeError(f"Unexpected llama-cpp response: {data}") from exc

        # tokens_evaluated = total prompt size the server saw (constant whether cache_prompt is on or off)
        # tokens_cached    = total KV cache occupancy after request — NOT cache hits, do not add
        # timings.prompt_n = newly-computed tokens (drops to ~1 on cache hits; reflects compute work, not logical input)
        timings  = data.get("timings", {})
        in_tok   = data.get("tokens_evaluated", 0)
        out_tok  = data.get("tokens_predicted", 0)
        wall_ms  = timings.get("prompt_ms", 0.0) + timings.get("predicted_ms", 0.0)
        hit_limit     = data.get("stop_type") == "limit"

        self._stats.requests     += 1
        self._stats.input_tokens  += in_tok
        self._stats.output_tokens += out_tok
        self._stats.total_ms      += wall_ms
        self._stats.max_tokens = max_tokens
        if hit_limit:
            self._stats.truncated += 1

        logger.info(
            "llama-cpp request #%d: in=%d out=%d/%d tokens%s | %.0f ms (%.1f tok/s)",
            self._stats.requests, in_tok, out_tok, max_tokens,
            " [HIT LIMIT]" if hit_limit else "",
            wall_ms, (out_tok / wall_ms * 1000) if wall_ms else 0,
        )

        if hit_limit:
            raise RuntimeError(
                f"llama-cpp hit n_predict limit ({max_tokens} tokens) — "
                "output is truncated JSON. Increase max_tokens."
            )

        return content
