"""Configuration dataclasses for the fuzzer."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ForkConfig:
    """Fork-mode settings. When set on FuzzerConfig, the harness uses
    `fork.sol.tpl` and points calls at the live target_address on the forked
    chain instead of redeploying. Used by the DeFiHackLabs dataset.
    """
    chain: str                          # foundry.toml [rpc_endpoints] key
    fork_block: int                     # archive block number
    target_address: str                 # checksummed or lowercased 0x... (calls + oracle)
    # Address whose runtime bytecode actually EXECUTES, used to anchor coverage
    # (on-chain eth_getCode fetch + the debug-arena frame filter). Equals
    # target_address for a normal contract; the IMPLEMENTATION address for an
    # EIP-1967/Etherscan-detected proxy (the delegatecall frame runs the impl's
    # code and is recorded under the impl address, while calls/oracle stay on the
    # proxy target). None → falls back to target_address. See coverage.py.
    code_address: Optional[str] = None
    is_proxy: bool = False              # True → target is a proxy (code_address is the impl)
    # EVM version to build the COVERAGE artifact under, when it must differ from the
    # (modern) EVM the harness build uses. Only pre-Constantinople targets need it:
    # their real EVM (e.g. byzantium) can't share a `forge build` invocation with
    # forge-std's constantinople-only `shl`, so compile() does a separate target-only
    # build (--skip test/*) under this EVM to reproduce the deployed dispatcher (SHR
    # vs EXP/DIV). None → the shared build's artifact is already correct (no extra
    # build). Set by scaffold.prepare from the target's solc default. See coverage.py.
    coverage_evm_version: Optional[str] = None
    # Ordered archive RPC URLs for `chain` (best/healthiest first). run_input
    # rewrites the foundry.toml `[rpc_endpoints] <chain>` line to the next entry
    # to rotate off a flaky endpoint when a fork run hits a transient RPC failure.
    # Populated by scaffold.prepare() (the pre-flight health gate reorders it so
    # a live endpoint leads). Empty → no rotation, retry-in-place only.
    rpc_endpoints: list[str] = field(default_factory=list)


@dataclass
class RLConfig:
    state_dim: int = 20     # PLACEHOLDER — overwritten at runtime from the StateEncoder INSTANCE (state_enc.state_dim). `sscfuzz_dqn` uses the PER-ARM layout (factored_head): N_GLOBAL(7) context dims + ARM_FEAT(5) per active arm (G gen + M mut) → 7 + 5·9 = 52 for the 5-gen+4-mut roster (57 with emit_static: global block 7→12). `sscfuzz_cb` uses the CONTEXT layout (selector="linucb"): the global block ONLY = N_GLOBAL(7) + N_STATIC(5 when emit_static) = 12; this is the LinUCB context dim d (an intercept is appended inside the controller → d+1). Block-layout fallback (baselines / esb, per_arm_layout off): coverage(3)+per-active-gen reward(≤7)+per-active-mut reward(≤10, Iter-5)+bug-success trace(G+M, emit_bug_trace)+static(5, emit_static)+revert(1)+dynamic tail(6); gen-only full roster, flags off = 17. See fuzzer/state.py.
    # Full-roster default = 7 generation + 10 mutation strategies = 17. RL Iter 6:
    # orchestrator.py builds a compact per-run ACTION TABLE from the ACTIVE roster
    # (disabled_strategies removed, not masked) and OVERWRITES this from
    # len(_action_table) before the DQN is built — same instance-driven sync as
    # state_dim. So SScFuzz's 8-strategy blocklist → action_dim 9 (5 gen + 4 mut;
    # RL Iter 7 C2 also gates exploration); an empty blocklist → the full 17
    # (ablation). Baselines override action_dim.
    action_dim: int = 17
    hidden_size: int = 128  # bumped from 64 to accommodate the larger state (heat-map)
    lr: float = 1e-3
    gamma: float = 0.99
    epsilon_start: float = 1.0
    epsilon_end: float = 0.1
    # Hyperparameters below are tuned for ~100-iter runs (LLM-bound experiments).
    # See research.md §10 Q8 for the per-regime table. At MAX_ITER=100:
    #   - training starts at iter 8 (batch_size=8) → ~92 train steps in 100 iters
    #   - epsilon reaches epsilon_end (0.1) at step ~45: 1.0 × 0.95^45 ≈ 0.10
    #     → ~55 iterations of exploit after exploration tapers
    #   - target net syncs ~4× per run (every 20 train steps)
    epsilon_decay: float = 0.95
    replay_buffer_size: int = 200
    batch_size: int = 8
    target_sync_every: int = 20
    # Corpus parameters for gen×mut hybrid. Admission is unconditional — every run
    # enters and Group A/B curation decides what survives (no reward pre-filter:
    # a reward=0 run can still be the *leanest* coverer of an existing branch, which
    # is exactly what Group A wants — a reward gate would block those).
    corpus_top_coverage: int = 5        # Group A size (k_cov): AFL-favored minimal coverers
    corpus_top_reward: int = 5          # Group B size (k_bug): weak-signal bug witnesses — heuristic-tier near-misses (RL Iter 7 C6; high-signal exploits excluded, path-gated → no mutation value). Name kept to avoid churn.
    # Effective corpus = Group A (favored coverer) ∪ Group B (bug witnesses),
    # ≤ k_cov + k_bug (10) entries. Seed selection: uniform random over the union.
    # (corpus_top_reward keeps its name to avoid churn; it now sizes Group B.)
    mutation_min_corpus_size: int = 1   # start mutating as soon as 1 seed exists
    # Prioritized Experience Replay (PER). When use_per=True the replay buffer
    # samples transitions ∝ |TD error|^per_alpha instead of uniformly, so rare
    # high-reward events (BUG_SIGNAL, new-branch coverage) replay more often
    # rather than being evicted unseen from the small (200-slot) buffer before a
    # batch ever touches them. Importance-sampling weights (beta, annealed
    # per_beta_start → per_beta_end over per_beta_anneal_steps train steps)
    # correct the bias the non-uniform sampling introduces. New transitions are
    # inserted at max priority so every event trains at least once.
    # Default OFF so the RLFuzz / MADFuzz baselines stay faithful vanilla-DQN
    # reproductions; SScFuzzDefaults turns it on (see profiles.py).
    use_per: bool = False
    # ── RL Iter 2 learner upgrades — gated like use_per ───────────────────────
    # All default OFF so the RLFuzz / MADFuzz baselines stay faithful vanilla-DQN
    # reproductions; SScFuzzDefaults turns all three on (see profiles.py). Making
    # them a clean SScFuzz-only ablation is the point — it's the "we improved the
    # RL algorithm" contribution, measured against the untouched baselines.
    #   dueling         — DQNNetwork factors Q = V(s) + (A(s,a) − mean_a A) so the
    #                     tiny action-to-action differences are learned on top of a
    #                     shared value baseline instead of drowning in it.
    #   double_dqn      — the policy net SELECTS the next action and the target net
    #                     SCORES it, removing vanilla DQN's max-operator overestimation.
    #   normalize_rewards — standardize rewards with a running mean/std before the
    #                     Bellman target so the +2→+50 range doesn't jerk gradients.
    dueling: bool = False
    double_dqn: bool = False
    normalize_rewards: bool = False
    # ── RL Iter 3 levers — also gated like use_per (default OFF = vanilla baselines) ─
    #   softmax_exploration — replace ε-greedy with Boltzmann/softmax over Q, so
    #                     exploration stays alive the whole run (ε bottoms out ~step
    #                     45) and concentrates on plausible actions rather than
    #                     uniform-random ones. `softmax_temperature` scales Q (in the
    #                     reward-normalized units the full method trains on).
    #   n_step          — n-step returns in train_step: an early strategy is linked
    #                     to the reward it eventually causes (a setup call enabling a
    #                     bug a step or two later), not only the next-step reward.
    #                     n_step=1 == vanilla one-step TD.
    softmax_exploration: bool = False
    softmax_temperature: float = 1.0
    n_step: int = 1
    # ── RL Iter 6 un-stick reward multiplier (SScFuzz-only, threaded by
    # orchestrator.py into compute_reward) ────────────────────────────────────
    # Breaking a long coverage plateau pays more than routine early coverage, so
    # the reward stays LIVE and action-differentiated late in the run when raw
    # coverage has flatlined and E[reward|action] would otherwise be ~flat (the
    # exact failure that made softmax-over-Q ≈ uniform). Action-AGNOSTIC: it pays
    # the OUTCOME (un-sticking), not "mutate" by name — the policy learns
    # mut-when-stalled from the gen_stall / seed-pool state dims. Formula on the
    # progress terms (cov + novelty, NOT the bug score):
    #   if progress>0 and stuck_before>=unstick_min:
    #     progress *= 1 + unstick_lambda * min(stuck_before/unstick_scale, 1)
    # compute_reward's OWN defaults leave this OFF (lambda=0) so baselines/tests
    # are unaffected — only orchestrator passes these RLConfig values through.
    unstick_lambda: float = 2.0         # max extra multiple at a fully-saturated plateau (→ up to 3×)
    unstick_min: int = 5                # min stuck_before iters before the bonus engages
    unstick_scale: float = 20.0         # stuck_before value at which the bonus saturates
    # ── RL Iter 7 two-tier coverage reward + Layer-2 bug steering (SScFuzz-only) ─
    # All default OFF / neutral so the RLFuzz / MADFuzz / LLMFuzz baselines keep the
    # legacy unconditional-coverage reward path in compute_reward (they never pass
    # two_tier=True); orchestrator.py threads these into compute_reward / the state
    # encoder for the SScFuzz method only. See fuzzer/reward.py + fuzzer/state.py.
    #   two_tier_cov — replace the single shared coverage term with a two-tier
    #     signal: a small per-strategy base (new-to-THIS-strategy branches, paid
    #     every run = anti-starvation) + a larger GLOBAL-new bonus gated by
    #     (past warmup AND stuck_before≥unstick_min) and amplified by the plateau
    #     multiplier. Kills the front-loaded coverage lottery that starved the
    #     late-arriving vuln strategy. SScFuzzDefaults turns it on.
    two_tier_cov: bool = False
    cov_ps_rate: float = 8.0            # per-strategy base rate (fraction of cov_global_rate)
    cov_global_rate: float = 40.0      # global-new bonus rate (≈ the old _COV_MAX)
    bug_scale: float = 1.0             # scales the path-gated bug score (lower if over-bias appears)
    #   bug_trace — Layer-2 steering: a DECAYING per-active-strategy "proven
    #     bug-finder" trace in the STATE (state.py), so the policy can prefer a
    #     strategy that recently banked a novel exploit AFTER the one-shot bug
    #     reward has evaporated (path-gated → 0 on repeat). Bounded/normalized; the
    #     STATE trace (not the reward magnitude) does the steering, and it FADES
    #     (×bug_trace_decay each round) so it can't tunnel-vision permanently.
    bug_trace: bool = False
    bug_trace_decay: float = 0.9       # ρ<1: recency-trace decay per round (EMA half-life ~7 rounds)
    per_alpha: float = 0.6              # priority exponent (0 = uniform, 1 = full)
    per_beta_start: float = 0.4         # IS-weight strength at step 0
    per_beta_end: float = 1.0           # IS-weight strength once annealed
    per_beta_anneal_steps: int = 100    # train steps to ramp beta_start → beta_end
    per_eps: float = 1e-5               # priority floor so nothing hits p=0
    # ── Selector variant (Option C — SScFuzz strategy-selector ablation) ───────
    # Which selector object the loop builds (rl.make_controller). All default-
    # neutral so `sscfuzz` / baselines are untouched (they never set these).
    #   "dqn"    — the dueling-DQN RLController (RLConfig default; the `sscfuzz_dqn` method).
    #   "bandit" — BanditController (Exhaustion-Switching Bandit, rl/bandit.py):
    #     a non-stationary bandit that warmup-pins quick-win bugs, exploits the
    #     best RECENT-payoff arm while it keeps finding new branches, and after
    #     `bandit_giveup` unproductive picks eliminates that arm (cooldown) and
    #     moves to the next. No neural net. The `sscfuzz_esb` profile selects it.
    #   "linucb" — ContextualBanditController (disjoint LinUCB, rl/contextual_bandit.py):
    #     each arm has its OWN discounted linear model θ_a over the StateEncoder
    #     CONTEXT layout (global block + F1 when emit_static), so F1 routes per-
    #     strategy natively and θ_a transfers across contracts via save/load. No
    #     neural net. The `sscfuzz_cb` profile selects it. Reads linucb_* + emit_static.
    selector: str = "dqn"
    # BanditController knobs (only read when selector == "bandit"):
    #   bandit_epsilon    — prob of an ε-explore probe (pick a uniform-random OTHER
    #                       candidate arm instead of the EWMA-argmax incumbent).
    #   bandit_ewma_alpha — recency weight for the per-arm reward EWMA
    #                       (ewma = α·reward + (1−α)·ewma); higher = more reactive.
    #   bandit_giveup     — consecutive UNPRODUCTIVE picks of an arm (no new branch,
    #                       no banked exploit) before it is eliminated (exhaustion).
    #   bandit_cooldown   — pulls_total to keep an eliminated arm on cooldown before
    #                       it may be revived (with a shrunk EWMA so it doesn't
    #                       instantly re-dominate).
    bandit_epsilon: float = 0.15
    bandit_ewma_alpha: float = 0.5
    bandit_giveup: int = 5
    bandit_cooldown: int = 10
    # ── Contextual bandit (disjoint LinUCB — `sscfuzz_cb`) ─────────────────────
    # emit_static feeds the 5 F1 contract features into the StateEncoder global
    # block (context AND per-arm layouts) — off by default (constant within a
    # single-contract run → dead for a per-contract net; live only ACROSS contracts,
    # which the LinUCB θ_a exploits). The linucb_* knobs are read only when
    # selector == "linucb" (ContextualBanditController). See rl/contextual_bandit.py.
    #   linucb_alpha    — UCB exploration width (p = θᵀx + α·√(xᵀA⁻¹x)); higher = more
    #                     exploration of high-uncertainty arms.
    #   linucb_lambda   — ridge regularization (A_a seeded λI); higher = stronger prior.
    #   linucb_discount — γ per-arm forgetting for non-stationarity (A←γA+xxᵀ+(1−γ)λI);
    #                     γ=1 → plain LinUCB, γ<1 forgets stale evidence (re-explores a
    #                     dried arm). See Garivier & Moulines 2011 / Russac 2019.
    emit_static: bool = False
    linucb_alpha: float = 1.0
    linucb_lambda: float = 1.0
    linucb_discount: float = 0.95
    # ── Per-arm recency/exhaustion tuple features ──────────────────────────────
    # marginal_alpha = the per-arm reward-EWMA (`mrew`) recency weight used by the
    #   StateEncoder per-arm layout (mrew = α·reward + (1−α)·mrew). The `mrew`
    #   (recency) + `dry` (exhaustion) signals are per-arm tuple features of the
    #   factored head. See fuzzer/state.py.
    marginal_alpha: float = 0.5
    # ── Factored shared-per-arm DQN head (the `sscfuzz_dqn` method) ─────────────
    # factored_head — when True (SScFuzzDefaults), the StateEncoder emits the
    #   per-arm layout (N_GLOBAL context dims + one ARM_FEAT tuple per active arm;
    #   see fuzzer/state.py) and DQNNetwork builds the `factored` head: ONE shared
    #   sub-net scores every arm from its own tuple + the global context, so the
    #   learned "pick a rising / not-dried arm" rule is pooled across all arms and
    #   applies to a barely-tried arm immediately (attacks the RQ3a starvation a
    #   flat MLP can't). Default OFF so baselines / the bandit variant are untouched.
    # arm_feat / n_global are SYNCED at runtime from the StateEncoder instance by
    #   orchestrator.py (like state_dim / action_dim); the values below are
    #   placeholders. n_global + action_dim·arm_feat must equal state_dim.
    factored_head: bool = False
    arm_feat: int = 5
    n_global: int = 0


@dataclass
class LLMConfig:
    model: str = "claude-sonnet-4-6"
    # Output (n_predict) cap. A single fuzz-input JSON is ~120-200 tokens, but the
    # MADFuzz seed pool returns a LIST of up to max_items_per_request (=5) items, each
    # up to max_calls_per_item calls + a free-text description — at 2048 the (pretty-
    # printed) array truncated mid-element → invalid JSON (seed-pool gen fell back to
    # an empty pool). 4096 fits the multi-item pool. With ctx_size=16384 this leaves a
    # 12288-token INPUT budget (see max_source_chars); measured worst-case input is
    # ~9.5K tok (Pledge: 80-fn signature table + 24K source + full history), so
    # input(9.5K)+output(4096) ≈ 13.6K stays under 16384 with headroom.
    max_tokens: int = 4096
    # Sampling temperature passed to the backend. 0.7 is a balanced default
    # (some determinism, still explores phrasing). Set to None to omit the
    # parameter from the request entirely → the backend samples at its own
    # default ("random"): llama.cpp ≈0.8, Anthropic API =1.0.
    temperature: Optional[float] = 0.7
    # Run-history depth retained PER strategy (not a global cap). Each prompt
    # renders only the active strategy's slice, so per-call history cost ≈ this
    # many entries (~50 tok each).
    history_window: int = 10
    # Max fuzz-input items the model may return in one response (top-level JSON
    # array size cap). Drives both the GBNF root upper bound and the gen/mut/
    # seed-pool prompt's "return N items" instruction.
    max_items_per_request: int = 1
    # "anthropic"  → direct API (needs ANTHROPIC_API_KEY)
    # "claude-code"→ Agent SDK via local Claude Code CLI (needs `claude` in PATH)
    # "llama-cpp"  → OpenAI-compatible HTTP endpoint (llama.cpp server, Ollama, etc.)
    backend: str = "anthropic"
    # Used by llama-cpp backend. Overridden by --backend-url or LLAMA_CPP_URL env var.
    backend_url: str = "http://localhost:8080/completion"
    # "whitebox" → full source code in prompt (default)
    # "greybox"  → ABI only in prompt (no source)
    approach: str = "whitebox"
    # Cap on contract source bytes embedded in the prompt (whitebox only).
    # Source is first minified (comments + whitespace runs stripped); if still
    # over the cap, the tail is dropped with a `// … [truncated N chars] …`
    # marker. Set 0 to disable the cap.
    #
    # Sizing for 16K-ctx llama-cpp with n_predict=4096 (~4 chars/token):
    #   input budget = 16384 - 4096 = 12288 tokens
    #   fixed scaffolding (system + ChatML + strategy + arg-encoding + special-values)
    #     + full 10-entry history ≈ 1800-2000 tokens
    #   whitebox signature table (UNBUDGETED, scales with #functions) ≈ up to ~900 tok
    #     (Pledge, 80 fns); absorbed within the budget, not capped against this number
    #   available for source ≈ 24000 chars ≈ 6000 tokens
    # Measured worst-case total input across the dataset ≈ 9.5K tok (78% of budget),
    # so 24000 holds with margin. Stage 2 (AST target-extraction) keeps multi-contract
    # giants (Bancor/Pledge) under this cap in live runs; this is the hard fallback.
    max_source_chars: int = 24000
    # Max number of calls per fuzz input (enforced after LLM output and on call_insert)
    max_calls_per_item: int = 12
    # Number of retry attempts on LLM call+parse failure before falling back to ABI defaults.
    # Covers: connection errors, context-window truncation, JSON parse errors, empty responses.
    llm_retries: int = 3


@dataclass
class FuzzerConfig:
    max_iterations: int = 500
    contract_path: str = ""
    contract_name: str = ""
    foundry_project: str = ""
    output_dir: str = "output"
    initial_balance_native: int = 10  # native coin (ETH/BNB/AVAX/FTM by chain) given to every test address
    rl: RLConfig = field(default_factory=RLConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    # When set, switches the harness into fork mode (fork.sol.tpl). The target
    # is NOT redeployed; calls go to fork.target_address on the forked chain.
    fork: Optional[ForkConfig] = None
    # Deploy-time constructor arguments for local (non-fork) targets whose
    # constructor takes parameters. Positional list zipped with the constructor
    # ABI inputs; address-typed args accept the aliases "deployer_address" /
    # "attacker_address" (resolved to the harness EOAs) or a raw 0x… literal.
    # None → synthesize type-default sentinels (the prior behavior). Sourced from
    # a dataset row's `extend.constructor_args`.
    constructor_args: Optional[list] = None
    # Strategy names (generation OR mutation) to GATE OFF for this run. RL Iter 6:
    # orchestrator.py builds the compact `_action_table` from the roster left after
    # this blocklist and HARD-RESIZES `action_dim` to len(_action_table) (disabled
    # strategies are ABSENT from the head, not masked) — so the full-17 roster is
    # one empty-tuple away (baselines / ablation). Empty = all 17 active.
    # SScFuzz sets a blocklist in profiles.py (5 dead mutations + boundary_values
    # folded into arithmetic_probe + arg_address→arg_shuffle). Any name not in the
    # roster is ignored.
    disabled_strategies: tuple[str, ...] = ()
    # Wei sent to a payable constructor at deploy (`new T{value: N}(…)` / the
    # value arg of the legacy assembly `create`). int or 0x/decimal string;
    # None/0 → no value. Sourced from `extend.constructor_value`.
    constructor_value: Optional[object] = None
    # Co-located dependency contracts (defined in the SAME source file as the
    # target) to deploy in setUp() BEFORE the target, each bound to a named var
    # `_depaddr_<name>` that `constructor_args` / `setup_calls` can reference by
    # alias. Each entry: {"contract": <Name>, "name": <alias>, "args": [...]}.
    # Sourced from a dataset row's `extend.pre_deploy`; None/[] → no deps.
    pre_deploy: Optional[list] = None
    # Post-deploy wiring calls issued on the target AFTER deploy via its own public
    # API (e.g. SetLogFile(log)). Each entry: {"fn": <name>, "args": [...]} where
    # args may reference a pre_deploy alias. Sourced from `extend.setup_calls`.
    setup_calls: Optional[list] = None
    # Declared NON-target contracts the fuzzer / LLM may call (fork mode). Each
    # entry: {"var": "WETH", "interface": "IWETH9", "address": "0x…"|null,
    #         "abi": [<minimal ABI of allowed calls>]}. A call whose head is
    # "<var>.<method>" is rendered against that contract; bare heads still go to
    # the main target. The main target stays the ONLY contract the financial-loss
    # oracle's drain / supply-inflation checks apply to. Sourced from a dataset
    # row's `extend.external`; None/[] → target-only (unchanged behavior).
    external: Optional[list] = None
    # Per-sample full Solidity test template (fork mode). When set, the fuzzer
    # loads this complete, self-contained contract and substitutes ONLY the fuzz
    # body (`${calls_code}`) — "you control only the fuzz function". The external
    # interfaces / address constants (+ any hand-added mocks) are baked into the
    # file. Repo-relative path. None → the built-in fork.sol.tpl (external decls
    # injected at runtime from `external`). Sourced from `extend.setup_template`.
    setup_template: Optional[str] = None
    # ── Iteration-level checkpointing (runtime; set by the experiment runner) ──
    # `checkpoint_path` = where to flush/restore the resumable loop state (None →
    # disabled, e.g. the ad-hoc CLI `fuzz` command). `checkpoint_every` = flush
    # cadence in iterations (≤0 → disabled). See fuzz/checkpoint.py.
    checkpoint_path: Optional[str] = None
    checkpoint_every: int = 0
    # `keep_checkpoint` = on CLEAN completion, write a FINAL complete checkpoint at
    # the actual last iteration (not the last periodic flush) and DON'T delete it,
    # so a later higher-`max_iterations` run continues from the true end instead of
    # starting over. Default False = transient crash-recovery only (cleared on
    # completion by the runner). Periodic mid-run flushes are unaffected.
    keep_checkpoint: bool = False
    # ── Cross-contract model transfer (DQN pretraining; set by the experiment
    # runner / CLI) ────────────────────────────────────────────────────────────
    # Distinct from the checkpoint fields above (which resume the FULL learner
    # state — replay, counters — for the SAME contract). These persist only the
    # trained *model* (policy net + optimizer + ε + step_count) so it transfers
    # ACROSS contracts, via RLController.save()/load():
    #   `load_model_path` = warm-start the controller from this .pt at construction
    #       if it exists (net+optimizer+ε+step carry; replay starts fresh). Ignored
    #       by selectors without a net (e.g. the sscfuzz_esb bandit).
    #   `save_model_path` = on CLEAN completion, write the trained model here for
    #       reuse by a later run. Chain them (same path load+save) to pretrain over
    #       a sequence of contracts.
    load_model_path: Optional[str] = None
    save_model_path: Optional[str] = None
    # ε-greedy random input injection. With this probability the LLM is bypassed
    # and a fuzz input is generated by uniform ABI sampling with per-type arg
    # pools (same machinery as rlfuzz). Mitigates the LLM's bias toward
    # semantically-familiar function names — without this gate, sscfuzz never
    # tries lateral functions like withdrawContractETH / borrowExactAmountETH
    # that random selection finds easily. Set epsilon_random_input_start=0
    # to disable (pure-LLM ablation).
    #
    # Tuned for ~100-iter runs (matches RLConfig regime) — see research.md §10 Q8.
    # Per-iteration geometric decay. Schedule at start=0.3, decay=0.95:
    #   - iter   0: ε = 0.30  (30% random — front-loads ABI breadth)
    #   - iter  10: ε = 0.18
    #   - iter  22: ε = 0.10  (reaches floor)
    #   - iter ≥22: ε = 0.10  (held at floor for the remaining ~78 iters)
    # The first quarter of the run does ABI-breadth exploration; the rest
    # leans on the LLM with corpus already populated by random seeds.
    # Conservative start vs the prior 0.5: at 100 iters, less front-loading
    # is needed because the corpus has more time to diversify organically.
    epsilon_random_input_start: float = 0.3
    epsilon_random_input_end:   float = 0.1
    epsilon_random_input_decay: float = 0.95
    # ── RL Iter 7 round-robin warmup (SScFuzz-only; regime-scaled) ─────────────
    # Number of round-robin ROUNDS (full cycles over the active roster) before the
    # DQN takes over selection: warmup_iters = warmup_rounds × active-roster size
    # (e.g. 2 rounds × 9 actions = 18 iters). During those iters the orchestrator
    # cycles the roster round-robin (DQN idle for selection but still storing/
    # learning), evenly populating each strategy's per-strategy coverage `seen` set +
    # the corpus, so the easy early coverage sweep crowns NO lottery winner (the
    # two-tier global bonus is suppressed throughout via compute_reward's in_warmup
    # gate). orchestrator.py bounds warmup_iters by max_iterations so a tiny run is
    # never entirely warmup. Threaded from the per-regime `warmup` knob in
    # profiles.py (_REGIMES); 0 = no warmup (baselines).
    warmup_rounds: int = 0
