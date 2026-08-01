"""FinanceFuzz financial-property oracle — port of `fuzzer/detectors/`.

Two property families, comparison done in Python (as upstream does):

  * **Invariant (token supply)** — `detectors/invarient/token_balance_detector.py`.
    Checked PER CALL (upstream prepares the detector before each tx and runs it after —
    `execution_trace_analysis.py:142-180`): for each call the sum of token balances over
    the accounts that call changed must be unchanged (a pure transfer moves value
    between accounts; TransferMint / overflow-mint create value → the sum grows). The
    harness emits one `FF_INV <pre> <post>` per call from balances captured around that
    call; a legitimate mint emits a from/to==0 Transfer (excluded), so it never enters a
    changed set — no false positive on mintable ERC20s (the per-sequence bracket did).

  * **Equivalence** — `detectors/equivalence_detector_executor.py` + the four detectors.
    Run T, then a detector-flavored variant T′ from the same initial state, and flag a
    violation when the watched accounts' ETH/token balances differ. Variant
    construction (`build_variants`):
      - TOD          — shuffle txs by sender, preserving per-sender order
                       (`tod_detector.py::final`). *Faithful.*
      - Timestamp    — re-run after `vm.warp` to a random time (`time_dep_detector.py`).
                       *Faithful* (single warp vs upstream per-tx randomization).
      - Reentrancy   — *approx:* arm the unified Attacker to re-enter vs not; a
                       balance difference ⇒ reentrancy-sensitive. (Upstream peels
                       internal txs via `forbid_internal_transactions` — not reproducible
                       on forge.)
      - Gasless send — *approx:* route the value recipient through a gas-guzzling
                       fallback vs a normal EOA; a balance difference with no revert ⇒
                       unchecked send. (Upstream hijacks the CALL opcode gas.)
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

# Equivalence detectors compared directly against the baseline run T (same callers,
# only the flavour differs): tag -> (taxonomy label, severity).
VS_T_DETECTORS: dict[str, tuple[str, str]] = {
    "TOD":     ("Transaction Order Dependency", "Medium"),
    "TIME":    ("Timestamp Dependency", "Medium"),
    "GASLESS": ("Gasless Send", "High"),
}
# Reentrancy is compared as a self-contained armed-vs-unarmed pair (both routed
# through the attacker contract, identical callers) so the only difference is the
# re-entry itself — a balance difference ⇒ reentrancy-sensitive.
REENT_ON, REENT_OFF = "REENT_ON", "REENT_OFF"
REENTRANCY_TYPE = "Reentrancy"
# Fingerprint index of the attacker contract (attacker_address) — see
# execution._accounts_init: [0]=attacker, [1]=reentrancy, [2]=target, …
REENT_ACTOR_IDX = "1"
INVARIANT_TYPE = "TransferMint / Integer Overflow"


@dataclass
class Variant:
    """A detector-flavored T′ to execute. `tag` is the fingerprint label."""
    tag: str
    calls: list                      # harness call-list
    warp: int | None = None          # vm.warp target for the timestamp detector
    gasless_recipient: bool = False  # route value recipient through the gas guzzler
    armed_reentrancy: bool = False    # individual already carries a setReentrantCall


def _reorder_by_sender(calls: list) -> list:
    """TOD variant: reorder transactions while preserving each sender's relative
    order (port of `TODDetector.final`). Upstream interleaves senders randomly; we
    interleave in REVERSE first-appearance order so the result is deterministic and
    guaranteed to differ from T (a random shuffle can coincidentally reproduce the
    original order, which is not a useful T′)."""
    buckets: dict[str, list] = {}
    order: list[str] = []
    for c in calls:
        caller = c[3] if len(c) > 3 else "attacker_address"
        if caller not in buckets:
            buckets[caller] = []
            order.append(caller)
        buckets[caller].append(c)
    senders = list(reversed(order))            # flip which sender leads
    out: list = []
    while senders:
        for s in list(senders):
            out.append(buckets[s].pop(0))
            if not buckets[s]:
                senders.remove(s)
    return out


def build_variants(
    calls: list, *, enabled: set[str] | None = None, warp_seed: int | None = None,
) -> list[Variant]:
    """Construct the enabled detector variants T′ for a sequence T."""
    enabled = enabled or {"TOD", "TIME", "REENTRANCY", "GASLESS"}
    variants: list[Variant] = []

    if "TOD" in enabled and len({c[3] if len(c) > 3 else "attacker_address" for c in calls}) > 1:
        variants.append(Variant("TOD", _reorder_by_sender(calls)))

    if "TIME" in enabled:
        ts = warp_seed if warp_seed is not None else random.randint(1, 2_000_000_000)
        variants.append(Variant("TIME", [list(c) for c in calls], warp=ts))

    if "REENTRANCY" in enabled:
        off, on = _reentrancy_pair(calls)
        if off is not None:
            variants.append(Variant(REENT_OFF, off))
            variants.append(Variant(REENT_ON, on, armed_reentrancy=True))

    if "GASLESS" in enabled and _has_value_call(calls):
        variants.append(Variant("GASLESS", [list(c) for c in calls], gasless_recipient=True))

    return variants


def _reentrancy_pair(calls: list) -> tuple[list | None, list | None]:
    """Build the (unarmed, armed) reentrancy pair. Both route every call through the
    attacker contract (attacker_address) so the caller is identical; the armed run
    additionally prepends a setReentrantCall configuring the attacker to re-enter the
    first call. Comparing the two isolates the re-entry effect (no caller-identity
    confound). Returns (None, None) when there is nothing to route."""
    plain = [c for c in calls if c and c[0] != "atk.setReentrantCall"]
    if not plain:
        return None, None
    rerouted: list = []
    for c in plain:
        nc = list(c)
        if len(nc) > 3:
            nc[3] = "attacker_address"
        rerouted.append(nc)
    fn = plain[0][0]
    args = list(plain[0][1]) if len(plain[0]) > 1 and isinstance(plain[0][1], list) else []
    setup = [
        "atk.setReentrantCall",
        {"reentrant_func": fn, "reentrant_args": args, "max_count": 3},
        "0x0", "attacker_address",
    ]
    return rerouted, [setup] + [list(c) for c in rerouted]


def _has_value_call(calls: list) -> bool:
    for c in calls:
        if c and c[0] != "atk.setReentrantCall" and len(c) > 2 and int(c[2] or 0) > 0:
            return True
    # Even with no value sent in, a withdraw-style call can send ETH out; allow the
    # gasless probe whenever the sequence has any plain call.
    return any(c and c[0] != "atk.setReentrantCall" for c in calls)


# ── Fingerprint parsing + interpretation ──────────────────────────────────────

@dataclass
class Fingerprint:
    """Per-tag balances keyed by account label → (eth_wei, token_bal)."""
    eth: dict[str, int] = field(default_factory=dict)
    tok: dict[str, int] = field(default_factory=dict)
    reverted: bool = False


def parse_fingerprints(decoded_logs: list) -> dict[str, Fingerprint]:
    """Parse `FF_FP`/`FF_FP_TOK`/`FF_REVERT` lines into per-tag fingerprints.

    Line formats (whitespace-separated console.log):
      FF_FP <tag> <label> <eth_wei>
      FF_FP_TOK <tag> <label> <token_bal>
      FF_REVERT <tag>
    """
    fps: dict[str, Fingerprint] = {}
    for raw in decoded_logs:
        line = str(raw).strip()
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "FF_FP":
            fp = fps.setdefault(parts[1], Fingerprint())
            fp.eth[parts[2]] = _to_int(parts[3])
        elif len(parts) >= 4 and parts[0] == "FF_FP_TOK":
            fp = fps.setdefault(parts[1], Fingerprint())
            fp.tok[parts[2]] = _to_int(parts[3])
        elif len(parts) >= 2 and parts[0] == "FF_REVERT":
            fps.setdefault(parts[1], Fingerprint()).reverted = True
    return fps


def parse_block_failures(decoded_logs: list) -> dict[str, set[int]]:
    """Per-block set of call indices that reverted.

    The finance test prints `FF_BLOCK <tag>` before each block; the harness's
    try/catch prints `[<idx>] <label> fail: …` when a call reverts. We attribute
    each fail line to the most recent block. Backs the gasless-send `is_success`
    gate (a checked send reverts under the reject-recipient variant → its fail-set
    differs from T → skip, no false positive)."""
    import re
    fails: dict[str, set[int]] = {}
    current = None
    fail_re = re.compile(r"^\[(\d+)\]\s+.*\bfail\b")
    for raw in decoded_logs:
        line = str(raw).strip()
        if line.startswith("FF_BLOCK "):
            current = line.split(None, 1)[1].strip()
            fails.setdefault(current, set())
            continue
        m = fail_re.match(line)
        if m and current is not None:
            fails[current].add(int(m.group(1)))
    return fails


def parse_invariant(decoded_logs: list) -> list[tuple[int, int]]:
    """Parse the per-call `FF_INV <pre_sum> <post_sum>` lines (sum of token balances
    over THAT call's changed accounts). The T block emits one line per call (upstream
    TokenBalanceDetector runs around each tx); returns one (pre, post) per call, or an
    empty list if absent (non-ERC20 target / no changed accounts)."""
    out: list[tuple[int, int]] = []
    for raw in decoded_logs:
        parts = str(raw).strip().split()
        if len(parts) >= 3 and parts[0] == "FF_INV":
            out.append((_to_int(parts[1]), _to_int(parts[2])))
    return out


def _to_int(s: str) -> int:
    try:
        return int(s, 0) if s.lower().startswith("0x") else int(s)
    except (ValueError, AttributeError):
        return 0


@dataclass
class Violation:
    detector: str          # detector key (TOD/TIME/REENTRANCY/GASLESS/INVARIANT)
    bug_type: str          # FinanceFuzz taxonomy label
    severity: str
    message: str


def interpret(decoded_logs: list) -> list[Violation]:
    """Apply FinanceFuzz's property checks to one individual's forge output."""
    violations: list[Violation] = []

    # Per-call invariant: flag if ANY call's changed-account balance sum grew (a
    # legitimate mint emits a from/to==0 Transfer and is excluded upstream of here,
    # so it never enters a call's changed set — no false positive on mintable ERC20s).
    for pre, post in parse_invariant(decoded_logs):
        if pre != post:
            violations.append(Violation(
                "INVARIANT", INVARIANT_TYPE, "High",
                f"Token balance invariant violated: {pre} != {post}",
            ))
            break

    fps = parse_fingerprints(decoded_logs)
    failures = parse_block_failures(decoded_logs)
    base = fps.get("T")
    if base is not None:
        for tag, (label, severity) in VS_T_DETECTORS.items():
            var = fps.get(tag)
            if var is None or var.reverted:
                continue
            # Gasless `is_success` gate (upstream GaslessSendDetector): only compare
            # when the reject-recipient variant's revert pattern matches T's. A
            # checked send reverts under the variant (different fail-set) → skip.
            if tag == "GASLESS" and failures.get("GASLESS") != failures.get("T", set()):
                continue
            if _balances_differ(base, var):
                violations.append(Violation(
                    tag, label, severity, f"{label} equivalence violated (T != {tag})",
                ))

    # Reentrancy: armed-vs-unarmed pair (identical callers). We require the attacker
    # to *extract more* value when armed (paper §4.2: "withdraw an excess amount"),
    # NOT merely that balances differ. A bare-difference test false-positives on
    # reentrancy-SAFE contracts: e.g. `owner.transfer(...)` (2300-gas, the correct
    # guard) reverts when the armed attacker's fallback tries to re-enter, so the
    # armed run yields LESS — a difference, but the opposite of a vulnerability.
    on, off = fps.get(REENT_ON), fps.get(REENT_OFF)
    if on is not None and off is not None and _attacker_extracted_more(on, off):
        violations.append(Violation(
            "REENTRANCY", REENTRANCY_TYPE, "High", "Reentrancy: armed re-entry extracted excess value",
        ))
    return violations


def _attacker_extracted_more(on: Fingerprint, off: Fingerprint) -> bool:
    """True iff the attacker (attacker_address) ends with strictly more ETH or
    more of any watched token under arming than without — a genuine re-entrant
    drain, as opposed to an arming side effect that yields equal or less."""
    if on.eth.get(REENT_ACTOR_IDX, 0) > off.eth.get(REENT_ACTOR_IDX, 0):
        return True
    return on.tok.get(REENT_ACTOR_IDX, 0) > off.tok.get(REENT_ACTOR_IDX, 0)


def _balances_differ(a: Fingerprint, b: Fingerprint) -> bool:
    # Compare only labels both fingerprints reported. The harness emits the full
    # watched-account set for every tag, so the intersection is the whole set; the
    # guard just keeps partial/truncated logs from producing phantom differences.
    if any(a.eth[k] != b.eth[k] for k in (set(a.eth) & set(b.eth))):
        return True
    return any(a.tok[k] != b.tok[k] for k in (set(a.tok) & set(b.tok)))
