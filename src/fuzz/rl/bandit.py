"""Exhaustion-Switching Bandit selector (Option C — `sscfuzz-esb`).

`BanditController` is a drop-in for `RLController` behind the loop's polymorphic
selector seam (`select_strategy`/`store`/`train_step`/`state_dict`), plus the
`observe_outcome` hook the loop calls every iteration. It encodes — rather than
learns — the non-stationary-bandit policy the RL Iter 7 XAI report proved the DQN
cannot pick up from a <200-iter cold start:

  1. **Warmup** — the orchestrator's round-robin warmup tries every arm equally
     (BanditController's `select_strategy` isn't called during warmup, but
     `observe_outcome` IS — so warmup already banks quick-win bugs by pinning).
  2. **Exploit** — pick the arm with the best RECENT payoff (a per-arm reward
     EWMA) while it keeps finding new branches; a `pinned` arm (one that banked an
     exploit) leads the incumbent race.
  3. **Give up** — after `bandit_giveup` consecutive UNPRODUCTIVE picks of an arm
     (no new branch, no banked exploit) eliminate it (cooldown) and fall to the
     next-best arm. An ε-probe occasionally tries a random other arm; one that
     pays spikes its EWMA and becomes the next incumbent (surprise promotion).

No neural net is built — `store`/`train_step` are no-ops. Arms are indexed by the
loop's compact action-table index (`0..action_dim`), the same integer
`select_strategy` returns and `observe_outcome`/`store` receive.
"""

from __future__ import annotations

import random

from ..config import RLConfig

# Multiplier applied to an eliminated arm's EWMA when it is put on cooldown, so a
# once-dominant arm doesn't instantly re-win the incumbent race the moment its
# cooldown lapses — it has to re-earn its lead via fresh payoff.
_GIVEUP_EWMA_SHRINK = 0.5


class BanditController:
    """Exhaustion-Switching Bandit — same public surface as `RLController`.

    Ignores the encoded `state` entirely; keeps its own per-arm bookkeeping over
    the compact action table (`n_arms == config.action_dim`).
    """

    def __init__(self, config: RLConfig):
        self.config = config
        n = int(config.action_dim)
        self._n_arms = n
        self._alpha = float(config.bandit_ewma_alpha)
        self._epsilon = float(config.bandit_epsilon)
        self._giveup = int(config.bandit_giveup)
        self._cooldown = int(config.bandit_cooldown)

        # Per-arm state.
        self.ewma: list[float] = [0.0] * n          # recency-weighted reward
        self.dry: list[int] = [0] * n               # consecutive unproductive picks
        self.pulls: list[int] = [0] * n             # per-arm pick count
        self.pinned: list[bool] = [False] * n       # banked an exploit → priority incumbent
        # cooldown_until[a] = pulls_total value BEFORE which arm a stays eliminated.
        self.cooldown_until: list[int] = [0] * n
        self.pulls_total: int = 0

        # Telemetry attrs the run-log `learning` block reads (report.py). The
        # bandit has no ε-decay / TD-loss, so epsilon is the fixed probe rate and
        # last_loss stays None; last_q_chosen carries the incumbent EWMA (None on
        # an ε-explore step), mirroring RLController's q_chosen semantics.
        self.epsilon: float = self._epsilon
        self.last_q_chosen: float | None = None
        self.last_loss: float | None = None
        self.step_count: int = 0

    # ── Selection ─────────────────────────────────────────────────────────────
    def select_strategy(
        self,
        state,                              # ignored — kept for signature parity
        valid_actions: list[int] | None = None,
    ) -> int:
        """Return the arm to pull this iteration (see class docstring)."""
        pool = valid_actions if valid_actions is not None else list(range(self._n_arms))
        if not pool:
            self.last_q_chosen = None
            return 0

        # 1) candidates = valid arms not on cooldown (revive all if that empties it).
        candidates = [a for a in pool if self.cooldown_until[a] <= self.pulls_total]
        if not candidates:
            candidates = list(pool)

        # 2) incumbent = argmax EWMA among PINNED candidates if any (a proven
        #    bug-finder leads), else argmax EWMA among all candidates.
        pinned = [a for a in candidates if self.pinned[a]]
        race = pinned if pinned else candidates
        incumbent = max(race, key=lambda a: self.ewma[a])

        # 3) with prob 1−ε return the incumbent; else an ε-probe: a uniform-random
        #    OTHER candidate (unbias / surprise promotion). Only the incumbent
        #    carries a Q estimate.
        others = [a for a in candidates if a != incumbent]
        if others and random.random() < self._epsilon:
            self.last_q_chosen = None
            return random.choice(others)
        self.last_q_chosen = float(self.ewma[incumbent])
        return incumbent

    # ── Outcome hook (called EVERY iter, incl. warmup) ────────────────────────
    def observe_outcome(
        self,
        action_idx: int,
        reward: float,
        found_new: bool,
        banked: bool,
    ) -> None:
        """Fold this iteration's outcome into arm `action_idx`'s bookkeeping.

        `found_new` — the run found a new bytecode branch (progress).
        `banked`    — the run banked a NOVEL exploit path → pin the arm.
        """
        a = action_idx
        if not (0 <= a < self._n_arms):
            return
        self.ewma[a] = self._alpha * reward + (1.0 - self._alpha) * self.ewma[a]
        self.pulls[a] += 1
        self.pulls_total += 1
        self.step_count += 1

        productive = bool(found_new or banked)
        self.dry[a] = 0 if productive else self.dry[a] + 1
        if banked:
            self.pinned[a] = True    # quick-win focus — works during warmup too

        # Exhaustion switch: enough unproductive picks → eliminate the arm. Put it
        # on cooldown, un-pin it, shrink its EWMA (so it can't instantly re-dominate
        # on revival) and reset its dry counter for a fresh chance after revival.
        if self.dry[a] >= self._giveup:
            self.cooldown_until[a] = self.pulls_total + self._cooldown
            self.pinned[a] = False
            self.ewma[a] *= _GIVEUP_EWMA_SHRINK
            self.dry[a] = 0

    # ── No-op learner surface (polymorphism with RLController) ────────────────
    def store(self, *args, **kwargs) -> None:
        return None

    def train_step(self) -> float | None:
        return None

    def save(self, path: str) -> None:
        return None

    def load(self, path: str) -> None:
        return None

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    def state_dict(self) -> dict:
        return {
            "ewma": list(self.ewma),
            "dry": list(self.dry),
            "pulls": list(self.pulls),
            "pinned": list(self.pinned),
            "cooldown_until": list(self.cooldown_until),
            "pulls_total": self.pulls_total,
            "step_count": self.step_count,
        }

    def load_state_dict(self, d: dict) -> None:
        if d.get("ewma") is not None and len(d["ewma"]) == self._n_arms:
            self.ewma = [float(v) for v in d["ewma"]]
            self.dry = [int(v) for v in d.get("dry", self.dry)]
            self.pulls = [int(v) for v in d.get("pulls", self.pulls)]
            self.pinned = [bool(v) for v in d.get("pinned", self.pinned)]
            self.cooldown_until = [int(v) for v in d.get("cooldown_until", self.cooldown_until)]
        self.pulls_total = int(d.get("pulls_total", self.pulls_total))
        self.step_count = int(d.get("step_count", self.step_count))


def make_controller(config: RLConfig):
    """Selector factory — returns the controller for `config.selector`.

    `"bandit"` → `BanditController` (Option C `sscfuzz_esb`); `"linucb"` →
    `ContextualBanditController` (disjoint LinUCB `sscfuzz_cb`, rl/contextual_bandit.py);
    anything else → the `RLController` — the factored shared-per-arm-head DQN for
    `sscfuzz` (`factored_head`), the flat dueling/vanilla DQN for the baselines.
    `config.state_dim` / `action_dim` / `n_global` / `arm_feat` are already synced
    from the encoder + action table by the caller (orchestrator.py) before this runs.
    """
    from .controller import RLController

    selector = getattr(config, "selector", "dqn")
    if selector == "bandit":
        return BanditController(config)
    if selector == "linucb":
        from .contextual_bandit import ContextualBanditController
        return ContextualBanditController(config)
    return RLController(config)
