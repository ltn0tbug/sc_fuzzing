"""Disjoint LinUCB contextual-bandit selector (`sscfuzz_cb`).

`ContextualBanditController` is a drop-in for `RLController` behind the loop's
polymorphic selector seam (`select_strategy`/`store`/`train_step`/`observe_outcome`
/`save`/`load`/`state_dict`/`load_state_dict`), plus the telemetry attrs the
run-log `learning` block reads. It selects the fuzzing strategy with **disjoint
LinUCB** (Li et al. 2010) using the StateEncoder CONTEXT layout as the context `x`
(the global-context block + F1 contract features when `emit_static`).

Why a contextual bandit — the RQ3a §7.4(ii)′ answer. The factored DQN collapses to
a contract-agnostic average under cross-contract training (state_space_design.md
§6.1): its arms are anonymous, so F1 in the state can only shift the action-agnostic
value stream, never route "reentrancy-shaped contract ⇒ reentrancy strategy." A
disjoint bandit gives each arm its OWN linear model `θ_a`, so F1 in the (arm-
independent) context routes per-strategy natively, and the per-arm `A_a`/`b_a`
transfer cleanly across contracts via `save`/`load` (unlike the collapsing DQN).

Model (per arm `a`, context dim `d`, intercept appended → `d+1`):
  * `A_a = λ·I` (design matrix), `b_a = 0`.
  * `θ_a = A_a⁻¹ b_a`; UCB score `p_a = θ_aᵀx + α·√(xᵀ A_a⁻¹ x)`.
  * select = argmax `p_a` over the VALID arms only.
  * update (in `store`, every iter incl. warmup) is DISCOUNTED for non-stationarity
    (Garivier & Moulines 2011 / Russac 2019): `A_a ← γ·A_a + xxᵀ + (1−γ)λI`,
    `b_a ← γ·b_a + r·x`. γ=1 → plain LinUCB; γ<1 forgets stale per-arm evidence so a
    strategy that has gone dry loses confidence and the UCB term re-explores it.

Learning happens in `store` (not a separate train step) — it already carries the
selection-time context (`state`), the pulled `action`, and the `reward`, and the
loop calls it every iteration INCLUDING the round-robin warmup, giving balanced
initial data for every arm. `observe_outcome`/`train_step` are no-ops. Arms are
indexed by the loop's compact action-table index (`0..action_dim`).
"""

from __future__ import annotations

import numpy as np

from ..config import RLConfig


class ContextualBanditController:
    """Disjoint LinUCB — same public surface as `RLController`.

    Reads the encoded `state` as the context `x` (an intercept term is appended
    internally); keeps per-arm `A_a`/`b_a` over the compact action table
    (`n_arms == config.action_dim`). `config.state_dim` is the context dim `d`,
    synced from the StateEncoder context layout by the orchestrator.
    """

    def __init__(self, config: RLConfig):
        self.config = config
        self._n_arms = int(config.action_dim)
        # Context dim + 1 for the appended intercept (constant-1) term.
        self._d = int(config.state_dim) + 1
        self._alpha = float(config.linucb_alpha)
        self._lambda = float(config.linucb_lambda)
        self._gamma = float(config.linucb_discount)

        # Per-arm design matrix A_a (d×d, seeded λI) and response vector b_a (d).
        eye = self._lambda * np.eye(self._d, dtype=np.float64)
        self.A: list[np.ndarray] = [eye.copy() for _ in range(self._n_arms)]
        self.b: list[np.ndarray] = [np.zeros(self._d, dtype=np.float64) for _ in range(self._n_arms)]

        # Telemetry attrs the run-log `learning` block reads (report.py). The bandit
        # has no ε-decay / TD-loss, so epsilon is 0 and last_loss stays None;
        # last_q_chosen carries the chosen arm's UCB score (mirrors q_chosen).
        self.epsilon: float = 0.0
        self.last_q_chosen: float | None = None
        self.last_loss: float | None = None
        self.step_count: int = 0

    # ── Context helper ────────────────────────────────────────────────────────
    def _context(self, state) -> np.ndarray:
        """Coerce the encoded state → a (d,) float64 context vector with intercept.

        The last dim is the constant-1 intercept, so `θ_a` can express an
        arm-specific bias independent of the process/contract features.
        """
        x = np.zeros(self._d, dtype=np.float64)
        if state is not None:
            arr = np.asarray(state, dtype=np.float64).ravel()
            k = min(arr.shape[0], self._d - 1)
            x[:k] = arr[:k]
        x[-1] = 1.0
        return x

    # ── Selection ─────────────────────────────────────────────────────────────
    def select_strategy(
        self,
        state,
        valid_actions: list[int] | None = None,
    ) -> int:
        """Return the arm with the highest LinUCB score over the valid arms."""
        pool = valid_actions if valid_actions is not None else list(range(self._n_arms))
        if not pool:
            self.last_q_chosen = None
            return 0
        x = self._context(state)
        best_a = pool[0]
        best_p = -np.inf
        for a in pool:
            if not (0 <= a < self._n_arms):
                continue
            A_inv_x = np.linalg.solve(self.A[a], x)   # A_a⁻¹ x (A symmetric PD)
            mean = float(self.b[a] @ A_inv_x)          # θ_aᵀx = b_aᵀ A_a⁻¹ x
            var = float(x @ A_inv_x)                    # xᵀ A_a⁻¹ x ≥ 0
            p = mean + self._alpha * np.sqrt(max(var, 0.0))
            if p > best_p:
                best_p = p
                best_a = a
        self.last_q_chosen = float(best_p)
        return best_a

    # ── Learning hook — the LinUCB update (called EVERY iter, incl. warmup) ────
    def store(self, state, action: int, reward: float, next_state=None, done: bool = False) -> None:
        """Discounted disjoint-LinUCB update on the pulled arm `action`."""
        a = int(action)
        if not (0 <= a < self._n_arms):
            return
        x = self._context(state)
        g, lam = self._gamma, self._lambda
        # A_a ← γ·A_a + xxᵀ + (1−γ)λI ;  b_a ← γ·b_a + r·x
        self.A[a] = g * self.A[a] + np.outer(x, x) + (1.0 - g) * lam * np.eye(self._d)
        self.b[a] = g * self.b[a] + float(reward) * x
        self.step_count += 1

    # ── No-op learner surface (polymorphism with RLController) ────────────────
    def observe_outcome(self, *args, **kwargs) -> None:
        return None

    def train_step(self) -> float | None:
        return None

    # ── Cross-contract model transfer (the point — persists A_a/b_a) ──────────
    def save(self, path: str) -> None:
        import torch
        torch.save({
            "A": [a.tolist() for a in self.A],
            "b": [v.tolist() for v in self.b],
            "n_arms": self._n_arms,
            "d": self._d,
            "step_count": self.step_count,
        }, path)

    def load(self, path: str) -> None:
        import torch
        ckpt = torch.load(path, weights_only=False)
        # Only adopt persisted matrices when the arm count + context dim match the
        # current roster (a gated-roster / emit_static mismatch → keep fresh λI).
        if int(ckpt.get("n_arms", -1)) == self._n_arms and int(ckpt.get("d", -1)) == self._d:
            self.A = [np.asarray(a, dtype=np.float64) for a in ckpt["A"]]
            self.b = [np.asarray(v, dtype=np.float64) for v in ckpt["b"]]
        self.step_count = int(ckpt.get("step_count", self.step_count))

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    def state_dict(self) -> dict:
        return {
            "A": [a.copy() for a in self.A],
            "b": [v.copy() for v in self.b],
            "step_count": self.step_count,
        }

    def load_state_dict(self, d: dict) -> None:
        A = d.get("A")
        if A is not None and len(A) == self._n_arms and np.asarray(A[0]).shape == (self._d, self._d):
            self.A = [np.asarray(a, dtype=np.float64) for a in A]
            self.b = [np.asarray(v, dtype=np.float64) for v in d.get("b", self.b)]
        self.step_count = int(d.get("step_count", self.step_count))
