"""DQN neural network.

Two modes, selected by the `dueling` flag (RL Iter 2, gated per-method):

- **Vanilla** (default; the RLFuzz / MADFuzz baselines): a plain 2-hidden-layer
  MLP mapping state → Q(s, ·). This is the faithful reproduction the baselines need.
- **Dueling** (SScFuzz): a shared feature trunk feeds two heads — a scalar
  **value** stream V(s) and a per-action **advantage** stream A(s,a) — recombined
  as Q(s,a) = V(s) + (A(s,a) − mean_a A(s,a)). The mean-subtraction identifies the
  two streams (otherwise V and A are free to shift by a constant).

Why dueling here: in this fuzzer every strategy has *similar* value on most states
(the "lottery-ticket" finding), so the shared baseline V(s) dominates and the
small action-to-action differences the policy must learn are a thin signal on top.
Factoring V out lets the advantage head model those differences directly instead
of re-learning the shared baseline in every Q(s,a). It reduces to a plain head
when advantages are near-constant, so it never hurts.
"""

import torch
import torch.nn as nn


class DQNNetwork(nn.Module):
    """DQN with three head modes. `factored` takes precedence over `dueling`.

    - **factored** (the shared-per-arm-head SScFuzz): the state is `n_global`
      context dims followed by `action_dim` contiguous per-arm tuples of `arm_feat`
      each (the StateEncoder `per_arm_layout`). ONE shared sub-net scores every
      arm from `(arm_tuple ‖ global_context)`, so the rule it learns ("rising
      recent reward + low dryness ⇒ pick me") is pooled across all arms and applies
      to a barely-tried arm immediately — the cross-arm generalization a flat MLP
      cannot do (attacks the RQ3a starvation). A separate value stream over the
      global context recombines dueling-style: Q = V(g) + (A_i − mean_i A).
    - **dueling** / **vanilla**: the original flat heads (below).
    """

    def __init__(self, state_dim: int, action_dim: int, hidden_size: int = 64,
                 dueling: bool = False, factored: bool = False,
                 n_global: int = 0, arm_feat: int = 0):
        super().__init__()
        self.factored = factored
        self.dueling = dueling
        if factored:
            # Shared per-arm advantage sub-net + a global-context value stream.
            self.n_global = n_global
            self.arm_feat = arm_feat
            self.n_arms = action_dim
            if n_global + action_dim * arm_feat != state_dim:
                raise ValueError(
                    f"factored head: n_global({n_global}) + action_dim({action_dim})"
                    f"·arm_feat({arm_feat}) != state_dim({state_dim})"
                )
            self.arm_net = nn.Sequential(
                nn.Linear(arm_feat + n_global, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, hidden_size),
                nn.ReLU(),
            )
            self.arm_advantage = nn.Linear(hidden_size, 1)   # applied per-arm → (B, A, 1)
            self.value_net = nn.Sequential(
                nn.Linear(n_global, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, 1),
            )
        elif not dueling:
            # Vanilla 2-hidden-layer MLP head (baselines).
            self.net = nn.Sequential(
                nn.Linear(state_dim, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, action_dim),
            )
        else:
            # Shared trunk + value/advantage streams (flat dueling SScFuzz).
            self.feature = nn.Sequential(
                nn.Linear(state_dim, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, hidden_size),
                nn.ReLU(),
            )
            self.value_head = nn.Linear(hidden_size, 1)
            self.advantage_head = nn.Linear(hidden_size, action_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.factored:
            b = x.shape[0]
            g = x[:, : self.n_global]                                  # (B, n_global)
            arms = x[:, self.n_global :].reshape(b, self.n_arms, self.arm_feat)  # (B, A, af)
            g_exp = g.unsqueeze(1).expand(b, self.n_arms, self.n_global)         # (B, A, n_global)
            arm_in = torch.cat([arms, g_exp], dim=2)                   # (B, A, af+n_global)
            feat = self.arm_net(arm_in)                                # (B, A, H) — shared weights
            advantage = self.arm_advantage(feat).squeeze(-1)           # (B, A)
            value = self.value_net(g)                                  # (B, 1)
            return value + (advantage - advantage.mean(dim=1, keepdim=True))
        if not self.dueling:
            return self.net(x)
        feat = self.feature(x)
        value = self.value_head(feat)                     # (B, 1)
        advantage = self.advantage_head(feat)             # (B, A)
        # Q = V + (A − mean_a A); mean over the action dim keeps the streams identifiable.
        return value + (advantage - advantage.mean(dim=1, keepdim=True))
