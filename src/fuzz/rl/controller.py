"""DQN-based RL controller for fuzzing strategy selection."""

import random
from collections import deque

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from ..config import RLConfig
from .network import DQNNetwork
from .replay_buffer import PrioritizedReplayBuffer, ReplayBuffer, Transition


class _RunningMeanStd:
    """Online mean/variance (Welford) for reward normalization.

    Rewards span +2 (one branch) → +50 (a banked exploit path), a 25× gap that
    makes the rare high-reward events jerk the gradients. Standardizing rewards
    with a running mean/std before the Bellman target keeps the learning signal
    on a stable scale across that range (RL Iter 2). Bootstrapped next-state Q is
    already on the normalized scale, so the target stays self-consistent.
    """

    def __init__(self) -> None:
        self.mean = 0.0
        self._m2 = 0.0
        self.count = 0

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        # Population std; ~0 until a couple of samples arrive → callers add an eps floor.
        return (self._m2 / self.count) ** 0.5 if self.count > 1 else 0.0


class RLController:
    """Selects fuzzing strategies using a DQN agent."""

    def __init__(self, config: RLConfig):
        self.config = config
        self.epsilon = config.epsilon_start
        self.step_count = 0
        # Learning-process telemetry (read by the loops for the run-log `learning`
        # block): Q of the last chosen action (None on a random-exploration step)
        # and the last TD loss (None until the replay buffer fills). See report.py.
        self.last_q_chosen: float | None = None
        self.last_loss: float | None = None

        dueling = getattr(config, "dueling", False)
        # Factored shared-per-arm head (the per-arm-layout SScFuzz). n_global /
        # arm_feat are synced onto the config from the StateEncoder instance by the
        # orchestrator (same instance-driven pattern as state_dim / action_dim).
        factored = getattr(config, "factored_head", False)
        n_global = getattr(config, "n_global", 0)
        arm_feat = getattr(config, "arm_feat", 0)
        _net = lambda: DQNNetwork(
            config.state_dim, config.action_dim, config.hidden_size,
            dueling=dueling, factored=factored, n_global=n_global, arm_feat=arm_feat)
        self.policy_net = _net()
        self.target_net = _net()
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=config.lr)
        self.double_dqn = getattr(config, "double_dqn", False)
        self.normalize_rewards = getattr(config, "normalize_rewards", False)
        self.softmax_exploration = getattr(config, "softmax_exploration", False)
        self.softmax_temperature = max(1e-3, getattr(config, "softmax_temperature", 1.0))
        self.n_step = max(1, getattr(config, "n_step", 1))
        # Sliding n-step buffer: holds the last n one-step transitions so store()
        # can emit an n-step-return transition into the replay buffer (RL Iter 3).
        self._nstep_buf: deque = deque(maxlen=self.n_step)
        self._reward_rms = _RunningMeanStd()   # reward normalization (RL Iter 2, gated)
        self.use_per = getattr(config, "use_per", False)
        if self.use_per:
            self.replay_buffer = PrioritizedReplayBuffer(
                config.replay_buffer_size,
                alpha=config.per_alpha,
                eps=config.per_eps,
            )
        else:
            self.replay_buffer = ReplayBuffer(config.replay_buffer_size)

    def select_strategy(
        self,
        state: np.ndarray,
        valid_actions: list[int] | None = None,
    ) -> int:
        """Select an action index using ε-greedy policy with optional masking.

        valid_actions — when provided, only these action indices are considered.
        Invalid actions are masked to -inf before argmax so RL never selects them.
        During random exploration the sample is also restricted to valid_actions.
        """
        pool = valid_actions if valid_actions is not None else list(range(self.config.action_dim))

        # ε-greedy path (vanilla / baselines). Softmax exploration replaces this
        # branch entirely (it keeps exploring over the whole run, so no ε floor).
        if not self.softmax_exploration and random.random() < self.epsilon:
            self.last_q_chosen = None   # random exploration — no Q estimate
            return random.choice(pool)

        state_t = torch.FloatTensor(state).unsqueeze(0)
        with torch.no_grad():
            q_values = self.policy_net(state_t).squeeze(0)

        if valid_actions is not None:
            mask = torch.full((self.config.action_dim,), float("-inf"))
            for a in valid_actions:
                mask[a] = 0.0
            q_values = q_values + mask

        if self.softmax_exploration:
            # Boltzmann/softmax over Q (RL Iter 3): sample ∝ exp(Q/temp). Masked
            # actions carry Q=-inf → probability 0. Explores in proportion to
            # estimated value instead of uniform-random, and never bottoms out.
            probs = torch.softmax(q_values / self.softmax_temperature, dim=0)
            probs = torch.nan_to_num(probs, nan=0.0)
            if float(probs.sum()) <= 0.0:
                self.last_q_chosen = None
                return random.choice(pool)
            a = int(torch.multinomial(probs, 1).item())
            self.last_q_chosen = float(q_values[a])
            return a

        a = int(q_values.argmax().item())
        self.last_q_chosen = float(q_values[a])
        return a

    def observe_outcome(self, action_idx: int, reward: float,
                        found_new: bool, banked: bool) -> None:
        """No-op — the DQN learns from stored transitions (store/train_step), not
        this hook. Present so the loop can call `rl.observe_outcome(...)`
        unconditionally regardless of selector; `BanditController` (rl/bandit.py)
        overrides it to fold the outcome into its per-arm bandit bookkeeping."""
        return None

    def store(self, state: np.ndarray, action: int, reward: float,
              next_state: np.ndarray, done: bool) -> None:
        """Store a transition in the replay buffer.

        With n_step=1 this is a plain one-step push. With n_step>1 (RL Iter 3) the
        transition is buffered and, once n one-step transitions have accumulated, an
        n-step-return transition (s_t, a_t, Σ γ^k r_{t+k}, s_{t+n}, done) is emitted
        so credit reaches the strategy that set up a delayed payoff.
        """
        if self.normalize_rewards:
            self._reward_rms.update(reward)   # track reward stats for normalization

        if self.n_step == 1:
            self.replay_buffer.push(Transition(state, action, reward, next_state, done))
            return

        self._nstep_buf.append((state, action, reward, next_state, done))
        if len(self._nstep_buf) == self.n_step:
            self._push_nstep()
        if done:
            # Flush the remaining partial windows at an episode boundary.
            while self._nstep_buf:
                self._push_nstep()
                self._nstep_buf.popleft()

    def _push_nstep(self) -> None:
        """Emit one n-step transition from the head of the sliding buffer."""
        s0, a0, _, _, _ = self._nstep_buf[0]
        ret = 0.0
        next_s = self._nstep_buf[-1][3]
        done_n = False
        for k, (_, _, r_k, ns_k, d_k) in enumerate(self._nstep_buf):
            ret += (self.config.gamma ** k) * r_k
            next_s = ns_k
            if d_k:
                done_n = True
                break
        self.replay_buffer.push(Transition(s0, a0, ret, next_s, done_n))

    def train_step(self) -> float | None:
        """Run one gradient update step. Returns loss or None if not enough data."""
        if len(self.replay_buffer) < self.config.batch_size:
            return None

        if self.use_per:
            batch, indices, is_weights = self.replay_buffer.sample(
                self.config.batch_size, beta=self._per_beta())
            weights_t = torch.FloatTensor(is_weights)
        else:
            batch = self.replay_buffer.sample(self.config.batch_size)

        states = torch.FloatTensor(np.array([t.state for t in batch]))
        actions = torch.LongTensor([t.action for t in batch]).unsqueeze(1)
        rewards = torch.FloatTensor([t.reward for t in batch])
        next_states = torch.FloatTensor(np.array([t.next_state for t in batch]))
        dones = torch.FloatTensor([float(t.done) for t in batch])

        # Reward normalization (RL Iter 2, gated): standardize with running mean/std
        # so the +2→+50 reward range doesn't jerk the gradients. Bootstrapped
        # next-state Q is on the same normalized scale, keeping the Bellman target
        # consistent. Off → baselines keep raw rewards (faithful vanilla DQN).
        if self.normalize_rewards:
            rewards = (rewards - self._reward_rms.mean) / (self._reward_rms.std + 1e-6)

        current_q = self.policy_net(states).gather(1, actions).squeeze(1)

        with torch.no_grad():
            if self.double_dqn:
                # Double DQN (RL Iter 2, gated): the POLICY net selects the next
                # action (argmax) and the TARGET net scores it — decoupling selection
                # from evaluation removes vanilla DQN's max-operator overestimation.
                next_actions = self.policy_net(next_states).argmax(dim=1, keepdim=True)
                max_next_q = self.target_net(next_states).gather(1, next_actions).squeeze(1)
            else:
                # Vanilla DQN: target net both selects and scores (baselines).
                max_next_q = self.target_net(next_states).max(1)[0]
            # n-step returns bootstrap from s_{t+n}, so discount by γ^n (γ^1 when
            # n_step=1). Rewards already hold the discounted n-step sum (see store()).
            bootstrap = self.config.gamma ** self.n_step
            target_q = rewards + bootstrap * max_next_q * (1 - dones)

        td_errors = target_q - current_q
        if self.use_per:
            # IS-weighted MSE; then feed |TD error| back as the new priorities.
            loss = (weights_t * td_errors.pow(2)).mean()
        else:
            loss = nn.MSELoss()(current_q, target_q)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()

        if self.use_per:
            self.replay_buffer.update_priorities(
                indices, td_errors.detach().abs().numpy())

        self.step_count += 1
        self._decay_epsilon()
        self._sync_target()

        self.last_loss = loss.item()
        return self.last_loss

    def _per_beta(self) -> float:
        """Linearly anneal the IS-weight exponent beta_start → beta_end.

        Bias correction matters most late in training (priorities have diverged
        from uniform), so beta ramps up over the run rather than starting at 1.0.
        """
        span = max(1, self.config.per_beta_anneal_steps)
        frac = min(1.0, self.step_count / span)
        return self.config.per_beta_start + frac * (
            self.config.per_beta_end - self.config.per_beta_start)

    def _decay_epsilon(self) -> None:
        self.epsilon = max(
            self.config.epsilon_end,
            self.epsilon * self.config.epsilon_decay,
        )

    def _sync_target(self) -> None:
        if self.step_count % self.config.target_sync_every == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

    def save(self, path: str) -> None:
        torch.save({
            "policy_net": self.policy_net.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "epsilon": self.epsilon,
            "step_count": self.step_count,
        }, path)

    def load(self, path: str) -> None:
        checkpoint = torch.load(path)
        self.policy_net.load_state_dict(checkpoint["policy_net"])
        self.target_net.load_state_dict(checkpoint["policy_net"])
        self.optimizer.load_state_dict(checkpoint["optimizer"])
        self.epsilon = checkpoint["epsilon"]
        self.step_count = checkpoint["step_count"]

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # save()/load() above persist the *trained model* for reuse across contracts;
    # these capture the FULL learner state (incl. replay buffer, n-step buffer,
    # reward normalizer, target net) so an interrupted run resumes learning
    # seamlessly rather than losing the accumulated experience.
    def state_dict(self) -> dict:
        return {
            "policy_net": self.policy_net.state_dict(),
            "target_net": self.target_net.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "epsilon": self.epsilon,
            "step_count": self.step_count,
            "replay_buffer": self.replay_buffer,   # picklable (deque/list of Transitions)
            "nstep_buf": list(self._nstep_buf),
            "reward_rms": (self._reward_rms.mean, self._reward_rms._m2, self._reward_rms.count),
        }

    def load_state_dict(self, d: dict) -> None:
        self.policy_net.load_state_dict(d["policy_net"])
        self.target_net.load_state_dict(d.get("target_net", d["policy_net"]))
        self.optimizer.load_state_dict(d["optimizer"])
        self.epsilon = d["epsilon"]
        self.step_count = d["step_count"]
        if d.get("replay_buffer") is not None:
            self.replay_buffer = d["replay_buffer"]
        self._nstep_buf = deque(d.get("nstep_buf", []), maxlen=self.n_step)
        rms = d.get("reward_rms")
        if rms:
            self._reward_rms.mean, self._reward_rms._m2, self._reward_rms.count = rms
