"""Comparison baseline implementations (RLFuzz, MADFuzz).

These baselines reuse our project's shared infrastructure:
  - FoundryFuzzer (executor) — `..fuzzer.foundry`
  - compute_reward (reward)  — `..fuzzer.reward`
  - DQNNetwork / ReplayBuffer — `..rl.network`, `..rl.replay_buffer`

Only the *policy* (action space, state encoding, input generation) is method-specific.

Module layout:
  common/   — shared executor loop, function grouping, arg pools, state encoder
  rlfuzz/   — RLFuzz policy (DRQN → 5 function groups + random args)
  madfuzz/  — MADFuzz policy (DRQN → 6 groups + per-type DQN args + LLM seed pool)
"""
