# path8-relayer — Path8 fork of `solana-foundation/kora`

This repo is **Path8's self-hosted fork** of [Kora](https://github.com/solana-foundation/kora), the Solana Foundation's gasless paymaster + transaction signing infrastructure. We fork (rather than depend on the public crate) so that we can:

1. **Add Path8-specific policy gates** in `kora.toml` — only co-sign txs that route through a Squads V4 vault-tx wrap; only accept fee-token payments to allowed Path8 vault destinations.
2. **Wire Path8's idempotency ledger** directly into Kora's `signTransaction` path, so retries against the same `memo` short-circuit before consuming a fresh blockhash.
3. **Extend the JSON-RPC** with Path8-custom methods (starting with `path8_execute`) that compose the approval-token gate, Kora validation, co-signing, and submission behind a single governed round-trip.
4. **Pin our Solana SDK version** independent of Kora's main branch (Path8 runs SDK 3.x split crates per the HFT playbook; upstream Kora moves on its own cadence).
5. **Audit cadence**: take new upstream changes only when we want them — we don't run unaudited upstream commits in production.

## Branching strategy

- `main` = Path8's integration branch. May diverge from `upstream/main`.
- `upstream/main` is tracked via the `upstream` remote (`git remote add upstream https://github.com/solana-foundation/kora.git`).
- Pull upstream changes deliberately:
  ```bash
  git fetch upstream
  git merge upstream/main         # or: git rebase upstream/main
  ```
- Path8-specific changes live on feature branches (e.g. `path8/squads-policy`, `path8/idempotency-ledger`) and merge into `main` after review.

## Where the Rust client lives

The client that talks to *this* relayer is in `path8-engine`:
`crates/integrations/payments/kora-paymaster/`. It implements `path8_x402_paywall::Paymaster` (cosign-only) and `path8_x402_paywall::Settler` (cosign + submit), pluggable into the x402 paywall hot path and the future `exec-core` `submit()` pipeline.

Wiki page (Path8 vault): `path8/engineering/integrations/kora-paymaster.md`.

## Path8 divergence status

| Area | Status | Notes |
| --- | --- | --- |
| `[path8]` approval config | Implemented | Adds `enabled`, `hmac_secret_env`, `required_for_methods`, `redis_url`, and `jti_key_prefix`. Protected methods deny when the token or JTI store is unavailable. |
| Approval-token verification | Implemented | HS256 token verification, expiry checks, compiled-message canonical hash comparison, and one-shot Redis JTI consumption live in `crates/lib/src/path8.rs`. |
| `path8_execute` RPC | Implemented | First governed execution entrypoint. It requires `approval_token`, then reuses the existing Kora sign-and-send flow. Enable it with `[kora.enabled_methods].path8_execute = true`. |
| Stock signing method protection | Implemented as optional defense | `signTransaction` and `signAndSendTransaction` accept `approval_token` and enforce it when listed in `[path8].required_for_methods`. Governed deployments should disable stock signing methods and expose `path8_execute` only. |
| Squads wrap inner validation | Planned | Stock `require_one_of_programs` supplies the first-layer Squads gate; Path8 still needs inner wrap correctness checks. |
| Memo idempotency ledger | Planned | JTI is one-shot today. Memo-keyed execution idempotency is still a follow-up for replay-safe submit retries. |
| Canonical hash parity | Implemented as golden fixtures | The relayer recomputes the compiled-message canonical hash locally and pins the same cross-repo fixture hash as `path8-engine` (`42d0d2fc...dfc3f34`). A shared crate is still a later cleanup option, but not a Phase B blocker. |

## License

MIT, inherited from upstream. See `LICENSE.md`.

---

The original Kora README follows below in `README.md`.
