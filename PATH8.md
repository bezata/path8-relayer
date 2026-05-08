# path8-relayer — Path8 fork of `solana-foundation/kora`

This repo is **Path8's self-hosted fork** of [Kora](https://github.com/solana-foundation/kora), the Solana Foundation's gasless paymaster + transaction signing infrastructure. We fork (rather than depend on the public crate) so that we can:

1. **Add Path8-specific policy gates** in `kora.toml` — only co-sign txs that route through a Squads V4 vault-tx wrap; only accept fee-token payments to allowed Path8 vault destinations.
2. **Wire Path8's idempotency ledger** directly into Kora's `signTransaction` path, so retries against the same `memo` short-circuit before consuming a fresh blockhash.
3. **Extend the JSON-RPC** with Path8-custom methods (e.g. `path8_quoteFeeInUsdc`, `path8_signWithSquadsCheck`) that compose multiple Kora calls behind a single round-trip.
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

## License

MIT, inherited from upstream. See `LICENSE.md`.

---

The original Kora README follows below in `README.md`.
