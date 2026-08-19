# seqcj

CoinJoin coordinator for Sequentia. Read `README.md` first — it carries the privacy model, and the
privacy model is the product.

## Shape

Zero dependencies, plain ES modules, no build step. Four files:

- `coordinator.mjs` — the service: rounds, registration, assembly, broadcast. One file with a
  `__configureForTest` hook, the same idiom as `sbtc-bridge`.
- `blindsig.mjs` — RSA blind signatures. **Isomorphic**: the browser wallet runs this exact file.
  No `node:` imports, no secret arithmetic (see below).
- `rsakey.mjs` — the coordinator's private half. The RSA private operation goes through OpenSSL
  (`privateDecrypt` with `RSA_NO_PADDING`), never a hand-rolled `modPow`, so the signing key is not
  leaked by timing.
- `client.mjs` — the participant protocol. **Wallet-agnostic**: everything that needs keys, coins or
  a transaction builder arrives as a hook. This is what lets the regtest test and the browser wallet
  run the same protocol code.

## Rules that are easy to break

- **A registration's arithmetic is `sum(inputs) = k*(denom + coord_fee) + change`.** The network fee
  is deliberately absent: the coordinator funds it from its own input, because mempool policy allows
  only one fee asset per transaction and a multi-asset round would otherwise be impossible.
- **Inputs must be transparent.** Blinding the round needs every input's blinding factors; accepting
  a confidential input would mean asking its owner to hand those to the coordinator.
- **Outputs must be confidential.** An explicit output would publish the denomination and hand the
  chain back the equal-value structure CT removes.
- **The lane of a credential is decided by which key verifies it**, never by what the caller says.
- **`combinerawtransaction` must be called with the coordinator's transaction first.** It clones
  `txs[0]` and merges only *input* signature data into it, which is what stops a participant
  substituting output range proofs.
- **A round with an unredeemed credential is aborted.** The coordinator cannot know whose output is
  missing — that is the blinding working — so completing the round is not an option.
- **Bans only ever come from the signing phase.** Earlier phases are not attributable, by design.

## Verification bar

`node --test 'test/**/*.test.mjs'`. The end-to-end test starts a real `sequentiad` regtest and runs a
complete round; if you change assembly, blinding or the fee model, that test is the thing that says
whether it still works. Do not replace it with a mock.

## Repository

Public. Never commit RPC credentials (`config.json` is gitignored). Commit author:
`GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`.
Open a PR and merge it yourself; there is no review process.
