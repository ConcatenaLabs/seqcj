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

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as**
`GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`.
Never a personal address.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
