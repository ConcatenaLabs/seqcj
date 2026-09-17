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

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

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

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
