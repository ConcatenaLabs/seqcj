# seqcj — a CoinJoin coordinator for Sequentia

A CoinJoin round is many people spending coins into one transaction so that nobody outside can say
which output belongs to which input. This coordinator runs those rounds on Sequentia, where the
outputs are **confidential**: the chain records commitments, not amounts.

It is not custodial. Coins move once, in a transaction every participant has verified and signed
themselves. A round that goes wrong never broadcasts.

```
                 blind signature                        confidential outputs
participant ──── input registration ──┐          ┌──── output registration (anonymous)
                                      ▼          ▼
                              ┌──────────────────────────┐
                              │  seqcj coordinator       │ ──▶ one CoinJoin transaction
                              │  (holds nothing)         │      every non-fee output blinded
                              └──────────────────────────┘
```

## What Confidential Transactions change

On Bitcoin, a CoinJoin is only as private as its **equal-value denominations**. Amounts are public,
so unequal outputs get re-linked by subset-sum arithmetic, and the change output is a permanent tag
tying the mix back to its owner. Every Bitcoin CoinJoin design is shaped around that problem.

Sequentia inherits Elements' Confidential Transactions, so a round's outputs can be Pedersen
commitments with range proofs. Three consequences:

* **Change stops being a tag.** It is blinded exactly like a mix output, and to an observer the two
  are indistinguishable. The heuristic that unwinds Bitcoin CoinJoins has nothing to read.
* **The denomination stops being public.** Rounds are still fixed-denomination — that is what makes
  a blind-signature credential sound — but only the coordinator ever learns the number.
* **Assets mix with each other.** A round may carry several assets at once. Each output's asset is
  hidden inside a surjection proof over the round's whole input set, so "which asset was this
  participant holding" collapses to "one of the ones in this transaction".

The cost is size: a confidential output is about 1.3 kvB of proofs, against ~68 vB for an input.
That is what caps round size, not the protocol.

## Fees, and why the coordinator pays them

Sequentia has an open fee market — a transaction may pay its fee in any accepted asset — but mempool
policy allows exactly **one fee asset per transaction**. A multi-asset round therefore cannot let
each lane pay its own network fee.

So the coordinator funds the entire network fee from its own input, in one fee asset, and charges
participants a coordination fee **in the asset they are mixing**, collected as an ordinary blinded
output. Someone mixing USDX needs only USDX. That is the open fee market doing the job it exists for.

## The round

| phase | what happens | who can be linked to whom |
|---|---|---|
| `input` | register UTXOs (transparent, one asset, ownership-proved); receive one blind signature per denomination; register change in the clear | the coordinator sees your coins and your change |
| `output` | on a fresh connection, present unblinded credentials and name a confidential address each | nothing identifies you |
| `signing` | the coordinator shuffles, builds, blinds and publishes the transaction; you verify your own outputs and sign your own inputs | — |
| `done` | the coordinator adds its fee-input signature, combines and broadcasts | — |

The credential is a Chaumian RSA blind signature (`blindsig.mjs`), one keypair per round and lane —
so a credential cannot be replayed into another round, or presented against a larger denomination.
The binding is the key itself, not a claim in a message.

## What this does and does not hide

**Hidden from the chain:** every amount and every asset in the round, mix outputs and change alike.
An observer sees a transaction with N inputs and M commitments and one explicit fee.

**Hidden from the coordinator:** which of your inputs paid for which of your mix outputs. That is
what the blind signatures buy, and it is the only thing they buy.

**Not hidden from the coordinator:** your amounts (it must check the round balances), and the link
between your inputs and your *change*. This is the standard WabiSabi-style trust boundary.

**Not hidden by this software at all:** your network identity. Registering inputs and outputs from
the same IP address hands the coordinator the link the blind signature just removed. A deployment
that means it routes the two phases over separate circuits. The browser PoC does not, and says so.

**The anonymity set is the round, and nothing else.** Two participants means an anonymity set of two.

## Running it

```sh
cp config.example.json config.json     # then fill in the node RPC, the fee asset and the lanes
node coordinator.mjs
```

The HTTP API is public by design — anyone should be able to join a round:

| | |
|---|---|
| `GET /status` | service info, the BTC lane, recent rounds |
| `GET /rounds` | open rounds, their lanes, denominations and blind-signing keys |
| `GET /round/:id` | phase, deadline, and the transaction once signing starts |
| `POST /register-input` | outpoints + ownership proofs + blinded credentials → blind signatures |
| `POST /register-output` | a credential + a confidential address |
| `POST /sign` | the participant's copy of the round transaction, signed |

## Bitcoin

Parent-chain BTC joins a round as **SBTC**, through the existing peg
([sbtc-bridge](https://github.com/GracedEternalKingCabbageMan/sbtc-bridge)): peg in before the round,
mix, peg out to a fresh Bitcoin address after. The coordinator never touches those funds — it only
publishes, in `/status`, which lane is the BTC-backed one and where the bridge lives, and the wallet
does the peg itself.

This is worth being blunt about: the bridge sees the BTC that goes in and the BTC that comes out. The
mix breaks the link **on Sequentia**, so the bridge cannot pair a deposit with a withdrawal unless it
is the only user of the round. It is not a substitute for the peg being a trusted custodian.

## The clients

| | |
|---|---|
| [Seqognito](https://github.com/GracedEternalKingCabbageMan/seqognito) | the desktop mixing wallet (Windows, Linux). Sends input registration and output registration over **different Tor circuits**, which is the one thing a browser cannot do and the reason it exists. |
| [sequentia-web-wallet](https://github.com/GracedEternalKingCabbageMan/sequentia-web-wallet) | the browser wallet's Mix tab. Runs the identical protocol, and says plainly that it cannot separate the two connections. |

Both vendor `blindsig.mjs` and `client.mjs` from here byte-identically, so the protocol they run is
the one the end-to-end test proves.

The full design note, including the fee model, the assembly-integrity argument and the threat model,
is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Tests

```sh
node --test 'test/**/*.test.mjs'
```

`test/e2e-round.test.mjs` starts a real `sequentiad` regtest, funds three participants, and runs a
complete round through the same client module the browser wallet uses — then checks that each
participant can unblind exactly its own outputs and that the chain shows nothing but commitments. It
skips if no daemon binary is present.

## Repository

Public, MIT. Commits are authored as
`GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`.
Never commit RPC credentials — `config.json` is gitignored for that reason.
