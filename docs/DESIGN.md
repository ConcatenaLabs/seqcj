# CoinJoin on Sequentia

This is the design note for `seqcj`, its two clients, and the honest threat model of both. It lives
here rather than in the node repository because none of it is consensus: no rule changed, no
soft fork, no new opcode. A CoinJoin is an ordinary transaction that several people happen to sign.

## 1. The problem CT changes

A CoinJoin is many people spending into one transaction so that an observer cannot say which output
belongs to which input. On Bitcoin that is harder than it sounds, and every design is shaped by the
same two facts:

* **amounts are public**, so unequal outputs are re-linked by subset-sum arithmetic. The answer is
  fixed, equal denominations — which everyone can see, count, and use to identify the transaction as
  a mix.
* **change is public**, so the leftover output is a permanent tag pointing back at the owner. Wasabi's
  own documentation treats change as the weak point, and it is.

Sequentia inherits Elements' Confidential Transactions. A round's outputs can be Pedersen commitments
with range proofs, and three things follow:

1. **Change stops being a tag.** It is blinded exactly like a mix output and, on chain, is
   indistinguishable from one.
2. **The denomination stops being public.** Rounds are still fixed-denomination — that is what makes
   a blind-signature credential sound — but only the coordinator learns the number. An observer
   cannot even confirm the transaction is a mix rather than a large payment batch.
3. **Assets mix with each other.** A round may carry several assets at once. Each output's asset is
   hidden inside a surjection proof over the round's whole input set, so "which asset was this
   participant holding" collapses to "one of the ones in this transaction".

The price is size. Measured on this chain: a confidential output costs about **1.2–1.3 kvB** of
proofs, against ~68 vB for a P2WPKH input. A five-participant round with change is ~13.5 kvB. That
is what caps round size, not the protocol — the standard-transaction ceiling is 100 kvB, and a block
holds 89,999 vB.

## 2. Fees, and the one policy rule that shapes everything

Sequentia has an open fee market: a transaction may pay its fee in any accepted asset. But mempool
policy allows **exactly one fee asset per transaction** — `validation.cpp` rejects anything else with
`bad-txns-multiple-fee-assets`, deliberately, because the fee-valuation logic keys on one asset and
an attacker-chosen second one would be valued inconsistently across nodes.

A multi-asset round therefore cannot let each lane pay its own network fee. The design:

* the **coordinator funds the entire network fee** from its own input, in a single fee asset, and
  takes its change blinded like everyone else's;
* participants pay a **coordination fee in the asset they are mixing**, collected as an ordinary
  blinded output.

So someone mixing USDX needs only USDX. That is the open fee market doing exactly the job it exists
for, and it is what makes multi-asset rounds possible at all.

## 3. The round

```
input  ──▶ output ──▶ signing ──▶ broadcast
```

| phase | what happens | what the coordinator learns |
|---|---|---|
| `input` | participants register UTXOs and receive one blind signature per denomination; change is registered in the clear | your coins, your amounts, your change |
| `output` | on a fresh connection, participants present unblinded credentials and name a confidential address each | nothing that identifies you |
| `signing` | the coordinator shuffles, builds, blinds every non-fee output, and publishes; participants verify their own outputs and sign their own inputs | — |
| `done` | the coordinator adds its fee-input signature, combines, broadcasts | — |

**The credential** is a Chaumian RSA blind signature (RSA-FDH, MGF1-SHA256 full-domain hash), one
keypair per round *and lane*. The key is the binding: a credential cannot be replayed into another
round, or presented against a larger denomination, because no other key would verify it. The private
operation goes through OpenSSL with `RSA_NO_PADDING` rather than a hand-rolled `modPow`, so the
signing key is not leaked by timing.

**Ownership proofs.** Registering a UTXO requires an ECDSA signature over a round-bound message with
that coin's own key, checked against the pubkey, which must hash to the coin's witness program.
Without it anyone could register a stranger's coins and stall every round.

**Inputs must be transparent.** Blinding the round needs every input's blinding factors, so accepting
a confidential input would mean asking its owner to hand those to the coordinator — which would
unblind that coin's whole history. Sequentia is transparent by default, so this costs a user nothing:
plain coins in, blinded coins out. That direction is the point.

**Outputs must be confidential.** An explicit one would publish the denomination and hand the chain
back exactly the structure CT removes.

**Assembly integrity.** Participants return their copy of the transaction; the coordinator accepts it
only if the txid matches (the txid commits to every input, output, commitment and script) and merges
with `combinerawtransaction`, which clones `txs[0]` — the coordinator's own copy — and merges only
*input* signature data. A participant cannot substitute output range proofs.

**Failure.** A round with an unredeemed credential is aborted, never published: the coordinator cannot
know whose output is missing, which is the blinding working as intended. Nothing was broadcast, so
nothing was lost. Only the signing phase is attributable, so only the signing phase produces bans.

## 4. What the client must check

The coordinator builds the transaction, so its word for the amounts is worth nothing. Before signing,
a participant unblinds the round with its own SLIP-77 blinding key and refuses unless:

* every mix address it registered is present, for exactly the denomination, in the right asset;
* its change output, if any, is present for exactly the change;
* **no other output of its own appears** — an extra output is not free money, it is a sign the round
  is not the one that was agreed, and very likely a de-anonymising marker;
* every coin it registered is among the inputs.

That check is `verifyRoundOutputs` in `client.mjs`. It lives in the module both wallets vendor, and
is tested here rather than twice, because it is the single function whose failure costs money.

## 5. Bitcoin

Parent-chain BTC cannot be mixed directly — Bitcoin has no confidential transactions, which is the
whole reason this is worth doing here. So BTC is pegged to **SBTC** through the existing bridge,
mixed, and pegged back out to a fresh Bitcoin address.

The residual risk is real and is stated in both clients: the bridge is a custodian for as long as the
coins are pegged, and it sees the Bitcoin going in and the Bitcoin coming out. What the round removes
is its ability to *pair* them — it cannot match a deposit to a withdrawal unless it is the only user
of the round. Seqognito additionally puts the peg-in and peg-out on their own Tor circuit and waits
between them, because two bridge requests seconds apart from one exit pair themselves.

## 6. The threat model, stated plainly

**Hidden from the chain:** every amount and every asset in the round, mix outputs and change alike.

**Hidden from the coordinator:** which of your inputs paid for which of your mix outputs.

**NOT hidden from the coordinator:** your amounts, and the link between your inputs and your change.
This is the standard WabiSabi-style boundary. A coordinator that logs everything still cannot tell
which mixed output is yours.

**Not hidden by the protocol at all:** your network identity. Registering inputs and outputs from one
IP address hands the coordinator the link the blind signature just removed — no cryptography is
broken, a column in an access log is simply read. This is why:

* **Seqognito** (the desktop client) sends the two phases over **different Tor circuits**, rotated
  before use, and has no path to the network that is not Tor;
* **the browser wallet** cannot do that, and says so where a user will read it.

**The anonymity set is the round.** Two participants means two. Both clients let you set a floor;
Seqognito checks it after the round is final, when walking away still costs nothing.

## 7. Live

The coordinator runs on the Sequentia testnet at **`https://sequentiatestnet.com/coinjoin`**, with
three lanes (USDX 10.00, EURX 10.00, BTC 0.001) and the network fee paid by the coordinator in USDX.

First live round, 2026-08-19: transaction
`77f5e1ed48a111baf41ab0d666915cd2b7e8bde168416d9fdd1dd2f1f644197e`, confirmed at height 99691.
Two participants, 3 inputs, 8 outputs, 8.6 kvB. **Exactly one output is explicit — the fee — and the
other seven are commitments**, mix outputs and change alike. Each participant unblinded its own two
denominations and its change and nothing else.

The fee was 5,000 atoms of USDX: an issued asset, not the policy asset, funded entirely by the
coordinator, so neither participant needed to hold anything but the asset they were mixing.

## 8. What is proven, and how

* `test/e2e-round.test.mjs` — three participants, a real `sequentiad` regtest, a full round: 12
  outputs, 13.5 kvB, accepted and broadcast, each participant unblinding exactly its own two
  denominations and its change, the chain showing nothing but commitments and one explicit fee.
* `test/e2e-wasm-participant.test.mjs` — the same, with a participant driven through the wallet's own
  wasm calls (lwk key derivation, `coinjoinUnblindOutputs`, `coinjoinSignInputs`). The Elements
  segwit-v0 sighash cannot be half-right, so "the node accepted it" is the assertion.
* `test/round-rules.test.mjs` — the refusals: confidential inputs, transparent mix outputs, foreign
  credentials, replayed credentials, double registration, banned coins, and a round with an
  unredeemed credential.
* `test/blindsig.test.mjs` — the credential scheme, both directions.
* `test/gate.test.mjs` — ten ways a round could short a participant, and ten refusals.
* Seqognito's `test/gateway.test.mjs` — circuit isolation against a real SOCKS5 server.
