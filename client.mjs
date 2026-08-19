// The participant half of the seqcj protocol.
//
// This module is deliberately WALLET-AGNOSTIC and ISOMORPHIC: it contains the round protocol and
// nothing else — no key handling, no coin selection, no transaction building. Everything that needs
// a wallet arrives as a hook. That is what lets the browser wallet and the regtest harness run the
// SAME protocol code, so a round proven end-to-end in the test is the round the wallet performs.
//
// The hooks (all may be async):
//
//   fetchJson(path, body?)        -> talk to the coordinator (GET when body is omitted)
//   selectInputs({ asset, denom, coordFee, maxCredentials })
//                                 -> { inputs: [{txid, vout, atoms, ...}], atoms }  transparent coins
//   proveOwnership(message, input)-> { pubkey, sig }   ECDSA/SHA-256, DER hex, over `message`
//   freshAddress()                -> a CONFIDENTIAL (blinded) address, unused
//   verifyAndSign(txHex, context) -> signed tx hex, or throw
//   onStatus(phase, detail)       -> progress, optional
//   sleep(ms)                     -> optional (tests make it instant)
//
// THE RULE THAT MATTERS. `verifyAndSign` is the last gate before a signature exists, and it is the
// participant's ONLY protection against a dishonest coordinator. It must check, against the wallet's
// own view and not against anything this module says, that the transaction pays the participant what
// the round promised. This module cannot check it for you: it never sees a key, a blinding factor or
// a balance. It refuses to proceed if the hook is missing rather than defaulting to "sign it".

import { blind, unblind } from './blindsig.mjs';

const DEFAULT_SLEEP = (ms) => new Promise((r) => setTimeout(r, ms));

function need(hooks, name) {
  const fn = hooks[name];
  if (typeof fn !== 'function') throw new Error('coinjoin client needs a ' + name + ' hook');
  return fn;
}

// Pick the round and lane to join. `assetId` is required — a mix is per asset, and guessing one for
// the user would be picking which of their holdings to move.
export async function chooseRound(hooks, assetId) {
  const fetchJson = need(hooks, 'fetchJson');
  const { rounds } = await fetchJson('/rounds');
  const open = (rounds || []).filter((r) => r.phase === 'input');
  for (const r of open) {
    const lane = r.lanes.find((l) => l.asset === assetId);
    if (lane) return { round: r, lane };
  }
  return null;
}

// One full round, from registration to broadcast. Returns { txid, denominations, change }.
export async function runRound({ hooks, assetId, maxCredentials }) {
  const fetchJson = need(hooks, 'fetchJson');
  const selectInputs = need(hooks, 'selectInputs');
  const proveOwnership = need(hooks, 'proveOwnership');
  const freshAddress = need(hooks, 'freshAddress');
  const verifyAndSign = need(hooks, 'verifyAndSign');
  const status = hooks.onStatus || (() => {});
  const sleep = hooks.sleep || DEFAULT_SLEEP;

  const found = await chooseRound(hooks, assetId);
  if (!found) throw new Error('no open round is mixing that asset right now');
  const { round, lane } = found;
  const denom = BigInt(lane.denom_atoms), coordFee = BigInt(lane.coord_fee_atoms || '0');
  const cap = Math.min(maxCredentials || round.max_credentials, round.max_credentials);
  status('selecting', { round: round.round_id, lane: lane.label });

  // ---- 1. coins ------------------------------------------------------------
  const sel = await selectInputs({ asset: assetId, denom, coordFee, maxCredentials: cap });
  const inputs = sel.inputs || [];
  if (!inputs.length) throw new Error('no transparent coins of that asset to mix');
  const total = inputs.reduce((s, i) => s + BigInt(i.atoms), 0n);
  const k = Number(total / (denom + coordFee)) > cap ? cap : Number(total / (denom + coordFee));
  if (k < 1) throw new Error(`need at least ${denom + coordFee} atoms to mix one denomination; have ${total}`);
  const change = total - BigInt(k) * (denom + coordFee);

  // ---- 2. blind k nonces ---------------------------------------------------
  // Kept material (nonce + blinding factor) never leaves this scope until phase two. If the tab dies
  // here the round simply fails: no coins have moved, and none can — nothing has been signed.
  const kept = [];
  for (let i = 0; i < k; i++) kept.push(await blind(lane.blind_key));

  // ---- 3. input registration (identified) ----------------------------------
  const proofs = [];
  for (const i of inputs) {
    const msg = `seqcj-ownership-v1|${round.round_id}|${i.txid}:${i.vout}`;
    const { pubkey, sig } = await proveOwnership(msg, i);
    proofs.push({ txid: i.txid, vout: i.vout, pubkey, sig });
  }
  const changeAddress = change > 0n ? await freshAddress() : undefined;
  status('registering-inputs', { inputs: inputs.length, denominations: k, change: change.toString() });
  const reg = await fetchJson('/register-input', {
    round_id: round.round_id,
    lane: lane.index,
    inputs: proofs,
    credentials: kept.map((x) => x.blinded),
    ...(changeAddress ? { change_address: changeAddress } : {}),
  });
  const credentials = [];
  for (let i = 0; i < kept.length; i++) {
    credentials.push(await unblind(lane.blind_key, reg.blind_sigs[i], kept[i]));
  }

  // ---- 4. output registration (anonymous) ----------------------------------
  // Wait for the phase to turn over, then present the credentials. Two things are deliberate here:
  // the addresses are drawn ONLY now (so nothing about them existed during input registration), and
  // the registrations are spaced by a random delay, because submitting k outputs back to back in the
  // same instant is itself a correlation the coordinator could read. Network-level unlinkability
  // (a different circuit per registration) is the deployment's job, not this module's — see the
  // wallet's coinjoin.js for what the PoC does and does not achieve.
  await waitForPhase(fetchJson, round.round_id, 'output', sleep, status);
  const mixAddresses = [];
  for (const cred of shuffled(credentials)) {
    const address = await freshAddress();
    mixAddresses.push(address);
    await fetchJson('/register-output', { round_id: round.round_id, credential: cred, address });
    status('registering-outputs', { registered: mixAddresses.length, of: k });
    if (mixAddresses.length < credentials.length) await sleep(200 + Math.floor(Math.random() * 800));
  }

  // ---- 5. verify + sign ----------------------------------------------------
  const signing = await waitForPhase(fetchJson, round.round_id, 'signing', sleep, status);
  status('verifying', { vsize: signing.vsize });
  const signed = await verifyAndSign(signing.tx_hex, {
    round: signing, lane, inputs, denom, k,
    mixAddresses, changeAddress, change,
    expectedCredit: BigInt(k) * denom + change,
  });
  await fetchJson('/sign', { round_id: round.round_id, registration_id: reg.registration_id, tx_hex: signed });
  status('signed', {});

  // ---- 6. outcome ----------------------------------------------------------
  const done = await waitForPhase(fetchJson, round.round_id, 'done', sleep, status);
  return {
    txid: done.txid,
    denominations: k,
    denom_atoms: denom.toString(),
    change_atoms: change.toString(),
    mix_addresses: mixAddresses,
    change_address: changeAddress || null,
  };
}

function shuffled(a) {
  const out = a.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const r = new Uint32Array(1); crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// Poll until the round reaches `phase`. A round that fails, or vanishes because the coordinator
// retired it, ends the wait with the coordinator's own reason rather than a timeout the user cannot
// act on.
export async function waitForPhase(fetchJson, roundId, phase, sleep, status = () => {}, timeoutMs = 600000) {
  const order = ['input', 'output', 'signing', 'broadcasting', 'done'];
  const target = order.indexOf(phase);
  const until = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < until) {
    let r;
    try { r = (await fetchJson('/round/' + roundId)).round; }
    catch (e) { throw new Error('round ' + roundId + ' is no longer available: ' + e.message); }
    if (r.phase === 'failed') throw new Error('round failed: ' + (r.error || 'no reason given'));
    if (r.phase !== last) { status('waiting', { phase: r.phase }); last = r.phase; }
    if (order.indexOf(r.phase) >= target) return r;
    await sleep(1000);
  }
  throw new Error('timed out waiting for the round to reach ' + phase);
}
