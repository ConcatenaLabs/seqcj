// seqcj — a CoinJoin coordinator for Sequentia.
//
// WHAT MAKES THIS DIFFERENT FROM A BITCOIN COINJOIN
//
// On Bitcoin every output amount is public, so a join is only as private as its equal-value
// denominations: unequal outputs are re-linked by subset-sum, and the change output is a permanent
// tag. Sequentia inherits Elements' Confidential Transactions, so the join's outputs can be
// COMMITMENTS — the chain sees that a transaction happened and nothing about how much moved, or
// (across a multi-asset round) in which asset. Three things follow, and they are the reason this
// coordinator exists:
//
//   * the change output stops being a tag. It is blinded like every mix output and, to an observer,
//     indistinguishable from one. Wasabi's change-detection heuristic has nothing to bite on.
//   * the denomination stops being public. Round sizing is still fixed-denomination — that is what
//     makes the blind-signature credential sound — but only the coordinator ever learns the number.
//   * assets mix with each other. A round may carry several assets at once; each output's asset is
//     hidden inside the surjection proof over the round's whole input set, so "which asset did this
//     participant hold" is answered only by "one of the ones in this transaction".
//
// The coordinator never holds user funds. It sees amounts (it must, to check the round balances) and
// it can link a participant's inputs to their change, exactly as a ZeroLink / Wasabi 1.0 (Chaumian
// CoinJoin) coordinator can; WabiSabi-style amount credentials would hide that link too, and are not
// implemented here. What it cannot do — and what the blind signatures buy — is link a participant's
// inputs to their MIX outputs. What the chain cannot do is see any of it. The honest threat model is
// in docs/DESIGN.md §6; read it before believing anything stronger.
//
// THE ROUND
//
//   input  ──▶ output ──▶ signing ──▶ broadcast
//
//   input   participants register UTXOs (transparent, one asset, ownership-proved) and receive one
//           blind signature per denomination they are entitled to, plus a change output registered
//           in the clear (the coordinator already knows it is theirs).
//   output  on a fresh connection, participants present unblinded credentials and name a
//           CONFIDENTIAL address per denomination. Nothing here identifies them.
//   signing the coordinator shuffles, builds the transaction, blinds every non-fee output, and
//           publishes it. Participants verify their own outputs, sign their own inputs, and submit.
//   done    the coordinator adds its own signature (it funds the network fee), combines and
//           broadcasts.
//
// FEES, AND WHY THE COORDINATOR PAYS THEM
//
// Sequentia has an open fee market — a transaction may pay its fee in any accepted asset — but
// mempool policy allows exactly ONE fee asset per transaction (validation.cpp, "bad-txns-multiple-fee
// -assets"). A multi-asset round therefore cannot let each lane pay its own network fee. So the
// coordinator funds the whole network fee from its own input in a single fee asset, and charges each
// participant a coordination fee in the asset THEY are mixing, collected as an ordinary (blinded)
// output. Participants never need to hold the fee asset, which is the open fee market doing exactly
// what it is for.
//
// FUND SAFETY. There is no custody to get wrong: every participant signs a transaction they have
// verified, and a round that fails simply never broadcasts. The two failure modes that matter are
// (a) signing something you did not check — which is the CLIENT's job, and the client is built to
// refuse (see the wallet's coinjoin.js), and (b) a coordinator that stalls a round to grief users,
// which costs them time and nothing else.

import http from 'node:http';
import { createHash, randomBytes, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { newRoundKey, signBlinded } from './rsakey.mjs';
import { verify as verifyCredential } from './blindsig.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CFG_PATH = process.env.SEQCJ_CONFIG || join(HERE, 'config.json');
const STATE_PATH = process.env.SEQCJ_STATE || join(HERE, 'state.json');

const log = (...a) => console.log(new Date().toISOString(), '[seqcj]', ...a);
const err = (...a) => console.error(new Date().toISOString(), '[seqcj]', ...a);

// ---- runtime context --------------------------------------------------------
// Set by main() from config.json, or by __configureForTest(). Nothing here has import-time side
// effects, so the round logic can be unit-tested against a mock node with no config and no server.
let CFG = null;
let seqrpc = null;
let ROUNDS = new Map();          // round_id -> round (in memory: a round holds no funds, so a
                                 // restart just aborts what was in flight; nothing is at risk)
let STATE = { bans: {}, history: [] };
let saveState = () => {};

// ---- JSON-RPC ---------------------------------------------------------------
// Node's fetch refuses credentials embedded in the URL, so they move to an Authorization header.
async function rpc(url, method, params = [], wallet) {
  const u = new URL(url);
  const auth = (u.username || u.password)
    ? 'Basic ' + Buffer.from(decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password)).toString('base64')
    : null;
  u.username = ''; u.password = '';
  const clean = u.toString().replace(/\/$/, '');
  const base = wallet ? clean + '/wallet/' + encodeURIComponent(wallet) : clean;
  const headers = { 'content-type': 'application/json' };
  if (auth) headers.authorization = auth;
  const res = await fetch(base, {
    method: 'POST', headers,
    body: JSON.stringify({ jsonrpc: '1.0', id: 'seqcj', method, params }),
    signal: AbortSignal.timeout(60000),         // blinding a large round is CPU-bound on the node
  });
  const j = await res.json().catch(() => ({ error: { message: 'bad json (HTTP ' + res.status + ')' } }));
  if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
  return j.result;
}

// ---- amounts ----------------------------------------------------------------
// Atoms are BigInt everywhere and only become decimal strings at the RPC boundary. Elements amounts
// are always 8dp on the wire regardless of an asset's display precision, and a float round-trip at
// 1e8 loses atoms, which shows up as an unbalanced transaction hours later.
export function fmt8(atoms) {
  const a = BigInt(atoms);
  if (a < 0n) throw new Error('negative amount');
  const s = a.toString().padStart(9, '0');
  return s.slice(0, -8) + '.' + s.slice(-8);
}
export function parse8(str) {
  const m = /^(\d+)(?:\.(\d{0,8}))?$/.exec(String(str).trim());
  if (!m) throw new Error('bad amount: ' + str);
  return BigInt(m[1]) * 100000000n + BigInt((m[2] || '').padEnd(8, '0') || '0');
}
const hash160 = (buf) => createHash('ripemd160').update(createHash('sha256').update(buf).digest()).digest();

// ---- ownership proof --------------------------------------------------------
// A participant must prove it can spend the UTXOs it registers. Without this, anyone could register
// a stranger's coins into a round and stall it for ever (and mine the coordinator for which UTXOs
// are unspent). The proof is an ECDSA signature over a round-bound message, checked against the
// pubkey, which must in turn hash to the UTXO's witness program.
export function ownershipMessage(roundId, txid, vout) {
  return `seqcj-ownership-v1|${roundId}|${txid}:${vout}`;
}
const SPKI_SECP256K1 = Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex');
export function verifyOwnership(roundId, utxo, pubkeyHex, sigHex) {
  const pub = Buffer.from(String(pubkeyHex || ''), 'hex');
  if (pub.length !== 33 || (pub[0] !== 2 && pub[0] !== 3)) throw new Error('pubkey must be 33-byte compressed');
  // The scriptPubKey binds the pubkey to the coin. P2WPKH only: that is what the wallet's
  // wpkh/SLIP-77 descriptor produces, and accepting shapes we cannot check is how a proof becomes
  // decorative.
  const spk = Buffer.from(String(utxo.scriptPubKey || ''), 'hex');
  if (spk.length !== 22 || spk[0] !== 0x00 || spk[1] !== 0x14) throw new Error('input is not P2WPKH');
  if (!hash160(pub).equals(spk.subarray(2))) throw new Error('pubkey does not match the input script');
  const key = createPublicKey({ key: Buffer.concat([SPKI_SECP256K1, pub]), format: 'der', type: 'spki' });
  const msg = Buffer.from(ownershipMessage(roundId, utxo.txid, utxo.vout));
  if (!cryptoVerify('sha256', msg, key, Buffer.from(String(sigHex || ''), 'hex'))) {
    throw new Error('ownership signature does not verify');
  }
  return true;
}

// ---- round construction -----------------------------------------------------
const nowMs = () => Date.now();
const rid = () => randomBytes(8).toString('hex');

// A lane is one (asset, denomination) pair. Each lane gets its own blind-signing key, which is what
// stops a credential minted for a 1-unit lane from being spent against a 100-unit one — the binding
// is the key, not a claim in a message anyone could rewrite.
function makeRound(cfg) {
  const r = {
    id: rid(),
    created: nowMs(),
    phase: 'input',
    // No countdown yet. A round is not on the clock until it could actually happen — see advance().
    deadline: Infinity,
    lanes: cfg.lanes.map((l) => ({
      asset: l.asset,
      label: l.label || l.asset.slice(0, 8),
      denom: BigInt(l.denom_atoms),
      coord_fee: BigInt(l.coord_fee_atoms || 0),
      btc_backed: !!l.btc_backed,
      key: newRoundKey(cfg.round.key_bits || 2048),
    })),
    registrations: new Map(),      // registration_id -> { inputs, k, lane, change, signed, tx }
    spentNonces: new Set(),
    outputs: [],                   // { address, atoms, asset } — anonymous, registered in phase 2
    credentialsIssued: 0,
    tx: null,                      // { hex, txid } once published
    txid: null,
    error: null,
  };
  return r;
}

export function roundPublic(r, cfg) {
  return {
    round_id: r.id,
    phase: r.phase,
    // null while the round is still waiting for the participant that makes it viable: a countdown
    // shown before there is one is a promise the coordinator has not made.
    deadline_ms: Number.isFinite(r.deadline) ? Math.max(0, r.deadline - nowMs()) : null,
    waiting_for_participants: r.phase === 'input' && r.registrations.size < cfg.round.min_participants,
    participants: r.registrations.size,
    min_participants: cfg.round.min_participants,
    max_participants: cfg.round.max_participants,
    max_credentials: cfg.round.max_credentials,
    inputs_registered: [...r.registrations.values()].reduce((n, g) => n + g.inputs.length, 0),
    // Two different numbers, because conflating them reads as progress that has not happened: the
    // total includes the change outputs registered in phase one, while only the anonymous mix
    // outputs of phase two are what the round is waiting for.
    outputs_registered: r.outputs.length,
    mix_outputs_registered: r.spentNonces.size,
    credentials_issued: r.credentialsIssued,
    lanes: r.lanes.map((l, i) => ({
      index: i,
      asset: l.asset,
      label: l.label,
      denom_atoms: l.denom.toString(),
      coord_fee_atoms: l.coord_fee.toString(),
      btc_backed: l.btc_backed,
      blind_key: l.key.pub,
    })),
    txid: r.txid,
    error: r.error,
  };
}

// ---- registration arithmetic ------------------------------------------------
// The one equation a registration must satisfy. Kept pure and exported so it is tested directly:
// every "you may mix this much" decision in the system reduces to it.
//
//   sum(inputs) = k * (denom + coordination fee) + change
//
// The network fee is absent on purpose — the coordinator pays it out of its own fee-asset input, so
// a participant mixing USDX needs no other asset to take part.
export function registrationBalance({ inputSum, k, denom, coordFee }) {
  const owed = BigInt(k) * (BigInt(denom) + BigInt(coordFee));
  const change = BigInt(inputSum) - owed;
  if (change < 0n) {
    throw new Error(`inputs total ${inputSum} but ${k} denomination(s) cost ${owed}`);
  }
  return change;
}

// ---- input registration -----------------------------------------------------
async function registerInput(r, cfg, body) {
  if (r.phase !== 'input') throw new Error('round is no longer accepting inputs');
  if (r.registrations.size >= cfg.round.max_participants) throw new Error('round is full');
  const laneIndex = Number(body.lane ?? 0);
  const lane = r.lanes[laneIndex];
  if (!lane) throw new Error('unknown lane');

  const inputs = Array.isArray(body.inputs) ? body.inputs : [];
  if (!inputs.length) throw new Error('at least one input is required');
  if (inputs.length > (cfg.round.max_inputs_per_participant || 8)) throw new Error('too many inputs');
  const k = Array.isArray(body.credentials) ? body.credentials.length : 0;
  if (k < 1 || k > cfg.round.max_credentials) throw new Error('between 1 and ' + cfg.round.max_credentials + ' credentials, please');

  // Resolve and check every coin against the chain, not against what the client said about it.
  let sum = 0n;
  const resolved = [];
  const seen = new Set();
  for (const i of inputs) {
    const txid = String(i.txid || ''), vout = Number(i.vout);
    if (!/^[0-9a-f]{64}$/i.test(txid) || !Number.isInteger(vout) || vout < 0) throw new Error('malformed outpoint');
    const key = txid + ':' + vout;
    if (seen.has(key)) throw new Error('duplicate input ' + key);
    seen.add(key);
    if (isBanned(key)) throw new Error('input ' + key + ' is temporarily excluded (it stalled a previous round)');
    if (outpointInUse(key)) throw new Error('input ' + key + ' is already registered in a round');
    const utxo = await seqrpc('gettxout', [txid, vout, true]);
    if (!utxo) throw new Error('input ' + key + ' is unknown or already spent');
    // CONFIDENTIAL INPUTS ARE REFUSED. Blinding the round requires the blinding factors of every
    // input, so accepting a confidential coin would mean asking its owner to hand its blinders to
    // the coordinator — which would let the coordinator (and anyone it told) unblind that coin's
    // whole history. Sequentia is transparent by default, so this costs a user nothing: they spend
    // an ordinary tb1 coin in and receive a confidential one out. That direction is the point.
    if (utxo.value === undefined || utxo.value === null || !utxo.asset) {
      throw new Error('input ' + key + ' is confidential; register transparent coins (its blinders would have to be revealed)');
    }
    if (utxo.asset !== lane.asset) throw new Error('input ' + key + ' is not the asset of this lane');
    if ((utxo.confirmations ?? 0) < (cfg.round.min_conf ?? 1)) throw new Error('input ' + key + ' needs ' + (cfg.round.min_conf ?? 1) + ' confirmation(s)');
    verifyOwnership(r.id, { txid, vout, scriptPubKey: utxo.scriptPubKey?.hex }, i.pubkey, i.sig);
    sum += parse8(utxo.value);
    resolved.push({ txid, vout, atoms: parse8(utxo.value), asset: utxo.asset, script: utxo.scriptPubKey?.hex });
  }

  const change = registrationBalance({ inputSum: sum, k, denom: lane.denom, coordFee: lane.coord_fee });
  let changeOut = null;
  if (change > 0n) {
    if (!body.change_address) throw new Error('this registration leaves change of ' + change + ' atoms and needs a change address');
    await requireConfidentialAddress(body.change_address);
    // Change is blinded like everything else. The coordinator knows it is yours; the chain does not,
    // which is the half that matters — on Bitcoin this output is what unwinds the mix.
    changeOut = { address: String(body.change_address), atoms: change, asset: lane.asset };
  } else if (body.change_address) {
    throw new Error('registration is exact; no change address should be given');
  }

  const blind_sigs = body.credentials.map((c) => signBlinded(lane.key, c));
  const regid = rid();
  r.registrations.set(regid, {
    lane: laneIndex, inputs: resolved, k, change: changeOut,
    signed: null, registered: nowMs(),
  });
  r.credentialsIssued += k;
  if (changeOut) r.outputs.push({ ...changeOut, kind: 'change' });
  log(`round ${r.id}: +${resolved.length} input(s) in lane ${lane.label}, ${k} credential(s), change ${change}`);
  // The clock starts when the round becomes viable, not when it opened. On a quiet coordinator a
  // fixed countdown means every round expires empty and whoever arrives alone always misses; worse,
  // it means arriving ten seconds after a round opened costs a full cycle of waiting. Now the first
  // participant simply waits, and the timer starts the moment a second one makes a mix possible.
  if (r.registrations.size === cfg.round.min_participants) {
    r.deadline = nowMs() + cfg.round.input_ms;
    log(`round ${r.id}: viable with ${r.registrations.size} participants — closing registration in ${Math.round(cfg.round.input_ms / 1000)}s`);
  }
  if (r.registrations.size >= cfg.round.max_participants) r.deadline = Math.min(r.deadline, nowMs() + 2000);
  return { registration_id: regid, blind_sigs, change_atoms: change.toString() };
}

// ---- output registration ----------------------------------------------------
// The unlinkable half. Nothing in this request identifies the caller, and the coordinator must keep
// it that way: no registration id, no input reference, and (in deployment) a fresh connection.
async function registerOutput(r, cfg, body) {
  if (r.phase !== 'output') throw new Error('round is not accepting outputs');
  const cred = body.credential || {};
  if (!/^[0-9a-f]{64}$/i.test(String(cred.nonce || ''))) throw new Error('malformed credential');
  if (r.spentNonces.has(cred.nonce.toLowerCase())) throw new Error('credential already spent');

  // Which lane a credential belongs to is decided by WHICH KEY VERIFIES IT, never by what the caller
  // says. That is the whole point of a per-lane key.
  let laneIndex = -1;
  for (let i = 0; i < r.lanes.length; i++) {
    if (await verifyCredential(r.lanes[i].key.pub, cred)) { laneIndex = i; break; }
  }
  if (laneIndex < 0) throw new Error('credential is not one this round issued');
  const lane = r.lanes[laneIndex];

  const address = String(body.address || '');
  await requireConfidentialAddress(address);
  if (r.outputs.some((o) => o.address === address)) throw new Error('that address is already an output of this round');

  r.spentNonces.add(cred.nonce.toLowerCase());
  r.outputs.push({ address, atoms: lane.denom, asset: lane.asset, kind: 'mix' });
  log(`round ${r.id}: +1 mix output in lane ${lane.label} (${r.spentNonces.size}/${r.credentialsIssued})`);
  if (r.spentNonces.size >= r.credentialsIssued) r.deadline = Math.min(r.deadline, nowMs() + 1500);
  return { ok: true, registered: r.spentNonces.size, expected: r.credentialsIssued };
}

// A mix output MUST be confidential — an explicit one would publish the denomination and hand the
// chain the equal-value structure that CT is here to remove. Checked against the node so a typo or a
// mainnet address fails now rather than at broadcast.
async function requireConfidentialAddress(address) {
  const v = await seqrpc('validateaddress', [String(address)]);
  if (!v || !v.isvalid) throw new Error('not a valid address for this chain: ' + address);
  if (!v.confidential_key && !v.confidential) {
    throw new Error('coinjoin outputs must be confidential (blinded) addresses; ' + address + ' is transparent');
  }
  return true;
}

// ---- transaction assembly ---------------------------------------------------
// Shuffle with a cryptographic RNG. Output order is the last piece of metadata a coordinator could
// leak by accident (registration order is arrival order, which is timing, which is identity).
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomBytes(4).readUInt32BE(0) % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// What a round of this shape will weigh. Confidential outputs are the whole cost: a rangeproof plus
// a surjection proof runs about 1.2 kvB per output, measured on this chain, against ~68 vB for a
// P2WPKH input. The figures below are deliberately generous — underestimating means the assembled
// round is rejected for a low fee and everybody re-registers, while overestimating costs the
// coordinator a few atoms of its own fee asset.
//
// The same arithmetic is why round size is capped: at ~1.3 kvB per blinded output a 20-participant
// round with change is already ~50 kvB, and the standard-transaction ceiling is 100 kvB.
export function estimateVsize(nIn, nBlindedOut) {
  return 250 + 68 * nIn + 1300 * nBlindedOut;
}
export function networkFeeAtoms(cfg, nIn, nBlindedOut) {
  const rate = BigInt(cfg.fee_rate_atoms_per_vb ?? 2);
  const est = BigInt(estimateVsize(nIn, nBlindedOut)) * rate;
  const floor = BigInt(cfg.network_fee_atoms ?? 0);
  return est > floor ? est : floor;
}

// Pick the coordinator's own fee input: one confirmed wallet UTXO of the fee asset large enough to
// cover the network fee. It carries the round's only explicit output (the fee), and its change is
// blinded like everyone else's.
async function selectFeeInput(cfg, need) {
  const utxos = await seqrpc('listunspent', [1, 9999999], cfg.seq.wallet);
  const candidates = (utxos || [])
    .filter((u) => u.asset === cfg.fee_asset && u.spendable !== false)
    .map((u) => ({ ...u, atoms: parse8(u.amount) }))
    .filter((u) => u.atoms > BigInt(need))
    .sort((a, b) => (a.atoms < b.atoms ? -1 : 1));
  if (!candidates.length) {
    throw new Error(`coordinator has no fee-asset UTXO above ${need} atoms to fund the network fee`);
  }
  return candidates[0];
}

async function buildRoundTx(r, cfg) {
  // Every credential must have been redeemed. An unredeemed one has no output to pay, and the
  // coordinator cannot know whose it was (that is the design working), so the only safe move is to
  // abort the round: nothing was broadcast, nobody lost anything, everyone re-registers.
  if (r.spentNonces.size !== r.credentialsIssued) {
    throw new Error(`only ${r.spentNonces.size} of ${r.credentialsIssued} credentials were redeemed`);
  }
  const regs = [...r.registrations.values()];
  if (regs.length < cfg.round.min_participants) {
    throw new Error(`only ${regs.length} participant(s); this round needs ${cfg.round.min_participants}`);
  }

  // Size the fee before anything is built: the number of inputs and blinded outputs is already
  // known, and the coordinator's own input has to be big enough to carry it.
  const nIn = regs.reduce((n, g) => n + g.inputs.length, 0) + 1;
  const nOut = r.outputs.length
    + r.lanes.filter((l) => l.coord_fee > 0n).length     // coordination-fee outputs
    + 1;                                                 // the coordinator's own change
  const feeAtoms = networkFeeAtoms(cfg, nIn, nOut);
  const feeUtxo = await selectFeeInput(cfg, feeAtoms);
  const ins = shuffle([
    ...regs.flatMap((g) => g.inputs.map((i) => ({ txid: i.txid, vout: i.vout, atoms: i.atoms, asset: i.asset, blinder: '0'.repeat(64), assetblinder: '0'.repeat(64) }))),
    { txid: feeUtxo.txid, vout: feeUtxo.vout, atoms: feeUtxo.atoms, asset: feeUtxo.asset,
      // The coordinator's own coin may well be confidential (its change from an earlier round is),
      // and it knows its own blinders, so it can spend one without asking anybody to reveal anything.
      blinder: feeUtxo.amountblinder || '0'.repeat(64), assetblinder: feeUtxo.assetblinder || '0'.repeat(64) },
  ]);

  const outs = [...r.outputs.map((o) => ({ address: o.address, atoms: o.atoms, asset: o.asset }))];

  // Coordination fees, one blinded output per lane that earned any. Collected in the lane's own
  // asset: a participant mixing GOLD pays in GOLD and never has to hold the fee asset.
  for (const lane of r.lanes) {
    if (lane.coord_fee === 0n) continue;
    const earned = regs.filter((g) => r.lanes[g.lane] === lane).reduce((s, g) => s + BigInt(g.k) * lane.coord_fee, 0n);
    if (earned > 0n) outs.push({ address: await seqrpc('getnewaddress', ['', 'blech32'], cfg.seq.wallet), atoms: earned, asset: lane.asset });
  }

  // The coordinator's change in the fee asset, blinded.
  const coordChange = feeUtxo.atoms - feeAtoms;
  if (coordChange > 0n) {
    outs.push({ address: await seqrpc('getnewaddress', ['', 'blech32'], cfg.seq.wallet), atoms: coordChange, asset: cfg.fee_asset });
  }
  shuffle(outs);

  const rpcOuts = outs.map((o) => ({ [o.address]: fmt8(o.atoms), asset: o.asset }));
  rpcOuts.push({ fee: fmt8(feeAtoms), fee_asset: cfg.fee_asset });   // the round's only explicit output

  const raw = await seqrpc('createrawtransaction', [ins.map((i) => ({ txid: i.txid, vout: i.vout })), rpcOuts]);
  const blinded = await seqrpc('rawblindrawtransaction', [
    raw,
    ins.map((i) => i.blinder),
    ins.map((i) => fmt8(i.atoms)),
    ins.map((i) => i.asset),
    ins.map((i) => i.assetblinder),
    null,
    false,          // never accept a silently-unblinded output: that would publish someone's amount
  ]);
  const decoded = await seqrpc('decoderawtransaction', [blinded]);
  const blindedCount = decoded.vout.filter((o) => o.valuecommitment).length;
  if (blindedCount !== decoded.vout.length - 1) {
    throw new Error(`assembly produced ${decoded.vout.length - 1 - blindedCount} unblinded non-fee output(s); refusing to publish`);
  }
  r.tx = { hex: blinded, txid: decoded.txid, vsize: decoded.vsize, inputs: ins, outputs: outs };
  log(`round ${r.id}: built ${decoded.txid} — ${decoded.vin.length} in, ${decoded.vout.length} out, ${decoded.vsize} vB`);
  return r.tx;
}

// ---- signature collection + broadcast ---------------------------------------
// A submission is accepted only if it is the SAME transaction: the txid commits to every input,
// output, commitment and script, so equality means the participant signed what we published and
// nothing else. combinerawtransaction then merges input signature data only, starting from OUR copy
// of the transaction — so a participant cannot slip in altered rangeproofs either.
async function submitSignature(r, cfg, body) {
  if (r.phase !== 'signing' || !r.tx) throw new Error('round is not collecting signatures');
  const g = r.registrations.get(String(body.registration_id || ''));
  if (!g) throw new Error('unknown registration');
  const hex = String(body.tx_hex || '');
  const decoded = await seqrpc('decoderawtransaction', [hex]);
  if (decoded.txid !== r.tx.txid) throw new Error('that is a different transaction; refusing it');
  const mine = new Set(g.inputs.map((i) => i.txid + ':' + i.vout));
  let witnessed = 0;
  decoded.vin.forEach((vin) => {
    if (mine.has(vin.txid + ':' + vin.vout) && Array.isArray(vin.txinwitness) && vin.txinwitness.length) witnessed++;
  });
  if (witnessed !== g.inputs.length) throw new Error(`expected ${g.inputs.length} signed input(s), found ${witnessed}`);
  g.signed = hex;
  const done = [...r.registrations.values()].filter((x) => x.signed).length;
  log(`round ${r.id}: signature ${done}/${r.registrations.size}`);
  if (done === r.registrations.size) setImmediate(() => finishRound(r, cfg).catch((e) => failRound(r, cfg, e.message)));
  return { ok: true, signed: done, of: r.registrations.size };
}

async function finishRound(r, cfg) {
  if (r.phase !== 'signing') return;
  r.phase = 'broadcasting';
  const parts = [...r.registrations.values()].map((g) => g.signed).filter(Boolean);
  // Ours first: combinerawtransaction clones txs[0] and merges only input signatures into it, so the
  // published output commitments and proofs are the ones that survive.
  const withCoord = await seqrpc('signrawtransactionwithwallet', [r.tx.hex], cfg.seq.wallet);
  const combined = await seqrpc('combinerawtransaction', [[withCoord.hex, ...parts]]);
  const [test] = await seqrpc('testmempoolaccept', [[combined]]);
  if (!test.allowed) throw new Error('assembled round was rejected: ' + test['reject-reason']);
  const txid = await seqrpc('sendrawtransaction', [combined]);
  r.txid = txid; r.phase = 'done'; r.finished = nowMs();
  STATE.history.unshift({ txid, at: Date.now(), participants: r.registrations.size, outputs: r.outputs.length, vsize: r.tx.vsize });
  STATE.history = STATE.history.slice(0, 100);
  saveState();
  log(`round ${r.id}: BROADCAST ${txid} (${r.registrations.size} participants, ${r.outputs.length} blinded outputs)`);
}

// A round that dies in the signing phase has identifiable culprits — whoever registered inputs and
// then did not sign. Those outpoints are excluded for a while so the same coin cannot stall round
// after round. Earlier phases are NOT attributable (that is the blinding working as intended), so
// nothing is banned for them.
function failRound(r, cfg, reason) {
  r.phase = 'failed'; r.error = reason; r.finished = nowMs();
  if (r.tx) {
    const until = Date.now() + (cfg.round.ban_ms || 3600000);
    for (const g of r.registrations.values()) {
      if (g.signed) continue;
      for (const i of g.inputs) STATE.bans[i.txid + ':' + i.vout] = until;
    }
    saveState();
  }
  err(`round ${r.id} failed: ${reason}`);
}
function isBanned(key) {
  const until = STATE.bans[key];
  if (!until) return false;
  if (until < Date.now()) { delete STATE.bans[key]; return false; }
  return true;
}
function outpointInUse(key) {
  for (const r of ROUNDS.values()) {
    if (r.phase === 'done' || r.phase === 'failed') continue;
    for (const g of r.registrations.values()) {
      if (g.inputs.some((i) => i.txid + ':' + i.vout === key)) return true;
    }
  }
  return false;
}

// ---- phase clock ------------------------------------------------------------
export async function advance(r, cfg) {
  if (r.phase === 'done' || r.phase === 'failed') return;
  const expired = nowMs() >= r.deadline;
  if (r.phase === 'input') {
    const enough = r.registrations.size >= cfg.round.min_participants;
    // A round waiting for company waits indefinitely — but not for ever with somebody's coins held
    // out of every other round. After `stale_ms` an unviable round is released so those coins are
    // free again, and a fresh round opens behind it.
    if (!enough) {
      const waited = nowMs() - r.created;
      if (r.registrations.size > 0 && waited > (cfg.round.stale_ms ?? 1800000)) {
        return failRound(r, cfg, `no second participant arrived in ${Math.round(waited / 60000)} minutes`);
      }
      return;
    }
    if (expired || r.registrations.size >= cfg.round.max_participants) {
      r.phase = 'output';
      r.deadline = nowMs() + cfg.round.output_ms;
      log(`round ${r.id}: input -> output (${r.registrations.size} participants, ${r.credentialsIssued} credentials)`);
    }
    return;
  }
  if (r.phase === 'output') {
    if (!expired && r.spentNonces.size < r.credentialsIssued) return;
    try {
      await buildRoundTx(r, cfg);
      r.phase = 'signing';
      r.deadline = nowMs() + cfg.round.sign_ms;
    } catch (e) { failRound(r, cfg, e.message); }
    return;
  }
  if (r.phase === 'signing' && expired) {
    return failRound(r, cfg, 'not every participant signed in time');
  }
}

let ticking = false;
let timer = null;
async function tick() {
  if (ticking) return; ticking = true;
  try {
    for (const r of ROUNDS.values()) {
      try { await advance(r, CFG); } catch (e) { err('advance:', e.message); }
    }
    // Retire finished rounds after a grace period so clients can still read the outcome. `deadline`
    // can be Infinity on a round that never became viable, so the clock here is the retirement time
    // recorded when it finished.
    for (const [id, r] of ROUNDS) {
      if ((r.phase === 'done' || r.phase === 'failed') && nowMs() - (r.finished || 0) > 120000) ROUNDS.delete(id);
    }
    const open = [...ROUNDS.values()].filter((r) => r.phase === 'input');
    if (open.length < (CFG.round.concurrent_open || 1)) {
      const r = makeRound(CFG);
      ROUNDS.set(r.id, r);
      log(`round ${r.id}: open for registration (${r.lanes.map((l) => l.label).join(', ')})`);
    }
  } finally { ticking = false; }
}

// ---- HTTP -------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (d) => { b += d; if (b.length > 1e7) req.destroy(); });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve(null); } });
  });
}
function send(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(obj));
}
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (req.method === 'GET' && (path === '/status' || path === '/')) {
      return send(res, 200, {
        ok: true, service: 'seqcj', version: 1,
        fee_asset: CFG.fee_asset,
        // Which lane is really parent-chain Bitcoin, and where the peg lives. The wallet needs both
        // to offer "mix my BTC": it pegs in, mixes SBTC here, and pegs out itself. No coordinator
        // ever touches those funds.
        btc: CFG.sbtc ? { lane_asset: CFG.sbtc.asset, bridge_path: CFG.sbtc.bridge_path || '/sbtc' } : null,
        open_rounds: [...ROUNDS.values()].filter((r) => r.phase !== 'done' && r.phase !== 'failed').length,
        recent: STATE.history.slice(0, 10),
      });
    }
    if (req.method === 'GET' && path === '/rounds') {
      return send(res, 200, { ok: true, rounds: [...ROUNDS.values()].map((r) => roundPublic(r, CFG)) });
    }
    const m = /^\/round\/([0-9a-f]{16})$/.exec(path);
    if (req.method === 'GET' && m) {
      const r = ROUNDS.get(m[1]);
      if (!r) return send(res, 404, { ok: false, error: 'unknown round' });
      const out = roundPublic(r, CFG);
      if (r.phase === 'signing' || r.phase === 'broadcasting') out.tx_hex = r.tx.hex;
      return send(res, 200, { ok: true, round: out });
    }
    if (req.method === 'POST' && path === '/register-input') {
      const b = await readBody(req); if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const r = ROUNDS.get(String(b.round_id || ''));
      if (!r) return send(res, 404, { ok: false, error: 'unknown round' });
      return send(res, 200, { ok: true, ...(await registerInput(r, CFG, b)) });
    }
    if (req.method === 'POST' && path === '/register-output') {
      const b = await readBody(req); if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const r = ROUNDS.get(String(b.round_id || ''));
      if (!r) return send(res, 404, { ok: false, error: 'unknown round' });
      return send(res, 200, { ok: true, ...(await registerOutput(r, CFG, b)) });
    }
    if (req.method === 'POST' && path === '/sign') {
      const b = await readBody(req); if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const r = ROUNDS.get(String(b.round_id || ''));
      if (!r) return send(res, 404, { ok: false, error: 'unknown round' });
      return send(res, 200, { ok: true, ...(await submitSignature(r, CFG, b)) });
    }
    return send(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    // Registration errors are the user's business (wrong amount, spent coin, bad proof), so they are
    // returned verbatim; nothing here carries key material or another participant's data.
    send(res, 400, { ok: false, error: e.message });
  }
});

// ---- main -------------------------------------------------------------------
function loadState() {
  if (!existsSync(STATE_PATH)) return { bans: {}, history: [] };
  try { return JSON.parse(readFileSync(STATE_PATH, 'utf8')); } catch { return { bans: {}, history: [] }; }
}
function defaultSaveState() {
  const tmp = STATE_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(STATE, null, 2));
  renameSync(tmp, STATE_PATH);
}

function main() {
  CFG = JSON.parse(readFileSync(CFG_PATH, 'utf8'));
  CFG.round = { input_ms: 60000, output_ms: 30000, sign_ms: 60000, min_participants: 2, max_participants: 12,
                max_credentials: 4, max_inputs_per_participant: 8, min_conf: 1, ban_ms: 3600000,
                concurrent_open: 1, key_bits: 2048, ...(CFG.round || {}) };
  seqrpc = (m, p, w) => rpc(CFG.seq.rpc, m, p, w === undefined ? CFG.seq.wallet : w);
  saveState = defaultSaveState;
  STATE = loadState();
  const port = CFG.http?.port || 9971, host = CFG.http?.host || '127.0.0.1';
  server.listen(port, host, () => {
    log(`listening http://${host}:${port} | fee asset ${CFG.fee_asset.slice(0, 12)}… | lanes ${CFG.lanes.map((l) => l.label || l.asset.slice(0, 8)).join(', ')}`);
    tick();
    timer = setInterval(tick, 1000);
  });
}

// Shut down cleanly. Only the test needs this — in production the process IS the service — but a
// service that cannot be stopped without killing the runtime is a service that cannot be tested.
export function stop() {
  if (timer) { clearInterval(timer); timer = null; }
  try { server.close(); } catch {}
}

// ---- test hook --------------------------------------------------------------
// Lets a test drive rounds against a real regtest node (or a mock) with no config file, no disk
// writes and no HTTP server.
export function __configureForTest(opts = {}) {
  CFG = opts.cfg || CFG;
  if (CFG) CFG.round = { input_ms: 60000, output_ms: 30000, sign_ms: 60000, min_participants: 2, max_participants: 12,
                         max_credentials: 4, max_inputs_per_participant: 8, min_conf: 1, ban_ms: 3600000,
                         concurrent_open: 1, key_bits: 2048, ...(CFG.round || {}) };
  if (opts.seqrpc) seqrpc = opts.seqrpc;
  ROUNDS = opts.rounds || new Map();
  STATE = opts.state || { bans: {}, history: [] };
  saveState = opts.saveState || (() => {});
  return { rounds: ROUNDS, state: STATE, cfg: CFG };
}
export { makeRound, registerInput, registerOutput, buildRoundTx, submitSignature, finishRound, failRound, ROUNDS, main as start, server };

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main();
