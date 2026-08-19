// The coordinator's refusals, tested without a chain. Every one of these is a rule that, if it
// silently stopped working, would still let rounds complete — which is exactly why they are tested
// rather than trusted to the end-to-end run.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as ecSign } from 'node:crypto';
import {
  __configureForTest, makeRound, registerInput, registerOutput, buildRoundTx,
  registrationBalance, ownershipMessage, verifyOwnership, estimateVsize, networkFeeAtoms,
  fmt8, parse8, advance,
} from '../coordinator.mjs';
import { blind, unblind } from '../blindsig.mjs';

const ASSET = 'aa'.repeat(32);
const FEE_ASSET = 'bb'.repeat(32);
const hash160 = (b) => createHash('ripemd160').update(createHash('sha256').update(b).digest()).digest();

// A throwaway wallet: a key, its P2WPKH script, and the ability to prove it owns a coin.
function newWallet() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url'), y = Buffer.from(jwk.y, 'base64url');
  const pub = Buffer.concat([Buffer.of(y[31] % 2 ? 3 : 2), x]);
  return {
    pubkey: pub.toString('hex'),
    script: '0014' + hash160(pub).toString('hex'),
    prove: (msg) => ecSign('sha256', Buffer.from(msg), privateKey).toString('hex'),
  };
}

// A chain that only knows about the coins we put in it.
function mockChain(coins) {
  return async (method, params) => {
    if (method === 'gettxout') {
      const [txid, vout] = params;
      return coins[`${txid}:${vout}`] ?? null;
    }
    if (method === 'validateaddress') {
      const a = String(params[0]);
      if (a.startsWith('conf')) return { isvalid: true, confidential_key: '02' + '11'.repeat(32), scriptPubKey: '0014' + '22'.repeat(20) };
      if (a.startsWith('plain')) return { isvalid: true, confidential_key: '', scriptPubKey: '0014' + '33'.repeat(20) };
      return { isvalid: false };
    }
    if (method === 'listunspent') return [];
    throw new Error('mock chain has no ' + method);
  };
}

function setup(coins, laneOverrides = {}) {
  const cfg = {
    seq: { wallet: 'coord' }, fee_asset: FEE_ASSET, fee_rate_atoms_per_vb: 2,
    lanes: [{ asset: ASSET, denom_atoms: '1000000000', coord_fee_atoms: '1000000', label: 'MIX 10', ...laneOverrides }],
    round: { min_participants: 2, max_participants: 5, max_credentials: 4, key_bits: 1024 },
  };
  const ctx = __configureForTest({ cfg, seqrpc: mockChain(coins) });
  const r = makeRound(ctx.cfg);
  ctx.rounds.set(r.id, r);
  return { r, cfg: ctx.cfg, state: ctx.state };
}

const coin = (script, value, extra = {}) => ({ value, asset: ASSET, confirmations: 3, scriptPubKey: { hex: script }, ...extra });

test('registration arithmetic is exact', () => {
  assert.equal(registrationBalance({ inputSum: 2500000000n, k: 2, denom: 1000000000n, coordFee: 1000000n }), 498000000n);
  assert.equal(registrationBalance({ inputSum: 2002000000n, k: 2, denom: 1000000000n, coordFee: 1000000n }), 0n);
  assert.throws(() => registrationBalance({ inputSum: 100n, k: 1, denom: 1000000000n, coordFee: 0n }), /denomination/);
  // atoms survive the RPC boundary as decimal strings, which is where a float would lose them
  assert.equal(fmt8(2500000001n), '25.00000001');
  assert.equal(parse8('25.00000001'), 2500000001n);
  assert.equal(parse8(fmt8(1n)), 1n);
});

test('an ownership proof binds a key, a coin and a round', () => {
  const w = newWallet();
  const utxo = { txid: 'ab'.repeat(32), vout: 1, scriptPubKey: w.script };
  const msg = ownershipMessage('round1', utxo.txid, utxo.vout);
  assert.equal(verifyOwnership('round1', utxo, w.pubkey, w.prove(msg)), true);
  // ...and refuses everything else
  assert.throws(() => verifyOwnership('round2', utxo, w.pubkey, w.prove(msg)), /does not verify/);
  assert.throws(() => verifyOwnership('round1', { ...utxo, vout: 2 }, w.pubkey, w.prove(msg)), /does not verify/);
  const other = newWallet();
  assert.throws(() => verifyOwnership('round1', utxo, other.pubkey, other.prove(msg)), /does not match the input script/);
  assert.throws(() => verifyOwnership('round1', { ...utxo, scriptPubKey: '5120' + '00'.repeat(32) }, w.pubkey, w.prove(msg)), /not P2WPKH/);
});

test('a confidential input is refused', async () => {
  const w = newWallet();
  const key = 'cd'.repeat(32) + ':0';
  // A confidential coin reports commitments, not a value: accepting it would mean asking its owner
  // to hand the coordinator the blinders for its whole history.
  const coins = { [key]: { asset: undefined, value: undefined, valuecommitment: '09'.repeat(33), confirmations: 3, scriptPubKey: { hex: w.script } } };
  const { r, cfg } = setup(coins);
  const kept = await blind(r.lanes[0].key.pub);
  await assert.rejects(() => registerInput(r, cfg, {
    inputs: [{ txid: 'cd'.repeat(32), vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, 'cd'.repeat(32), 0)) }],
    credentials: [kept.blinded],
  }), /confidential/);
});

test('a transparent output address is refused for a mix output', async () => {
  const w = newWallet();
  const txid = 'ef'.repeat(32);
  const { r, cfg } = setup({ [txid + ':0']: coin(w.script, '20.00000000') });
  const kept = [await blind(r.lanes[0].key.pub)];
  const reg = await registerInput(r, cfg, {
    inputs: [{ txid, vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, txid, 0)) }],
    credentials: kept.map((k) => k.blinded),
    change_address: 'conf-change',
  });
  const cred = await unblind(r.lanes[0].key.pub, reg.blind_sigs[0], kept[0]);
  r.phase = 'output';
  await assert.rejects(() => registerOutput(r, cfg, { credential: cred, address: 'plain-address' }), /must be confidential/);
  // the same credential against a proper blinded address is fine
  assert.equal((await registerOutput(r, cfg, { credential: cred, address: 'conf-mix-1' })).registered, 1);
  // ...but only once
  await assert.rejects(() => registerOutput(r, cfg, { credential: cred, address: 'conf-mix-2' }), /already spent/);
});

test('a credential this round did not issue is worthless', async () => {
  const w = newWallet();
  const txid = '11'.repeat(32);
  const { r, cfg } = setup({ [txid + ':0']: coin(w.script, '20.00000000') });
  const other = makeRound(cfg);                       // a different round, so a different key
  const kept = await blind(other.lanes[0].key.pub);
  const cred = await unblind(other.lanes[0].key.pub, (await import('../rsakey.mjs')).signBlinded(other.lanes[0].key, kept.blinded), kept);
  r.phase = 'output';
  await assert.rejects(() => registerOutput(r, cfg, { credential: cred, address: 'conf-mix' }), /not one this round issued/);
});

test('the same coin cannot be registered twice, and a stalled coin is excluded', async () => {
  const w = newWallet();
  const txid = '22'.repeat(32);
  const { r, cfg } = setup({ [txid + ':0']: coin(w.script, '10.01000000') });
  const body = async () => ({
    inputs: [{ txid, vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, txid, 0)) }],
    credentials: [(await blind(r.lanes[0].key.pub)).blinded],
  });
  await registerInput(r, cfg, await body());
  const again = await body();
  await assert.rejects(() => registerInput(r, cfg, again), /already registered in a round/);
});

test('a coin that stalled a previous round is excluded for a while', async () => {
  const w = newWallet();
  const txid = '55'.repeat(32);
  const coins = { [txid + ':0']: coin(w.script, '10.01000000') };
  const cfg = {
    seq: { wallet: 'coord' }, fee_asset: FEE_ASSET,
    lanes: [{ asset: ASSET, denom_atoms: '1000000000', coord_fee_atoms: '1000000', label: 'MIX 10' }],
    round: { min_participants: 2, max_participants: 5, max_credentials: 4, key_bits: 1024 },
  };
  const ctx = __configureForTest({
    cfg, seqrpc: mockChain(coins),
    state: { bans: { [txid + ':0']: Date.now() + 60000 }, history: [] },
  });
  const r = makeRound(ctx.cfg); ctx.rounds.set(r.id, r);
  const reg = {
    inputs: [{ txid, vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, txid, 0)) }],
    credentials: [(await blind(r.lanes[0].key.pub)).blinded],
  };
  await assert.rejects(() => registerInput(r, ctx.cfg, reg), /temporarily excluded/);
});

test('a round with an unredeemed credential is aborted, not published', async () => {
  const w = newWallet(), w2 = newWallet();
  const t1 = '33'.repeat(32), t2 = '44'.repeat(32);
  const { r, cfg } = setup({ [t1 + ':0']: coin(w.script, '20.02000000'), [t2 + ':0']: coin(w2.script, '20.02000000') });
  for (const [txid, wal] of [[t1, w], [t2, w2]]) {
    await registerInput(r, cfg, {
      inputs: [{ txid, vout: 0, pubkey: wal.pubkey, sig: wal.prove(ownershipMessage(r.id, txid, 0)) }],
      credentials: [(await blind(r.lanes[0].key.pub)).blinded, (await blind(r.lanes[0].key.pub)).blinded],
    });
  }
  assert.equal(r.credentialsIssued, 4);
  // Nobody redeemed anything: the coordinator cannot know whose output is missing (that is the
  // blinding working), so the only safe answer is to abort — no transaction, no loss.
  r.phase = 'output'; r.deadline = 0;
  await advance(r, cfg);
  assert.equal(r.phase, 'failed');
  assert.match(r.error, /0 of 4 credentials/);
});

test('a round waits for company instead of expiring alone', async () => {
  const w = newWallet(), w2 = newWallet();
  const t1 = '66'.repeat(32), t2 = '77'.repeat(32);
  const { r, cfg } = setup({ [t1 + ':0']: coin(w.script, '10.01000000'), [t2 + ':0']: coin(w2.script, '10.01000000') });
  cfg.round.input_ms = 50;

  // Nobody has registered: the round has no deadline at all, and cannot expire.
  assert.equal(r.deadline, Infinity);
  await advance(r, cfg);
  assert.equal(r.phase, 'input');

  // One participant. Still no clock — a countdown here would mean the first to arrive always loses.
  await registerInput(r, cfg, {
    inputs: [{ txid: t1, vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, t1, 0)) }],
    credentials: [(await blind(r.lanes[0].key.pub)).blinded],
  });
  assert.equal(r.deadline, Infinity);
  await advance(r, cfg);
  assert.equal(r.phase, 'input', 'a round with one participant must keep waiting');

  // The second makes it viable, and only now does registration start closing.
  await registerInput(r, cfg, {
    inputs: [{ txid: t2, vout: 0, pubkey: w2.pubkey, sig: w2.prove(ownershipMessage(r.id, t2, 0)) }],
    credentials: [(await blind(r.lanes[0].key.pub)).blinded],
  });
  assert.ok(Number.isFinite(r.deadline), 'the clock starts when a mix becomes possible');
  await new Promise((res) => setTimeout(res, 60));
  await advance(r, cfg);
  assert.equal(r.phase, 'output');
});

test('a lone registration is eventually released rather than held for ever', async () => {
  const w = newWallet();
  const txid = '88'.repeat(32);
  const { r, cfg } = setup({ [txid + ':0']: coin(w.script, '10.01000000') });
  cfg.round.stale_ms = 10;
  await registerInput(r, cfg, {
    inputs: [{ txid, vout: 0, pubkey: w.pubkey, sig: w.prove(ownershipMessage(r.id, txid, 0)) }],
    credentials: [(await blind(r.lanes[0].key.pub)).blinded],
  });
  r.created = Date.now() - 1000;              // waited long enough
  await advance(r, cfg);
  // Waiting for company is fine; waiting for ever with someone's coins locked out of every other
  // round is not.
  assert.equal(r.phase, 'failed');
  assert.match(r.error, /no second participant/);
});

test('fee sizing tracks the cost of confidentiality', () => {
  // A blinded output is ~1.3 kvB of proofs; that is the whole reason round size is capped.
  assert.ok(estimateVsize(5, 12) > 15000);
  assert.ok(estimateVsize(5, 12) < 25000);
  const cfg = { fee_rate_atoms_per_vb: 2, network_fee_atoms: 0 };
  assert.equal(networkFeeAtoms(cfg, 5, 12), BigInt(estimateVsize(5, 12) * 2));
  assert.equal(networkFeeAtoms({ ...cfg, network_fee_atoms: 10n ** 9n }, 1, 1), 10n ** 9n);   // floor wins
});
